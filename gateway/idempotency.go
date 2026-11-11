package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

var (
	ErrIdempotencyMismatch = errors.New("idempotency key payload mismatch")
)

type IdempotencyRecord struct {
	Key         string
	AgentID     string
	Action      string
	PayloadHash string
	StatusCode  int
	Headers     http.Header
	Body        []byte
	CreatedAt   time.Time
	InProgress  bool
	Done        chan struct{}
}

type IdempotencyManager struct {
	mu      sync.Mutex
	records map[string]*IdempotencyRecord
	ttl     time.Duration
}

var globalIdempotencyManager = NewIdempotencyManager(1 * time.Hour)

func NewIdempotencyManager(ttl time.Duration) *IdempotencyManager {
	return &IdempotencyManager{
		records: make(map[string]*IdempotencyRecord),
		ttl:     ttl,
	}
}

// ComputePayloadHash returns SHA-256 hex digest of serialized payload
func ComputePayloadHash(payload map[string]interface{}) string {
	b, _ := json.Marshal(payload)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Acquire attempts to acquire or wait for an idempotency key
func (m *IdempotencyManager) Acquire(key, agentID, action, payloadHash string) (*IdempotencyRecord, bool, error) {
	if key == "" {
		return nil, false, nil
	}

	m.mu.Lock()
	rec, exists := m.records[key]
	if exists {
		// Key exists: check payload and agent match
		if rec.PayloadHash != payloadHash || rec.AgentID != agentID || rec.Action != action {
			m.mu.Unlock()
			return nil, false, ErrIdempotencyMismatch
		}

		if rec.InProgress {
			// Another request is in-flight: wait for it outside lock
			doneCh := rec.Done
			m.mu.Unlock()

			// Block until concurrent execution finishes or times out
			select {
			case <-doneCh:
				m.mu.Lock()
				defer m.mu.Unlock()
				return rec, true, nil
			case <-time.After(5 * time.Second):
				return nil, false, errors.New("idempotency concurrency timeout")
			}
		}

		m.mu.Unlock()
		return rec, true, nil
	}

	// New key: create in-progress entry
	newRec := &IdempotencyRecord{
		Key:         key,
		AgentID:     agentID,
		Action:      action,
		PayloadHash: payloadHash,
		CreatedAt:   time.Now(),
		InProgress:  true,
		Done:        make(chan struct{}),
	}
	m.records[key] = newRec
	m.mu.Unlock()

	return newRec, false, nil
}

// Complete finalizes an in-progress idempotency execution
func (m *IdempotencyManager) Complete(key string, statusCode int, headers http.Header, body []byte) {
	if key == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if rec, exists := m.records[key]; exists && rec.InProgress {
		rec.StatusCode = statusCode
		rec.Headers = headers.Clone()
		rec.Body = make([]byte, len(body))
		copy(rec.Body, body)
		rec.InProgress = false
		close(rec.Done)
	}
}

// Abort releases a key if an unhandled internal failure occurs
func (m *IdempotencyManager) Abort(key string) {
	if key == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if rec, exists := m.records[key]; exists && rec.InProgress {
		delete(m.records, key)
		close(rec.Done)
	}
}
