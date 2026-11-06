package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// -------------------------------------------------------------------
// PHASE 3.4: Distributed State Mesh (Redis Cluster Lua Synchronization)
// -------------------------------------------------------------------

// DistributedStateMesh provides atomic swarm-wide state synchronization across multi-pod clusters
type DistributedStateMesh interface {
	CheckAndConsumeNonce(ctx context.Context, agentID, nonce string, now time.Time, ttl time.Duration) (bool, string)
	CheckAndRecordVelocity(ctx context.Context, agentID string, amount float64, window time.Duration, limit float64, now time.Time) (bool, float64, float64, error)
	IsFleetFrozen(ctx context.Context) (bool, string, error)
	SetFleetFreeze(ctx context.Context, frozen bool, reason string) error
	Reset(ctx context.Context) error
}

// MemoryClusterStateMesh implements DistributedStateMesh with exact Redis Cluster atomic Lua script semantics
// for zero-dependency operation, multi-pod test simulation, and microsecond performance.
type MemoryClusterStateMesh struct {
	mu           sync.Mutex
	nonces       map[string]time.Time
	velocitySets map[string][]VelocityEntry
	fleetFrozen  bool
	freezeReason string
	defaultWin   time.Duration
	defaultLimit float64
	lastEviction time.Time
}

var globalStateMesh DistributedStateMesh = NewMemoryClusterStateMesh(1*time.Hour, 25000.0)

func NewMemoryClusterStateMesh(defaultWindow time.Duration, defaultLimit float64) *MemoryClusterStateMesh {
	return &MemoryClusterStateMesh{
		nonces:       make(map[string]time.Time),
		velocitySets: make(map[string][]VelocityEntry),
		defaultWin:   defaultWindow,
		defaultLimit: defaultLimit,
		lastEviction: time.Now(),
	}
}

// CheckAndConsumeNonce simulates atomic Redis "SET sentinel:nonce:{agent}:{nonce} 1 EX ttl NX"
func (m *MemoryClusterStateMesh) CheckAndConsumeNonce(ctx context.Context, agentID, nonce string, now time.Time, ttl time.Duration) (bool, string) {
	if !validNonceRegex.MatchString(nonce) {
		return false, "Invalid nonce format or length (must be 16-128 alphanumeric characters)"
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Periodic batched eviction of expired nonces
	if now.Sub(m.lastEviction) > 15*time.Second {
		for key, exp := range m.nonces {
			if now.After(exp) {
				delete(m.nonces, key)
			}
		}
		m.lastEviction = now
	}

	compositeKey := fmt.Sprintf("%s:%s", agentID, nonce)
	if exp, exists := m.nonces[compositeKey]; exists {
		if now.Before(exp) {
			return false, "Cryptographic nonce has already been consumed (replay attack prevention)"
		}
	}

	// Atomically record with TTL
	m.nonces[compositeKey] = now.Add(ttl)
	return true, ""
}

// CheckAndRecordVelocity executes the atomic sliding-window Lua script equivalent over Redis Sorted Sets:
// 1. ZREMRANGEBYSCORE key -inf (now - window)
// 2. ZRANGEBYSCORE key (now - window) +inf
// 3. If sum + amount > limit -> return (0, sum + amount, limit)
// 4. Else ZADD key now amount -> return (1, sum + amount, limit)
func (m *MemoryClusterStateMesh) CheckAndRecordVelocity(ctx context.Context, agentID string, amount float64, window time.Duration, limit float64, now time.Time) (bool, float64, float64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if window <= 0 {
		window = m.defaultWin
	}
	if limit <= 0 {
		limit = m.defaultLimit
	}

	cutoff := now.Add(-window)
	entries := m.velocitySets[agentID]
	var activeEntries []VelocityEntry
	var currentSum float64

	for _, e := range entries {
		if e.Timestamp.After(cutoff) {
			activeEntries = append(activeEntries, e)
			currentSum += e.Amount
		}
	}

	if currentSum+amount > limit {
		m.velocitySets[agentID] = activeEntries
		return false, currentSum + amount, limit, nil
	}

	activeEntries = append(activeEntries, VelocityEntry{Timestamp: now, Amount: amount})
	m.velocitySets[agentID] = activeEntries
	return true, currentSum + amount, limit, nil
}

// IsFleetFrozen checks the swarm-wide emergency stop flag
func (m *MemoryClusterStateMesh) IsFleetFrozen(ctx context.Context) (bool, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fleetFrozen, m.freezeReason, nil
}

// SetFleetFreeze toggles the swarm-wide emergency freeze across all pods
func (m *MemoryClusterStateMesh) SetFleetFreeze(ctx context.Context, frozen bool, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fleetFrozen = frozen
	m.freezeReason = reason
	return nil
}

// Reset clears all shared state in the mesh
func (m *MemoryClusterStateMesh) Reset(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nonces = make(map[string]time.Time)
	m.velocitySets = make(map[string][]VelocityEntry)
	m.fleetFrozen = false
	m.freezeReason = ""
	m.lastEviction = time.Now()
	return nil
}
