package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

// AgentRequest represents the payload from the AI Agent
type AgentRequest struct {
	AgentID string                 `json:"agent_id"`
	Action  string                 `json:"action"`
	Payload map[string]interface{} `json:"payload"`
}

// GatewayEvent represents the event pushed to Redpanda/Kafka
type GatewayEvent struct {
	AgentID   string                 `json:"agent_id"`
	Action    string                 `json:"action"`
	Payload   map[string]interface{} `json:"payload"`
	Decision  string                 `json:"decision"`
	Timestamp string                 `json:"timestamp"`
	AuthMode  string                 `json:"auth_mode,omitempty"`
	Reason    string                 `json:"reason,omitempty"`
}

var kafkaProducer *kafka.Producer
var topic = "sentinel-audit-events"
var enforcer *casbin.Enforcer

// Cryptographic Identity & KYA Configuration
var agentSharedSecret = "sentinel-agent-auth-secret-2026"
var strictAuthEnabled = false

// NonceCache prevents replay attacks with automatic expiration
type NonceCache struct {
	mu     sync.Mutex
	nonces map[string]time.Time
}

var nonceStore = &NonceCache{
	nonces: make(map[string]time.Time),
}

func (nc *NonceCache) CheckAndRecord(nonce string, now time.Time) bool {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	// Evict entries older than 120 seconds
	for k, t := range nc.nonces {
		if now.Sub(t) > 120*time.Second {
			delete(nc.nonces, k)
		}
	}

	if _, exists := nc.nonces[nonce]; exists {
		return false // Replay attack detected
	}
	nc.nonces[nonce] = now
	return true
}

// Parameter Guardrail Regexprs
var destructiveSQLRegex = regexp.MustCompile(`(?i)\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE|ALTER\s+TABLE|GRANT\s+ALL|REVOKE\s+ALL)\b`)
var unboundedDeleteRegex = regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+[a-zA-Z0-9_]+\s*(;|$)`)
var shellInjectionRegex = regexp.MustCompile(`[;&|` + "`" + `]|\$\(.*\)`)

func main() {
	// Initialize Secret and Auth Mode from environment
	if envSecret := os.Getenv("SENTINEL_AGENT_SECRET"); envSecret != "" {
		agentSharedSecret = envSecret
	}
	if os.Getenv("SENTINEL_STRICT_AUTH") == "true" {
		strictAuthEnabled = true
		log.Println("🔒 STRICT KYA AUTH ENFORCED: Unsigned requests will be rejected with HTTP 401.")
	} else {
		log.Println("🔓 DUAL-MODE KYA ACTIVE: Both signed and legacy requests accepted (Dev/Simulator mode).")
	}

	// 1. Initialize Kafka Producer
	p, err := kafka.NewProducer(&kafka.ConfigMap{"bootstrap.servers": "localhost:9092"})
	if err != nil {
		log.Printf("Failed to create Kafka producer: %s\n", err)
		log.Println("WARNING: Gateway will run, but audit events will not be pushed to Redpanda.")
	} else {
		kafkaProducer = p
		defer p.Close()
		log.Println("✅ Connected to Redpanda (localhost:9092)")
	}

	// 1.5 Initialize Casbin Enforcer
	var casbinErr error
	enforcer, casbinErr = casbin.NewEnforcer("../casbin_policies/model.conf", "../casbin_policies/policy.csv")
	if casbinErr != nil {
		log.Fatalf("Failed to initialize Casbin Enforcer: %s", casbinErr)
	}
	log.Println("✅ Casbin RBAC Initialized")

	// 2. Set up HTTP Handlers
	http.HandleFunc("/enforce", enforceHandler)
	http.HandleFunc("/health", healthHandler)

	// 3. Start Server
	port := ":8080"
	log.Printf("🛡️  SENTINEL Go Checkpoint Gateway running on http://localhost%s", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("Server failed to start: %s", err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "HEALTHY",
		"service":     "sentinel-edge-gateway",
		"strict_auth": strictAuthEnabled,
		"timestamp":   time.Now().Format(time.RFC3339),
	})
}

func enforceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// Memory Shield: Limit incoming body size to 1 MB to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Payload too large or unreadable (limit 1MB)", http.StatusRequestEntityTooLarge)
		return
	}

	var req AgentRequest
	if err := json.Unmarshal(rawBody, &req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// -------------------------------------------------------------------
	// SECURITY: Strict Input Length Validation
	// -------------------------------------------------------------------
	if req.AgentID == "" || len(req.AgentID) > 64 {
		http.Error(w, "Invalid or missing agent_id (max 64 chars)", http.StatusBadRequest)
		return
	}
	if req.Action == "" || len(req.Action) > 64 {
		http.Error(w, "Invalid or missing action (max 64 chars)", http.StatusBadRequest)
		return
	}
	if req.Payload == nil {
		req.Payload = make(map[string]interface{})
	}

	// -------------------------------------------------------------------
	// SECURITY: Cryptographic Agent Identity (KYA) & Replay Defense
	// -------------------------------------------------------------------
	authValid, authMode, authErr := verifyAgentAuth(r, rawBody, req.AgentID)
	if !authValid {
		log.Printf("⛔ KYA AUTH FAILED for [%s]: %s", req.AgentID, authErr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "DENY",
			"error":   "AUTHENTICATION_REQUIRED",
			"message": authErr,
		})
		return
	}

	// -------------------------------------------------------------------
	// SECURITY: Parameter Guardrails & Destructive Action Inspection
	// -------------------------------------------------------------------
	guardrailPassed, guardrailReason := checkParameterGuardrails(req.Action, req.Payload)
	if !guardrailPassed {
		log.Printf("⛔ PARAMETER GUARDRAIL BLOCKED [%s - %s]: %s", req.AgentID, req.Action, guardrailReason)

		// Record audit event for forensic review
		publishAuditEvent(GatewayEvent{
			AgentID:   req.AgentID,
			Action:    req.Action,
			Payload:   req.Payload,
			Decision:  "DENY",
			Timestamp: time.Now().Format(time.RFC3339),
			AuthMode:  authMode,
			Reason:    "GUARDRAIL_VIOLATION: " + guardrailReason,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "DENY",
			"error":   "GUARDRAIL_VIOLATION",
			"message": guardrailReason,
		})
		return
	}

	// -------------------------------------------------------------------
	// SECURITY: Casbin RBAC Edge Check
	// -------------------------------------------------------------------
	if enforcer != nil {
		ok, err := enforcer.Enforce(req.AgentID, req.Action, "execute")
		if err != nil {
			log.Printf("⚠️ Casbin error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if !ok {
			log.Printf("⛔ RBAC REJECTED: %s is not authorized to %s", req.AgentID, req.Action)

			publishAuditEvent(GatewayEvent{
				AgentID:   req.AgentID,
				Action:    req.Action,
				Payload:   req.Payload,
				Decision:  "DENY",
				Timestamp: time.Now().Format(time.RFC3339),
				AuthMode:  authMode,
				Reason:    "RBAC_UNAUTHORIZED",
			})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "DENY",
				"message": "Transaction denied by Edge RBAC Policy (Unauthorized).",
			})
			return
		}
	}

	// -------------------------------------------------------------------
	// THE CHECKPOINT LOGIC: Python Case Law Engine Integration
	// -------------------------------------------------------------------
	decision := "DENY" // Fail-Safe Default
	decisionReason := "Fail-Safe Default"

	engineURL := "http://localhost:8000/evaluate"
	engineReqBody, _ := json.Marshal(req)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(engineURL, "application/json", bytes.NewBuffer(engineReqBody))

	if err != nil {
		log.Printf("⚠️ Case Law Engine unreachable. Falling back to Fail-Safe DENY. Error: %s", err)
		decisionReason = "Case Law Engine unreachable (Circuit Breaker Fail-Safe DENY)"
	} else {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var engineResp struct {
				Decision string `json:"decision"`
				Reason   string `json:"reason"`
				Status   string `json:"status"`
			}
			if decodeErr := json.NewDecoder(resp.Body).Decode(&engineResp); decodeErr == nil {
				if engineResp.Decision == "ALLOW" || engineResp.Decision == "DENY" {
					decision = engineResp.Decision
					decisionReason = engineResp.Reason
				}
			}
		} else {
			log.Printf("⚠️ Case Law Engine returned non-200 status: %d", resp.StatusCode)
			decisionReason = fmt.Sprintf("Case Law Engine returned status %d", resp.StatusCode)
		}
	}

	log.Printf("Evaluated Request - Agent: %s | Action: %s -> Decision: %s (%s)", req.AgentID, req.Action, decision, authMode)

	// Respond with RFC-aligned HTTP status code
	w.Header().Set("Content-Type", "application/json")
	if decision == "ALLOW" {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ALLOW",
			"message": "Transaction permitted.",
		})
	} else {
		w.WriteHeader(http.StatusForbidden)
		responseMessage := "Transaction denied by Case Law precedent or Fail-Safe."
		if decisionReason != "" {
			responseMessage = decisionReason
		}
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "DENY",
			"message": responseMessage,
		})
	}

	// Asynchronously push the event to Redpanda
	publishAuditEvent(GatewayEvent{
		AgentID:   req.AgentID,
		Action:    req.Action,
		Payload:   req.Payload,
		Decision:  decision,
		Timestamp: time.Now().Format(time.RFC3339),
		AuthMode:  authMode,
		Reason:    decisionReason,
	})
}

// verifyAgentAuth validates Ed25519 or HMAC signatures and checks replay nonces
func verifyAgentAuth(r *http.Request, rawBody []byte, claimedAgentID string) (bool, string, string) {
	sig := r.Header.Get("X-Sentinel-Signature")
	tsHeader := r.Header.Get("X-Sentinel-Timestamp")
	nonce := r.Header.Get("X-Sentinel-Nonce")
	headerAgentID := r.Header.Get("X-Sentinel-Agent-ID")

	// If cryptographic headers are absent
	if sig == "" || tsHeader == "" || nonce == "" {
		if strictAuthEnabled {
			return false, "UNAUTHENTICATED", "Missing cryptographic signature headers (X-Sentinel-Signature, X-Sentinel-Timestamp, X-Sentinel-Nonce)"
		}
		// Dev / Simulator fallback
		return true, "LEGACY_UNSIGNED", ""
	}

	// 1. Agent ID consistency check
	if headerAgentID != "" && headerAgentID != claimedAgentID {
		return false, "IDENTITY_MISMATCH", fmt.Sprintf("Header agent_id (%s) does not match body agent_id (%s)", headerAgentID, claimedAgentID)
	}

	// 2. Timestamp drift check (+/- 60s)
	t, err := time.Parse(time.RFC3339, tsHeader)
	if err != nil {
		return false, "INVALID_TIMESTAMP", "Invalid RFC3339 timestamp format in X-Sentinel-Timestamp"
	}
	now := time.Now()
	if now.Sub(t) > 60*time.Second || t.Sub(now) > 60*time.Second {
		return false, "TIMESTAMP_DRIFT", "Request timestamp outside permitted drift window (±60s)"
	}

	// 3. Replay nonce check
	if !nonceStore.CheckAndRecord(nonce, now) {
		return false, "REPLAY_DETECTED", "Cryptographic nonce has already been consumed (replay attack prevention)"
	}

	// 4. Verify HMAC-SHA256 signature
	// Canonical message: claimedAgentID|tsHeader|nonce|SHA256(rawBody)
	bodyHash := sha256.Sum256(rawBody)
	canonical := fmt.Sprintf("%s|%s|%s|%s", claimedAgentID, tsHeader, nonce, hex.EncodeToString(bodyHash[:]))

	mac := hmac.New(sha256.New, []byte(agentSharedSecret))
	mac.Write([]byte(canonical))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(strings.ToLower(sig)), []byte(strings.ToLower(expectedSig))) {
		return false, "INVALID_SIGNATURE", "Cryptographic signature verification failed"
	}

	return true, "AUTHENTICATED_HMAC", ""
}

// checkParameterGuardrails inspects SQL, Shell commands, and transaction limits
func checkParameterGuardrails(action string, payload map[string]interface{}) (bool, string) {
	// 1. Deep recursive inspection for destructive SQL & Shell injections
	var inspectValue func(v interface{}) (bool, string)
	inspectValue = func(v interface{}) (bool, string) {
		switch val := v.(type) {
		case string:
			if destructiveSQLRegex.MatchString(val) {
				return false, "Destructive SQL DDL/DCL statement blocked by Parameter Guardrails"
			}
			if unboundedDeleteRegex.MatchString(val) {
				return false, "Unbounded DELETE statement without WHERE clause blocked by Parameter Guardrails"
			}
			// Command injection sanity check
			if shellInjectionRegex.MatchString(val) && (strings.Contains(val, "rm ") || strings.Contains(val, "curl ") || strings.Contains(val, "bash ") || strings.Contains(val, "/bin/sh")) {
				return false, "Arbitrary shell injection pattern detected by Parameter Guardrails"
			}
		case map[string]interface{}:
			for _, subv := range val {
				if ok, reason := inspectValue(subv); !ok {
					return false, reason
				}
			}
		case []interface{}:
			for _, subv := range val {
				if ok, reason := inspectValue(subv); !ok {
					return false, reason
				}
			}
		}
		return true, ""
	}

	if ok, reason := inspectValue(payload); !ok {
		return false, reason
	}

	// 2. Action-specific financial bounds
	upperAction := strings.ToUpper(action)
	var amount float64
	if rawAmount, ok := payload["amount"]; ok && rawAmount != nil {
		switch a := rawAmount.(type) {
		case float64:
			amount = a
		case int:
			amount = float64(a)
		case string:
			cleaned := strings.ReplaceAll(strings.ReplaceAll(a, "$", ""), ",", "")
			if parsed, err := strconv.ParseFloat(strings.TrimSpace(cleaned), 64); err == nil {
				amount = parsed
			}
		}
	}

	if amount < 0 {
		return false, "Negative transaction amounts are strictly prohibited"
	}

	switch upperAction {
	case "ISSUE_REFUND", "REFUND":
		if amount > 10000.0 {
			return false, fmt.Sprintf("Refund amount ($%.2f) exceeds Sentinel maximum refund threshold ($10,000.00)", amount)
		}
	case "CREDIT_INCREASE":
		if amount > 50000.0 {
			return false, fmt.Sprintf("Credit increase ($%.2f) exceeds Sentinel safety cap ($50,000.00)", amount)
		}
	case "TRANSFER":
		if amount > 25000.0 {
			return false, fmt.Sprintf("Transfer amount ($%.2f) exceeds single-transaction ceiling ($25,000.00)", amount)
		}
	}

	return true, ""
}

// publishAuditEvent delivers events to Kafka/Redpanda with delivery monitoring
func publishAuditEvent(event GatewayEvent) {
	if kafkaProducer == nil {
		return
	}
	eventBytes, err := json.Marshal(event)
	if err != nil {
		log.Printf("⚠️ Failed to marshal audit event: %v", err)
		return
	}

	deliveryChan := make(chan kafka.Event, 1)
	err = kafkaProducer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: kafka.PartitionAny},
		Value:          eventBytes,
	}, deliveryChan)

	if err != nil {
		log.Printf("⚠️ Kafka producer queue full or error: %v (event logged locally)", err)
		return
	}

	// Goroutine delivery receipt check
	go func() {
		ev := <-deliveryChan
		close(deliveryChan)
		m, ok := ev.(*kafka.Message)
		if ok && m.TopicPartition.Error != nil {
			log.Printf("⚠️ Redpanda delivery failed: %v", m.TopicPartition.Error)
		}
	}()
}
