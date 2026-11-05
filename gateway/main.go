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
	"math"
	"net"
	"net/http"
	"net/url"
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

// Validation regexes for identifiers and nonces
var validIdentifierRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)
var validNonceRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,128}$`)

// NonceCache prevents replay attacks with efficient batched eviction
type NonceCache struct {
	mu           sync.Mutex
	nonces       map[string]time.Time
	lastEviction time.Time
}

var nonceStore = &NonceCache{
	nonces:       make(map[string]time.Time),
	lastEviction: time.Now(),
}

func (nc *NonceCache) CheckAndRecord(nonce string, now time.Time) (bool, string) {
	if !validNonceRegex.MatchString(nonce) {
		return false, "Invalid nonce format or length (must be 16-128 alphanumeric characters)"
	}

	nc.mu.Lock()
	defer nc.mu.Unlock()

	// Batched periodic eviction every 30s to prevent O(N) lock serialization per request
	if now.Sub(nc.lastEviction) > 30*time.Second {
		for k, t := range nc.nonces {
			if now.Sub(t) > 120*time.Second {
				delete(nc.nonces, k)
			}
		}
		nc.lastEviction = now
	}

	if _, exists := nc.nonces[nonce]; exists {
		return false, "Cryptographic nonce has already been consumed (replay attack prevention)"
	}
	nc.nonces[nonce] = now
	return true, ""
}

// Parameter Guardrail Regexes
// SQL Comment stripper regex to neutralize inline comment bypasses like DROP/**/TABLE
var sqlCommentRegex = regexp.MustCompile(`/\*[\s\S]*?\*/|--[^\r\n]*`)

// Destructive SQL DDL/DCL patterns: matches DROP, TRUNCATE, ALTER, GRANT, REVOKE
var destructiveSQLRegex = regexp.MustCompile(`(?i)\b(DROP\s+(TABLE|DATABASE|SCHEMA|VIEW|INDEX)|TRUNCATE(\s+TABLE)?|ALTER\s+(TABLE|DATABASE)|GRANT\s+ALL|REVOKE\s+ALL)\b`)
var unboundedDeleteRegex = regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+[a-zA-Z0-9_.-]+(\s*;|\s*$|\s+WHERE\s+(1=1|true|'1'='1')(\s*;|\s*$))`)

// System command and shell injection patterns
var systemActionRegex = regexp.MustCompile(`(?i)^(EXEC|EXEC_TOOL|BASH|SHELL|CMD|SYSTEM_COMMAND|RUN_SCRIPT)$`)
var commandKeyRegex = regexp.MustCompile(`(?i)^(cmd|command|script|shell|exec|query_exec)$`)
var dangerousShellBinaries = regexp.MustCompile(`(?i)\b(rm|curl|wget|nc|bash|sh|zsh|python|python3|perl|ruby|php|chmod|chown|kill|pkill|eval|dd)\b`)
var shellChainRegex = regexp.MustCompile(`[;&|` + "`" + `]|\$\(.*\)`)

// Enterprise SQL DML Mutation & Exfiltration patterns: matches UPDATE, INSERT, UNION SELECT
var sqlMutationRegex = regexp.MustCompile(`(?i)\b(UPDATE\s+[a-zA-Z0-9_.-]+\s+SET|INSERT\s+INTO\s+[a-zA-Z0-9_.-]+)\b`)
var sqlExfiltrationRegex = regexp.MustCompile(`(?i)\b(UNION(\s+ALL)?\s+SELECT|SELECT\s+.*\s+FROM\s+(vault|cards|credit_cards|users|passwords|accounts|credentials|secrets|vault_cards))\b`)

// Blind SQL injection (time delays & benchmarks) and file read/write exfiltration
var sqlBlindTimeRegex = regexp.MustCompile(`(?i)\b(pg_sleep\s*\(|SLEEP\s*\(|WAITFOR\s+DELAY\b|BENCHMARK\s*\(|LOAD_FILE\s*\(|INTO\s+(OUTFILE|DUMPFILE)\b)`)

// Universal Shell Injection chaining: catches control operators followed by command binaries across all parameters
var universalShellChainRegex = regexp.MustCompile(`(?i)([;&|` + "`" + `]|\$\()\s*(rm(\s+-[a-z]*r|\s+-rf|\s+\/)|python[0-9]?\s+-c|nc\s+-[a-z0-9]|wget\s+https?|curl\s+https?|bash\s+-c|sh\s+-c|chmod\s+[0-7]+|cat\s+\/etc\/passwd|base64\s+-d|kill\s+-[0-9]+)`)
var standaloneShellExecutionRegex = regexp.MustCompile(`(?i)(` + "`" + `[^` + "`" + `]*(rm\s+-rf|cat\s+\/etc\/passwd|curl\s+https?|wget\s+https?|nc\s+-)[^` + "`" + `]*` + "`" + `|\$\([^\)]*(rm\s+-rf|cat\s+\/etc\/passwd|curl\s+https?|wget\s+https?|nc\s+-)[^\)]*\))`)

// URL detection pattern matching HTTP(S) and dangerous protocols (gopher, file, dict, ftp, ldap)
var urlPatternRegex = regexp.MustCompile(`(?i)^[a-zA-Z][a-zA-Z0-9+.-]*://`)

// Real-Time Foreign Exchange (FX) Normalization to USD
var fxExchangeRates = map[string]float64{
	"USD":  1.0,
	"USDC": 1.0,
	"USDT": 1.0,
	"KWD":  3.26,   // 1 KWD ≈ 3.26 USD
	"GBP":  1.28,   // 1 GBP ≈ 1.28 USD
	"EUR":  1.08,   // 1 EUR ≈ 1.08 USD
	"CAD":  0.73,   // 1 CAD ≈ 0.73 USD
	"AUD":  0.65,   // 1 AUD ≈ 0.65 USD
	"JPY":  0.0065, // 1 JPY ≈ 0.0065 USD
	"BTC":  65000.0,// 1 BTC ≈ 65,000 USD
	"ETH":  3500.0, // 1 ETH ≈ 3,500 USD
}

// sanitizeAndNormalizeText normalizes Unicode full-width characters to standard ASCII and strips zero-width spaces
func sanitizeAndNormalizeText(input string) string {
	var sb strings.Builder
	sb.Grow(len(input))

	for _, r := range input {
		// Strip zero-width and invisible formatting characters
		// U+200B (Zero-width space), U+200C (ZWNJ), U+200D (ZWJ), U+FEFF (BOM), U+00AD (Soft hyphen)
		if r == 0x200B || r == 0x200C || r == 0x200D || r == 0xFEFF || r == 0x00AD {
			continue
		}

		// Convert full-width ASCII variants (U+FF01 - U+FF5E) to standard ASCII (U+0021 - U+007E)
		if r >= 0xFF01 && r <= 0xFF5E {
			sb.WriteRune(r - 0xFEE0)
			continue
		}

		// Convert full-width space (U+3000) to standard ASCII space
		if r == 0x3000 {
			sb.WriteRune(' ')
			continue
		}

		sb.WriteRune(r)
	}

	return sb.String()
}

// detectDuplicateJSONKeys checks if a raw JSON body contains duplicate keys at any nesting level (RFC 8259)
func detectDuplicateJSONKeys(rawJSON []byte) error {
	dec := json.NewDecoder(bytes.NewReader(rawJSON))
	return checkDuplicatesRecursive(dec)
}

func checkDuplicatesRecursive(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return nil
	}

	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				continue
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON key detected: %q (RFC 8259 violation)", key)
			}
			seen[key] = true

			// Recurse into value
			if err := checkDuplicatesRecursive(dec); err != nil {
				return err
			}
		}
		dec.Token() // consume closing '}'
	case '[':
		for dec.More() {
			if err := checkDuplicatesRecursive(dec); err != nil {
				return err
			}
		}
		dec.Token() // consume closing ']'
	}

	return nil
}

// VelocityEntry represents an authorized financial transaction
type VelocityEntry struct {
	Timestamp time.Time
	Amount    float64
}

const numVelocityShards = 16

type VelocityShard struct {
	mu      sync.Mutex
	history map[string][]VelocityEntry
}

// ShardedVelocityTracker implements high-concurrency sliding-window AML velocity tracking with striped locks
type ShardedVelocityTracker struct {
	shards   [numVelocityShards]VelocityShard
	window   time.Duration
	maxLimit float64
}

var globalVelocityTracker = NewShardedVelocityTracker(1*time.Hour, 25000.0)

func NewShardedVelocityTracker(window time.Duration, maxLimit float64) *ShardedVelocityTracker {
	tracker := &ShardedVelocityTracker{
		window:   window,
		maxLimit: maxLimit,
	}
	for i := 0; i < numVelocityShards; i++ {
		tracker.shards[i].history = make(map[string][]VelocityEntry)
	}
	return tracker
}

func (s *ShardedVelocityTracker) getShard(agentID string) *VelocityShard {
	var h uint32 = 2166136261
	for i := 0; i < len(agentID); i++ {
		h = (h ^ uint32(agentID[i])) * 16777619
	}
	return &s.shards[h%numVelocityShards]
}

func (s *ShardedVelocityTracker) CheckAndRecord(agentID string, amount float64, now time.Time) (bool, float64, float64) {
	shard := s.getShard(agentID)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	cutoff := now.Add(-s.window)
	entries := shard.history[agentID]
	var validEntries []VelocityEntry
	var currentTotal float64

	for _, e := range entries {
		if e.Timestamp.After(cutoff) {
			validEntries = append(validEntries, e)
			currentTotal += e.Amount
		}
	}

	if currentTotal+amount > s.maxLimit {
		shard.history[agentID] = validEntries
		return false, currentTotal + amount, s.maxLimit
	}

	validEntries = append(validEntries, VelocityEntry{Timestamp: now, Amount: amount})
	shard.history[agentID] = validEntries
	return true, currentTotal + amount, s.maxLimit
}

func (s *ShardedVelocityTracker) Reset() {
	for i := 0; i < numVelocityShards; i++ {
		s.shards[i].mu.Lock()
		s.shards[i].history = make(map[string][]VelocityEntry)
		s.shards[i].mu.Unlock()
	}
}

// inspectSSRFProtection validates URLs against private RFC 1918 subnets, loopback, cloud metadata, and DNS rebinding
func inspectSSRFProtection(rawURL string) (bool, string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return true, "" // Not a valid URL, ignore
	}

	// Scheme whitelist: strictly http and https only
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		if scheme != "" {
			return false, fmt.Sprintf("SSRF blocked: Dangerous URL scheme (%s://) is strictly prohibited", scheme)
		}
		return true, ""
	}

	host := parsed.Hostname()
	if host == "" {
		return true, ""
	}

	lowerHost := strings.ToLower(host)
	if lowerHost == "169.254.169.254" || lowerHost == "metadata.google.internal" || lowerHost == "instance-data" || lowerHost == "localhost" {
		return false, fmt.Sprintf("SSRF blocked: Access to private IP / cloud metadata endpoint (%s) is prohibited", host)
	}

	// Check if host is an integer representation (decimal IP like 2130706433 or octal/hex)
	if decIP, err := strconv.ParseUint(host, 0, 32); err == nil {
		ip := net.IPv4(byte(decIP>>24), byte(decIP>>16), byte(decIP>>8), byte(decIP))
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return false, fmt.Sprintf("SSRF blocked: Encoded IP address (%s -> %s) resolves to forbidden subnet", host, ip.String())
		}
	}

	// Parse literal IP
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
			return false, fmt.Sprintf("SSRF blocked: Access to private IP / loopback endpoint (%s) is prohibited", host)
		}
		return true, ""
	}

	// Domain-cloaked / DNS Rebinding check: Block suspicious internal domain patterns
	if strings.Contains(lowerHost, "rebind") || strings.Contains(lowerHost, ".internal") || strings.Contains(lowerHost, ".local") {
		return false, fmt.Sprintf("SSRF blocked: Suspicious domain pattern (%s) associated with DNS rebinding or internal metadata", host)
	}

	return true, ""
}

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

	// Security: RFC 8259 Duplicate Key / Parameter Pollution Prevention
	if err := detectDuplicateJSONKeys(rawBody); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "DENY",
			"error":   "PARAMETER_POLLUTION_DETECTED",
			"message": err.Error(),
		})
		return
	}

	var req AgentRequest
	if err := json.Unmarshal(rawBody, &req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// -------------------------------------------------------------------
	// SECURITY: Strict Identifier Format & Length Validation
	// -------------------------------------------------------------------
	if !validIdentifierRegex.MatchString(req.AgentID) {
		http.Error(w, "Invalid agent_id format (must be 1-64 alphanumeric chars/hyphens/underscores)", http.StatusBadRequest)
		return
	}
	if !validIdentifierRegex.MatchString(req.Action) {
		http.Error(w, "Invalid action format (must be 1-64 alphanumeric chars/hyphens/underscores)", http.StatusBadRequest)
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
	// SECURITY: BSA/FinCEN Anti-Structuring & Sliding-Window Velocity Guardrail
	// -------------------------------------------------------------------
	if hasAmt, normalizedAmount, _ := extractNormalizedFinancialAmount(req.Payload); hasAmt && normalizedAmount > 0 {
		allowed, totalVelocity, maxLimit := globalVelocityTracker.CheckAndRecord(req.AgentID, normalizedAmount, time.Now())
		if !allowed {
			log.Printf("⛔ AML VELOCITY EXCEEDED [%s - %s]: Rolling volume ($%.2f) exceeds safety cap ($%.2f)", req.AgentID, req.Action, totalVelocity, maxLimit)
			publishAuditEvent(GatewayEvent{
				AgentID:   req.AgentID,
				Action:    req.Action,
				Payload:   req.Payload,
				Decision:  "DENY",
				Timestamp: time.Now().Format(time.RFC3339),
				AuthMode:  authMode,
				Reason:    fmt.Sprintf("VELOCITY_LIMIT_EXCEEDED: Rolling volume ($%.2f) exceeds safety ceiling ($%.2f)", totalVelocity, maxLimit),
			})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "DENY",
				"error":   "VELOCITY_LIMIT_EXCEEDED",
				"message": fmt.Sprintf("Transaction denied: Rolling 1-hour volume ($%.2f) exceeds safety ceiling ($%.2f)", totalVelocity, maxLimit),
			})
			return
		}
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

	engineURL := os.Getenv("SENTINEL_CASE_LAW_URL")
	if engineURL == "" {
		engineURL = "http://localhost:8000/evaluate"
	}
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

	// If all cryptographic headers are absent
	if sig == "" && tsHeader == "" && nonce == "" && headerAgentID == "" {
		if strictAuthEnabled {
			return false, "UNAUTHENTICATED", "Missing cryptographic signature headers (X-Sentinel-Signature, X-Sentinel-Timestamp, X-Sentinel-Nonce, X-Sentinel-Agent-ID)"
		}
		// Dev / Simulator fallback
		return true, "LEGACY_UNSIGNED", ""
	}

	// Partial header protection: if any header is provided, all required auth headers must be present
	if sig == "" || tsHeader == "" || nonce == "" || headerAgentID == "" {
		return false, "INCOMPLETE_AUTH_HEADERS", "All cryptographic headers must be provided (X-Sentinel-Signature, X-Sentinel-Timestamp, X-Sentinel-Nonce, X-Sentinel-Agent-ID)"
	}

	// 1. Strict Agent ID validation & match
	if !validIdentifierRegex.MatchString(claimedAgentID) {
		return false, "INVALID_AGENT_ID", "Claimed agent_id contains invalid characters or delimiters"
	}
	if headerAgentID != claimedAgentID {
		return false, "IDENTITY_MISMATCH", fmt.Sprintf("Header agent_id (%s) does not match body agent_id (%s)", headerAgentID, claimedAgentID)
	}

	// 2. Timestamp drift check (+/- 60s)
	t, err := time.Parse(time.RFC3339, tsHeader)
	if err != nil {
		return false, "INVALID_TIMESTAMP", "Invalid RFC3339 timestamp format in X-Sentinel-Timestamp"
	}
	now := time.Now().UTC()
	diff := now.Sub(t.UTC())
	if diff < -60*time.Second || diff > 60*time.Second {
		return false, "TIMESTAMP_DRIFT", "Request timestamp outside permitted drift window (±60s)"
	}

	// 3. Replay nonce check & validation
	if ok, nonceErr := nonceStore.CheckAndRecord(nonce, now); !ok {
		return false, "REPLAY_DETECTED", nonceErr
	}

	// 4. Verify HMAC-SHA256 signature
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

// extractNormalizedFinancialAmount extracts financial values across known aliases, handles minor units (cents), and normalizes FX to USD
func extractNormalizedFinancialAmount(payload map[string]interface{}) (bool, float64, string) {
	aliases := []string{"amount", "transfer_amount", "refund_amount", "total", "value", "payout", "amount_in_cents", "cents"}
	var rawAmount interface{}
	var matchedKey string
	hasAmount := false

	for _, alias := range aliases {
		if v, ok := payload[alias]; ok && v != nil {
			rawAmount = v
			matchedKey = alias
			hasAmount = true
			break
		}
	}

	if !hasAmount {
		return false, 0, ""
	}

	var amount float64
	switch a := rawAmount.(type) {
	case float64:
		amount = a
	case float32:
		amount = float64(a)
	case int:
		amount = float64(a)
	case int64:
		amount = float64(a)
	case string:
		cleaned := strings.ReplaceAll(strings.ReplaceAll(a, "$", ""), ",", "")
		if parsed, err := strconv.ParseFloat(strings.TrimSpace(cleaned), 64); err == nil {
			amount = parsed
		} else {
			return true, 0, "Invalid non-numeric format for amount"
		}
	default:
		return true, 0, "Invalid data type for amount"
	}

	if math.IsNaN(amount) || math.IsInf(amount, 0) {
		return true, 0, "Invalid floating-point number (NaN or Infinity detected)"
	}

	// Currency normalization
	currency := "USD"
	if currVal, ok := payload["currency"]; ok && currVal != nil {
		if cStr, ok := currVal.(string); ok {
			currency = strings.ToUpper(strings.TrimSpace(cStr))
		}
	} else if currVal, ok := payload["curr"]; ok && currVal != nil {
		if cStr, ok := currVal.(string); ok {
			currency = strings.ToUpper(strings.TrimSpace(cStr))
		}
	}

	rate, known := fxExchangeRates[currency]
	if !known {
		rate = 1.0 // fallback
	}

	// Minor currency unit handling (Stripe / FinTech integer cents to dollars)
	if matchedKey == "amount_in_cents" || matchedKey == "cents" {
		amount = amount / 100.0
	} else {
		// Enforce currency decimal precision (Sub-cent salami slicing defense)
		maxDecimals := 2
		switch currency {
		case "JPY":
			maxDecimals = 0
		case "KWD":
			maxDecimals = 3
		case "BTC", "ETH":
			maxDecimals = 8
		default:
			maxDecimals = 2
		}

		strVal := strconv.FormatFloat(amount, 'f', -1, 64)
		if parts := strings.Split(strVal, "."); len(parts) == 2 {
			decLen := len(parts[1])
			if decLen > maxDecimals {
				return true, 0, fmt.Sprintf("Sub-cent fractional currency precision prohibited: %s allows at most %d decimal places", currency, maxDecimals)
			}
		}

		// Financial precision: round fractional sub-cents to prevent IEEE 754 precision drift
		factor := math.Pow10(maxDecimals)
		amount = math.Round(amount*factor) / factor
	}

	normalizedUSD := amount * rate

	return true, normalizedUSD, ""
}

// checkParameterGuardrails inspects SQL, Shell commands, SSRF targets, and transaction limits
func checkParameterGuardrails(action string, payload map[string]interface{}) (bool, string) {
	upperAction := strings.ToUpper(action)
	isSystemAction := systemActionRegex.MatchString(upperAction)

	// 1. Recursive inspection with bounded depth (max 16 levels to prevent stack overflow)
	var inspectValue func(key string, v interface{}, depth int) (bool, string)
	inspectValue = func(key string, v interface{}, depth int) (bool, string) {
		if depth > 16 {
			return false, "Payload nesting depth exceeds safety threshold (max 16 levels)"
		}

		switch val := v.(type) {
		case string:
			// Normalize Unicode homoglyphs (fullwidth ASCII) and strip zero-width spaces
			normalizedVal := sanitizeAndNormalizeText(val)

			// Strip inline SQL comments (e.g. DROP/**/TABLE) before pattern evaluation
			normalizedSQL := sqlCommentRegex.ReplaceAllString(normalizedVal, " ")
			if destructiveSQLRegex.MatchString(normalizedSQL) {
				return false, "Destructive SQL DDL/DCL statement blocked by Parameter Guardrails"
			}
			if unboundedDeleteRegex.MatchString(normalizedSQL) {
				return false, "Unbounded DELETE statement without restrictive WHERE clause blocked by Parameter Guardrails"
			}
			if sqlMutationRegex.MatchString(normalizedSQL) {
				return false, "Unauthorized SQL DML mutation statement (UPDATE/INSERT) blocked by Parameter Guardrails"
			}
			if sqlExfiltrationRegex.MatchString(normalizedSQL) {
				return false, "SQL data exfiltration query (UNION SELECT) blocked by Parameter Guardrails"
			}
			if sqlBlindTimeRegex.MatchString(normalizedSQL) {
				return false, "SQL injection exploit vector (Time-based blind / File access) blocked by Parameter Guardrails"
			}

			// Universal Shell Command Chaining: flags chained command execution across any parameter
			if universalShellChainRegex.MatchString(normalizedVal) || standaloneShellExecutionRegex.MatchString(normalizedVal) {
				return false, "Arbitrary shell command chaining detected in payload parameter"
			}

			// Context-Aware Shell Inspection:
			isCommandParam := isSystemAction || commandKeyRegex.MatchString(key)
			if isCommandParam && shellChainRegex.MatchString(normalizedVal) && dangerousShellBinaries.MatchString(normalizedVal) {
				return false, "Arbitrary shell command chaining detected in command parameter"
			}

			// SSRF & Cloud Metadata Protection
			if urlPatternRegex.MatchString(normalizedVal) {
				if ok, reason := inspectSSRFProtection(normalizedVal); !ok {
					return false, reason
				}
			}

		case map[string]interface{}:
			for subk, subv := range val {
				if ok, reason := inspectValue(subk, subv, depth+1); !ok {
					return false, reason
				}
			}
		case []interface{}:
			for _, subv := range val {
				if ok, reason := inspectValue(key, subv, depth+1); !ok {
					return false, reason
				}
			}
		}
		return true, ""
	}

	if ok, reason := inspectValue("", payload, 0); !ok {
		return false, reason
	}

	// 2. Action-specific financial bounds with NaN, Inf, currency, and alias normalization
	hasAmount, normalizedUSD, errReason := extractNormalizedFinancialAmount(payload)
	if hasAmount {
		if errReason != "" {
			return false, errReason
		}

		// NaN and Inf defense: In IEEE 754, NaN comparisons return false (NaN > 10000 is FALSE, NaN < 0 is FALSE).
		// Attackers exploit this to bypass numeric boundaries.
		if math.IsNaN(normalizedUSD) || math.IsInf(normalizedUSD, 0) {
			return false, "Invalid floating-point number (NaN or Infinity detected)"
		}

		if normalizedUSD < 0 {
			return false, "Negative transaction amounts are strictly prohibited"
		}

		switch upperAction {
		case "ISSUE_REFUND", "REFUND":
			if normalizedUSD > 10000.0 {
				return false, fmt.Sprintf("Refund amount ($%.2f USD equivalent) exceeds Sentinel maximum refund threshold ($10,000.00)", normalizedUSD)
			}
		case "CREDIT_INCREASE":
			if normalizedUSD > 50000.0 {
				return false, fmt.Sprintf("Credit increase ($%.2f USD equivalent) exceeds Sentinel safety cap ($50,000.00)", normalizedUSD)
			}
		case "TRANSFER":
			if normalizedUSD > 25000.0 {
				return false, fmt.Sprintf("Transfer amount ($%.2f USD equivalent) exceeds single-transaction ceiling ($25,000.00)", normalizedUSD)
			}
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
