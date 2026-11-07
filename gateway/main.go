package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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
	"syscall"
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

// Google AP2 Intent Mandate Configuration (Phase 3.2)
var intentSharedSecret = "sentinel-intent-mandate-secret-2026"
var requireIntentMandate = false

// UserIntentMandate represents a cryptographically anchored user mandate (Google AP2 Standard)
type UserIntentMandate struct {
	MandateID    string    `json:"mandate_id"`
	AuthorizerID string    `json:"authorizer_id"`
	Action       string    `json:"action"`
	MaxAmount    float64   `json:"max_amount"`
	Currency     string    `json:"currency"`
	Recipient    string    `json:"recipient"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Commitment   string    `json:"commitment"`
}

// MandateConsumptionTracker tracks and prevents replay of one-time user intent mandates
type MandateConsumptionTracker struct {
	mu        sync.Mutex
	consumed  map[string]time.Time
	lastPurge time.Time
}

var globalMandateTracker = &MandateConsumptionTracker{
	consumed:  make(map[string]time.Time),
	lastPurge: time.Now(),
}

func (mct *MandateConsumptionTracker) CheckAndConsume(mandateID string, now time.Time) (bool, string) {
	if mandateID == "" {
		return false, "Missing mandate_id"
	}
	mct.mu.Lock()
	defer mct.mu.Unlock()

	// Periodic purge of expired records older than 1 hour
	if now.Sub(mct.lastPurge) > 60*time.Second {
		for id, t := range mct.consumed {
			if now.Sub(t) > 3600*time.Second {
				delete(mct.consumed, id)
			}
		}
		mct.lastPurge = now
	}

	if _, exists := mct.consumed[mandateID]; exists {
		return false, fmt.Sprintf("MANDATE_REPLAY_DETECTED: Mandate ID (%s) has already been consumed", mandateID)
	}
	mct.consumed[mandateID] = now
	return true, ""
}

func (mct *MandateConsumptionTracker) Reset() {
	mct.mu.Lock()
	defer mct.mu.Unlock()
	mct.consumed = make(map[string]time.Time)
	mct.lastPurge = time.Now()
}

// ComputeIntentCommitment calculates HMAC-SHA256 over canonicalized user intent fields (Google AP2)
func ComputeIntentCommitment(secret, authorizerID, action string, maxAmount float64, currency, recipient, mandateID string, expiresAtUnix int64) string {
	canonical := fmt.Sprintf("%s|%s|%.2f|%s|%s|%s|%d",
		strings.TrimSpace(authorizerID),
		strings.ToUpper(strings.TrimSpace(action)),
		maxAmount,
		strings.ToUpper(strings.TrimSpace(currency)),
		strings.TrimSpace(recipient),
		strings.TrimSpace(mandateID),
		expiresAtUnix,
	)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// extractPayloadRecipient looks up recipient identifiers across common alias keys
func extractPayloadRecipient(payload map[string]interface{}) string {
	keys := []string{"recipient", "to", "payee", "beneficiary", "target_account", "account_id", "destination_account", "user_id"}
	for _, k := range keys {
		if v, ok := payload[k]; ok && v != nil {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

// extractRawCurrency retrieves currency string from payload
func extractRawCurrency(payload map[string]interface{}) string {
	if c, ok := payload["currency"]; ok && c != nil {
		if s, ok := c.(string); ok && strings.TrimSpace(s) != "" {
			return strings.ToUpper(strings.TrimSpace(s))
		}
	}
	if c, ok := payload["curr"]; ok && c != nil {
		if s, ok := c.(string); ok && strings.TrimSpace(s) != "" {
			return strings.ToUpper(strings.TrimSpace(s))
		}
	}
	return "USD"
}

// extractNativeFinancialAmount extracts the unadjusted native financial amount (before FX conversion)
func extractNativeFinancialAmount(payload map[string]interface{}) (bool, float64, string) {
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

	if matchedKey == "amount_in_cents" || matchedKey == "cents" {
		amount = amount / 100.0
	}

	return true, amount, ""
}

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
	if globalStateMesh != nil {
		_ = globalStateMesh.Reset(context.Background())
	}
}

func (nc *NonceCache) Reset() {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	nc.nonces = make(map[string]time.Time)
	nc.lastEviction = time.Now()
}

// -------------------------------------------------------------------
// PHASE 3.1: Socket-Level Transport Defense & TOCTOU Rebinding Prevention
// -------------------------------------------------------------------

// IsRestrictedOrPrivateIP checks whether an IP address belongs to any private, loopback, link-local,
// carrier-grade NAT, multicast, reserved, documentation, or cloud metadata ranges (IPv4 & IPv6).
func IsRestrictedOrPrivateIP(ip net.IP) (bool, string) {
	if ip == nil {
		return true, "Invalid or unparseable IP address"
	}

	// Detailed IPv4 evaluation (including IPv4-mapped IPv6)
	if ip4 := ip.To4(); ip4 != nil {
		// 127.0.0.0/8 (Loopback)
		if ip4[0] == 127 || ip.IsLoopback() {
			return true, fmt.Sprintf("IPv4 loopback address (%s) blocked", ip)
		}
		// 169.254.0.0/16 (Link-Local / Cloud Metadata IMDS)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true, fmt.Sprintf("Link-local cloud metadata address (%s) blocked (Cloud metadata risk)", ip)
		}
		// 10.0.0.0/8 (RFC 1918 Private)
		if ip4[0] == 10 {
			return true, fmt.Sprintf("RFC 1918 private address (%s) blocked", ip)
		}
		// 172.16.0.0/12 (RFC 1918 Private: 172.16.0.0 - 172.31.255.255)
		if ip4[0] == 172 && (ip4[1] >= 16 && ip4[1] <= 31) {
			return true, fmt.Sprintf("RFC 1918 private address (%s) blocked", ip)
		}
		// 192.168.0.0/16 (RFC 1918 Private)
		if ip4[0] == 192 && ip4[1] == 168 {
			return true, fmt.Sprintf("RFC 1918 private address (%s) blocked", ip)
		}
		// 100.64.0.0/10 (Carrier-Grade NAT RFC 6598: 100.64.0.0 - 100.127.255.255)
		if ip4[0] == 100 && (ip4[1] >= 64 && ip4[1] <= 127) {
			return true, fmt.Sprintf("Carrier-Grade NAT address (%s) blocked (RFC 6598)", ip)
		}
		// 0.0.0.0/8 (Broadcast/Current network)
		if ip4[0] == 0 {
			return true, fmt.Sprintf("Broadcast / Current network address (%s) blocked", ip)
		}
		// 192.0.2.0/24 (TEST-NET-1 RFC 5737)
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2 {
			return true, fmt.Sprintf("Documentation subnet address (%s) blocked (RFC 5737)", ip)
		}
		// 198.51.100.0/24 (TEST-NET-2 RFC 5737)
		if ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100 {
			return true, fmt.Sprintf("Documentation subnet address (%s) blocked (RFC 5737)", ip)
		}
		// 203.0.113.0/24 (TEST-NET-3 RFC 5737)
		if ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113 {
			return true, fmt.Sprintf("Documentation subnet address (%s) blocked (RFC 5737)", ip)
		}
		// 198.18.0.0/15 (Benchmarking RFC 2544: 198.18.0.0 - 198.19.255.255)
		if ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19) {
			return true, fmt.Sprintf("Benchmarking network address (%s) blocked (RFC 2544)", ip)
		}
		// 224.0.0.0/4 (Multicast RFC 5771: 224.0.0.0 - 239.255.255.255)
		if ip4[0] >= 224 && ip4[0] <= 239 {
			return true, fmt.Sprintf("Multicast address (%s) blocked", ip)
		}
		// 255.255.255.255 (Limited broadcast)
		if ip4[0] == 255 && ip4[1] == 255 && ip4[2] == 255 && ip4[3] == 255 {
			return true, fmt.Sprintf("Limited broadcast address (%s) blocked", ip)
		}
		// 240.0.0.0/4 (Reserved / Future use RFC 1112)
		if ip4[0] >= 240 {
			return true, fmt.Sprintf("Reserved/Multicast address (%s) blocked", ip)
		}
		if ip.IsPrivate() {
			return true, fmt.Sprintf("Private network address (%s) blocked", ip)
		}
		return false, ""
	}

	// 16-byte IPv6 evaluation
	if ip.IsLoopback() {
		return true, fmt.Sprintf("IPv6 Loopback address (%s) blocked", ip)
	}
	if ip.IsUnspecified() {
		return true, fmt.Sprintf("IPv6 Unspecified address (%s) blocked", ip)
	}
	if len(ip) == 16 {
		// IPv6 Unique-Local Address (fc00::/7 - fc00... to fdff...)
		if ip[0] == 0xfc || ip[0] == 0xfd || ip.IsPrivate() {
			return true, fmt.Sprintf("IPv6 Unique Local Address (%s) blocked (RFC 4193 / Cloud IMDSv2)", ip)
		}
		// IPv6 Link-Local (fe80::/10)
		if (ip[0] == 0xfe && (ip[1]&0xc0) == 0x80) || ip.IsLinkLocalUnicast() {
			return true, fmt.Sprintf("IPv6 Link-Local Address (%s) blocked (RFC 4291)", ip)
		}
		// 6to4 encapsulation (2002::/16) - embedded IPv4 in bytes 2..6
		if ip[0] == 0x20 && ip[1] == 0x02 {
			embeddedIPv4 := net.IPv4(ip[2], ip[3], ip[4], ip[5])
			if restricted, reason := IsRestrictedOrPrivateIP(embeddedIPv4); restricted {
				return true, fmt.Sprintf("IPv6 6to4 encapsulation embeds restricted address: %s", reason)
			}
		}
	}
	if ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true, fmt.Sprintf("Multicast address (%s) blocked", ip)
	}

	return false, ""
}

// HardenedSocketControl intercepts raw TCP socket creation at the OS level (connect syn-ack instant)
// rendering dynamic DNS rebinding (TOCTOU) structurally impossible.
func HardenedSocketControl(network, address string, c syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("TRANSPORT_GUARD: Unparseable IP address in socket connection: %q", host)
	}

	if restricted, reason := IsRestrictedOrPrivateIP(ip); restricted {
		return fmt.Errorf("TRANSPORT_GUARD: TCP handshake blocked to restricted destination (%s): %s", ip, reason)
	}

	return nil
}

// CreateHardenedDialer produces a net.Dialer equipped with low-level socket interception
func CreateHardenedDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   HardenedSocketControl,
	}
}

// CreateHardenedHTTPTransport produces an http.Transport with physical socket-level pinning
func CreateHardenedHTTPTransport() *http.Transport {
	return &http.Transport{
		DialContext:           CreateHardenedDialer().DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// ValidateOutboundURLTransport performs deep verification of a URL, resolving DNS records
// and auditing every resolved IP against restricted subnets before any socket dial can occur.
func ValidateOutboundURLTransport(rawURL string) (bool, string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false, fmt.Sprintf("Invalid URL syntax: %v", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return false, fmt.Sprintf("Dangerous protocol (%s://) is strictly prohibited (only HTTP/HTTPS allowed)", scheme)
	}

	host := strings.TrimSuffix(parsed.Hostname(), ".")
	if host == "" {
		return false, "Empty hostname in URL"
	}

	lowerHost := strings.ToLower(host)
	if lowerHost == "169.254.169.254" || lowerHost == "metadata.google.internal" || lowerHost == "instance-data" || lowerHost == "localhost" {
		return false, fmt.Sprintf("SSRF blocked: Known metadata/localhost endpoint (%s)", host)
	}

	// Check if host is decimal/hex integer IP
	if decIP, err := strconv.ParseUint(host, 0, 32); err == nil {
		ip := net.IPv4(byte(decIP>>24), byte(decIP>>16), byte(decIP>>8), byte(decIP))
		if restricted, reason := IsRestrictedOrPrivateIP(ip); restricted {
			return false, fmt.Sprintf("SSRF blocked: Encoded IP (%s -> %s): %s", host, ip, reason)
		}
	}

	// Check for dotted octal/hex notation (e.g. 0177.0.0.1, 0x7f.0.0.1, 0251.0376.0251.0376)
	parts := strings.Split(host, ".")
	if len(parts) == 4 {
		var octets [4]byte
		validDotted := true
		hasNonDecimal := false
		for idx, p := range parts {
			trimmed := strings.TrimSpace(p)
			if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") || (len(trimmed) > 1 && trimmed[0] == '0') {
				hasNonDecimal = true
			}
			val, pErr := strconv.ParseUint(trimmed, 0, 8)
			if pErr != nil {
				validDotted = false
				break
			}
			octets[idx] = byte(val)
		}
		if validDotted && hasNonDecimal {
			dottedIP := net.IPv4(octets[0], octets[1], octets[2], octets[3])
			if restricted, reason := IsRestrictedOrPrivateIP(dottedIP); restricted {
				return false, fmt.Sprintf("SSRF blocked: Encoded octal/hex IP (%s -> %s): %s", host, dottedIP.String(), reason)
			}
		}
	}

	// Check if literal IP
	if ip := net.ParseIP(host); ip != nil {
		if restricted, reason := IsRestrictedOrPrivateIP(ip); restricted {
			return false, fmt.Sprintf("SSRF blocked: Literal IP (%s): %s", host, reason)
		}
		return true, ""
	}

	// Check suspicious domain patterns
	if strings.Contains(lowerHost, "rebind") || strings.Contains(lowerHost, ".internal") || strings.Contains(lowerHost, ".local") {
		return false, fmt.Sprintf("SSRF blocked: Suspicious domain pattern (%s) associated with DNS rebinding or internal metadata", host)
	}

	// Resolve DNS hostnames to verify that all resolved IPs are safe
	ips, err := net.LookupIP(host)
	if err != nil {
		return false, fmt.Sprintf("DNS resolution failed for host %s: %v", host, err)
	}

	for _, resolvedIP := range ips {
		if restricted, reason := IsRestrictedOrPrivateIP(resolvedIP); restricted {
			return false, fmt.Sprintf("DNS Rebinding / SSRF blocked: Domain %s resolved to restricted IP (%s): %s", host, resolvedIP, reason)
		}
	}

	return true, ""
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

	host := strings.TrimSuffix(parsed.Hostname(), ".")
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
		if restricted, reason := IsRestrictedOrPrivateIP(ip); restricted {
			return false, fmt.Sprintf("SSRF blocked: Encoded IP address (%s -> %s) resolves to forbidden subnet (%s)", host, ip.String(), reason)
		}
	}

	// Check for dotted octal/hex notation (e.g. 0177.0.0.1, 0x7f.0.0.1, 0251.0376.0251.0376)
	parts := strings.Split(host, ".")
	if len(parts) == 4 {
		var octets [4]byte
		validDotted := true
		hasNonDecimal := false
		for idx, p := range parts {
			trimmed := strings.TrimSpace(p)
			if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") || (len(trimmed) > 1 && trimmed[0] == '0') {
				hasNonDecimal = true
			}
			val, pErr := strconv.ParseUint(trimmed, 0, 8)
			if pErr != nil {
				validDotted = false
				break
			}
			octets[idx] = byte(val)
		}
		if validDotted && hasNonDecimal {
			dottedIP := net.IPv4(octets[0], octets[1], octets[2], octets[3])
			if restricted, reason := IsRestrictedOrPrivateIP(dottedIP); restricted {
				return false, fmt.Sprintf("SSRF blocked: Encoded octal/hex IP address (%s -> %s) resolves to forbidden subnet (%s)", host, dottedIP.String(), reason)
			}
		}
	}

	// Parse literal IP
	ip := net.ParseIP(host)
	if ip != nil {
		if restricted, reason := IsRestrictedOrPrivateIP(ip); restricted {
			return false, fmt.Sprintf("SSRF blocked: Access to private IP / loopback endpoint (%s) is prohibited (%s)", host, reason)
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

	// Initialize Intent Mandate Configuration (Google AP2)
	if envIntentSecret := os.Getenv("SENTINEL_INTENT_SECRET"); envIntentSecret != "" {
		intentSharedSecret = envIntentSecret
	}
	if os.Getenv("SENTINEL_REQUIRE_INTENT_MANDATE") == "true" {
		requireIntentMandate = true
		log.Println("🔒 STRICT INTENT MANDATE ENFORCED: Requests require valid User Intent Commitment (Google AP2).")
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
		"status":                 "HEALTHY",
		"service":                "sentinel-edge-gateway",
		"strict_auth":            strictAuthEnabled,
		"require_intent_mandate": requireIntentMandate,
		"timestamp":              time.Now().Format(time.RFC3339),
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
	// SECURITY: Swarm-Wide Emergency Freeze Kill Switch (Phase 3.4)
	// -------------------------------------------------------------------
	if globalStateMesh != nil {
		if frozen, reason, _ := globalStateMesh.IsFleetFrozen(r.Context()); frozen {
			if req.AgentID != "ag_Admin" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]string{
					"status":  "DENY",
					"error":   "FLEET_FROZEN",
					"message": fmt.Sprintf("Swarm-wide emergency freeze active: %s", reason),
				})
				return
			}
		}
	}

	// -------------------------------------------------------------------
	// SECURITY: Cryptographic Agent Identity (KYA) & Replay Defense
	// -------------------------------------------------------------------
	authValid, authMode, authErr := verifyAgentAuth(r, rawBody, req.AgentID)
	if !authValid {
		log.Printf("⛔ KYA AUTH FAILED for [%s]: %s (%s)", req.AgentID, authErr, authMode)
		w.Header().Set("Content-Type", "application/json")
		statusCode := http.StatusUnauthorized
		if strings.HasPrefix(authMode, "UCAN_DENIED_") {
			var code int
			if n, _ := fmt.Sscanf(authMode, "UCAN_DENIED_%d", &code); n == 1 && code > 0 {
				statusCode = code
			} else {
				statusCode = http.StatusForbidden
			}
		} else if authMode == "INVALID_AGENT_ID" || authMode == "INVALID_UCAN_PAYLOAD" {
			statusCode = http.StatusBadRequest
		}
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "DENY",
			"error":   authMode,
			"message": authErr,
		})
		return
	}

	// -------------------------------------------------------------------
	// SECURITY: Google AP2 User Intent Mandate & Drift Anchor (Phase 3.2)
	// -------------------------------------------------------------------
	intentValid, intentCode, intentReason, _ := verifyIntentMandate(r, req)
	if !intentValid {
		log.Printf("⛔ INTENT MANDATE DRIFT BLOCKED [%s - %s]: %s (HTTP %d)", req.AgentID, req.Action, intentReason, intentCode)

		publishAuditEvent(GatewayEvent{
			AgentID:   req.AgentID,
			Action:    req.Action,
			Payload:   req.Payload,
			Decision:  "DENY",
			Timestamp: time.Now().Format(time.RFC3339),
			AuthMode:  authMode,
			Reason:    "INTENT_MANDATE_DRIFT: " + intentReason,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(intentCode)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "DENY",
			"error":   "INTENT_MANDATE_DRIFT",
			"message": intentReason,
			"code":    intentCode,
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
	// SECURITY: High-Dimensional Semantic Injection & Taint Guardrail (Phase 4.2)
	// -------------------------------------------------------------------
	originHeader := r.Header.Get("X-Sentinel-Data-Origin")
	if globalSemanticGuard != nil {
		semanticRes := globalSemanticGuard.InspectSemanticSafety(req.AgentID, req.Action, req.Payload, originHeader)
		if !semanticRes.IsSafe {
			log.Printf("⛔ SEMANTIC GUARD BLOCKED [%s - %s]: %s (Score: %.2f)",
				req.AgentID, req.Action, strings.Join(semanticRes.Violations, "; "), semanticRes.AnomalyScore)

			publishAuditEvent(GatewayEvent{
				AgentID:   req.AgentID,
				Action:    req.Action,
				Payload:   req.Payload,
				Decision:  "DENY",
				Timestamp: time.Now().Format(time.RFC3339),
				AuthMode:  authMode,
				Reason:    "SEMANTIC_ANOMALY: " + strings.Join(semanticRes.Violations, "; "),
			})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":        "DENY",
				"error":         semanticRes.RiskCategory,
				"message":       strings.Join(semanticRes.Violations, "; "),
				"anomaly_score": semanticRes.AnomalyScore,
			})
			return
		}
	}

	// -------------------------------------------------------------------
	// SECURITY: BSA/FinCEN Anti-Structuring & Sliding-Window Velocity Guardrail (Phase 3.4)
	// -------------------------------------------------------------------
	if hasAmt, normalizedAmount, _ := extractNormalizedFinancialAmount(req.Payload); hasAmt && normalizedAmount > 0 {
		var allowed bool
		var totalVelocity, maxLimit float64
		if globalStateMesh != nil {
			var err error
			allowed, totalVelocity, maxLimit, err = globalStateMesh.CheckAndRecordVelocity(r.Context(), req.AgentID, normalizedAmount, 1*time.Hour, 25000.0, time.Now())
			if err != nil {
				log.Printf("⚠️ Global state mesh velocity error: %v", err)
			}
		} else {
			allowed, totalVelocity, maxLimit = globalVelocityTracker.CheckAndRecord(req.AgentID, normalizedAmount, time.Now())
		}
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
	if enforcer != nil && authMode != "AUTHENTICATED_UCAN" {
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
	// THE CHECKPOINT LOGIC: Hybrid Microsecond In-Process & Case Law Precedent (Phase 4.1)
	// -------------------------------------------------------------------
	decision := "DENY" // Fail-Safe Default
	decisionReason := "Fail-Safe Default"

	engineURL := os.Getenv("SENTINEL_CASE_LAW_URL")
	useInProcess := os.Getenv("SENTINEL_INPROCESS_POLICY") == "true"

	if useInProcess || (engineURL == "" && os.Getenv("SENTINEL_ENABLE_INPROCESS_FALLBACK") == "true") {
		// Zero-Hop Edge In-Process Evaluation (< 10 µs)
		inProc := globalInProcessEngine.Evaluate(r.Context(), req.AgentID, req.Action, req.Payload)
		decision = inProc.Decision
		decisionReason = inProc.Reason
	} else if engineURL == "" {
		decisionReason = "Case Law Engine unreachable (Circuit Breaker Fail-Safe DENY)"
	} else if !globalInProcessEngine.cb.ShouldTryExternal() && os.Getenv("SENTINEL_ENABLE_INPROCESS_FALLBACK") == "true" {
		// Circuit Breaker OPEN -> Fallback to in-process engine
		inProc := globalInProcessEngine.Evaluate(r.Context(), req.AgentID, req.Action, req.Payload)
		decision = inProc.Decision
		decisionReason = inProc.Reason + " [In-Process Circuit Breaker Fallback]"
	} else {
		engineReqBody, _ := json.Marshal(req)
		client := &http.Client{Timeout: 2 * time.Second}
		startHop := time.Now()
		resp, err := client.Post(engineURL, "application/json", bytes.NewBuffer(engineReqBody))

		if err != nil {
			log.Printf("⚠️ Case Law Engine unreachable (%v). Circuit breaker recorded failure.", err)
			globalInProcessEngine.cb.RecordFailure()
			if os.Getenv("SENTINEL_ENABLE_INPROCESS_FALLBACK") == "true" {
				inProc := globalInProcessEngine.Evaluate(r.Context(), req.AgentID, req.Action, req.Payload)
				decision = inProc.Decision
				decisionReason = inProc.Reason + " [In-Process Fallback]"
			} else {
				decisionReason = "Case Law Engine unreachable (Circuit Breaker Fail-Safe DENY)"
			}
		} else {
			defer resp.Body.Close()
			hopDuration := time.Since(startHop)
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
						globalInProcessEngine.cb.RecordSuccess(hopDuration)
					}
				}
			} else {
				log.Printf("⚠️ Case Law Engine returned non-200 status: %d", resp.StatusCode)
				globalInProcessEngine.cb.RecordFailure()
				decisionReason = fmt.Sprintf("Case Law Engine returned status %d", resp.StatusCode)
			}
		}
	}

	log.Printf("Evaluated Request - Agent: %s | Action: %s -> Decision: %s (%s)", req.AgentID, req.Action, decision, authMode)

	// -------------------------------------------------------------------
	// ZERO-LOSS PRE-COMMIT AUDIT RECEIPT (Phase 3.5 WAL)
	// Synchronous durable recording before client receives response (< 2 µs)
	// -------------------------------------------------------------------
	event := GatewayEvent{
		AgentID:   req.AgentID,
		Action:    req.Action,
		Payload:   req.Payload,
		Decision:  decision,
		Timestamp: time.Now().Format(time.RFC3339),
		AuthMode:  authMode,
		Reason:    decisionReason,
	}
	if globalAuditWAL != nil {
		if walEntry, walErr := globalAuditWAL.WriteSync(event); walErr == nil && walEntry != nil {
			w.Header().Set("X-Sentinel-WAL-Seq", fmt.Sprintf("%d", walEntry.SequenceNum))
			w.Header().Set("X-Sentinel-WAL-Hash", walEntry.EntryHash)
		}
	}

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
	publishAuditEvent(event)
}

// verifyAgentAuth validates Ed25519, UCAN, or HMAC signatures and checks replay nonces
func verifyAgentAuth(r *http.Request, rawBody []byte, claimedAgentID string) (bool, string, string) {
	sig := r.Header.Get("X-Sentinel-Signature")
	tsHeader := r.Header.Get("X-Sentinel-Timestamp")
	nonce := r.Header.Get("X-Sentinel-Nonce")
	headerAgentID := r.Header.Get("X-Sentinel-Agent-ID")
	ucanHeader := r.Header.Get("X-Sentinel-UCAN")

	// If all cryptographic headers are absent
	if sig == "" && tsHeader == "" && nonce == "" && headerAgentID == "" && ucanHeader == "" {
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

	// 3. Cluster-Wide Replay Nonce Check (Phase 3.4 Distributed State Mesh)
	if globalStateMesh != nil {
		if ok, clusterErr := globalStateMesh.CheckAndConsumeNonce(r.Context(), claimedAgentID, nonce, now, 120*time.Second); !ok {
			return false, "REPLAY_DETECTED", clusterErr
		}
	}
	if ok, nonceErr := nonceStore.CheckAndRecord(nonce, now); !ok {
		return false, "REPLAY_DETECTED", nonceErr
	}

	bodyHash := sha256.Sum256(rawBody)

	// 4. Check for UCAN Delegation Mode (Phase 3.3)
	if ucanHeader != "" {
		var token UCANToken
		tokenBytes := []byte(ucanHeader)
		trimmedHeader := strings.TrimSpace(ucanHeader)
		if !strings.HasPrefix(trimmedHeader, "{") {
			decoded, err := base64.StdEncoding.DecodeString(trimmedHeader)
			if err == nil {
				tokenBytes = decoded
			}
		}
		if err := json.Unmarshal(tokenBytes, &token); err != nil {
			return false, "INVALID_UCAN_PAYLOAD", fmt.Sprintf("Malformed UCAN token JSON: %v", err)
		}

		// Leaf agent must sign the canonical request payload with its Ed25519 key
		leafKey, hasLeafKey := globalKeyRegistry.GetKey(claimedAgentID)
		if !hasLeafKey {
			return false, "UNAUTHENTICATED_AGENT_KEY", fmt.Sprintf("No registered public key for leaf agent (%s)", claimedAgentID)
		}
		if !VerifyCanonicalPayloadEd25519(leafKey, claimedAgentID, tsHeader, nonce, bodyHash[:], sig) {
			return false, "INVALID_ED25519_SIGNATURE", "Leaf agent signature verification failed over request payload"
		}

		// Extract target action and payload from rawBody
		var tmpReq AgentRequest
		_ = json.Unmarshal(rawBody, &tmpReq)

		trustedRoots := map[string]bool{
			"ag_Admin":          true,
			"ag_Root_Authority": true,
			"did:key:admin":     true,
			"ag_Dispute_AI":     true,
		}

		valid, ucanCode, ucanErr := VerifyUCANDelegationChain(&token, claimedAgentID, tmpReq.Action, tmpReq.Payload, now, globalKeyRegistry, trustedRoots)
		if !valid {
			return false, fmt.Sprintf("UCAN_DENIED_%d", ucanCode), ucanErr
		}
		return true, "AUTHENTICATED_UCAN", ""
	}

	// 5. Check for Asymmetric Ed25519 Authentication (Phase 3.3)
	authScheme := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Sentinel-Auth-Scheme")))
	pubKey, hasEd25519Key := globalKeyRegistry.GetKey(claimedAgentID)
	if authScheme == "ed25519" || (hasEd25519Key && len(strings.TrimSpace(sig)) == 128) {
		if !hasEd25519Key {
			return false, "UNAUTHENTICATED_AGENT_KEY", fmt.Sprintf("No Ed25519 public key registered for agent (%s)", claimedAgentID)
		}
		if !VerifyCanonicalPayloadEd25519(pubKey, claimedAgentID, tsHeader, nonce, bodyHash[:], sig) {
			return false, "INVALID_ED25519_SIGNATURE", "Ed25519 asymmetric signature verification failed"
		}
		return true, "AUTHENTICATED_ED25519", ""
	}

	// 6. Verify HMAC-SHA256 signature (Legacy / Symmetric Mode)
	canonical := fmt.Sprintf("%s|%s|%s|%s", claimedAgentID, tsHeader, nonce, hex.EncodeToString(bodyHash[:]))

	mac := hmac.New(sha256.New, []byte(agentSharedSecret))
	mac.Write([]byte(canonical))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(strings.ToLower(sig)), []byte(strings.ToLower(expectedSig))) {
		return false, "INVALID_SIGNATURE", "Cryptographic signature verification failed"
	}

	return true, "AUTHENTICATED_HMAC", ""
}

// verifyIntentMandate enforces the Google AP2 User Intent Mandate protocol, ensuring that
// downstream tool invocations have not drifted in action, amount, currency, or recipient from
// the user's initial cryptographically anchored mandate.
func verifyIntentMandate(r *http.Request, req AgentRequest) (bool, int, string, *UserIntentMandate) {
	sigHeader := r.Header.Get("X-Sentinel-Intent-Commitment")
	authorizerHeader := r.Header.Get("X-Sentinel-Intent-Authorizer")
	mandateIDHeader := r.Header.Get("X-Sentinel-Intent-Mandate-ID")
	maxAmtHeader := r.Header.Get("X-Sentinel-Intent-Max-Amount")
	currHeader := r.Header.Get("X-Sentinel-Intent-Currency")
	recipientHeader := r.Header.Get("X-Sentinel-Intent-Recipient")
	expiresHeader := r.Header.Get("X-Sentinel-Intent-Expires")

	// If no intent commitment header is present
	if sigHeader == "" && authorizerHeader == "" && mandateIDHeader == "" && maxAmtHeader == "" && expiresHeader == "" {
		if requireIntentMandate {
			return false, http.StatusForbidden, "MANDATE_REQUIRED: Action requires cryptographic User Intent Mandate (Google AP2)", nil
		}
		return true, http.StatusOK, "NO_MANDATE_APPLIED", nil
	}

	// Partial header protection: if any intent header is provided, core fields must all be present
	if sigHeader == "" || authorizerHeader == "" || mandateIDHeader == "" || maxAmtHeader == "" || expiresHeader == "" {
		return false, http.StatusBadRequest, "INCOMPLETE_INTENT_HEADERS: Mandate headers require Commitment, Authorizer, Mandate-ID, Max-Amount, and Expires", nil
	}

	if currHeader == "" {
		currHeader = "USD"
	}
	currHeader = strings.ToUpper(strings.TrimSpace(currHeader))

	maxAmount, err := strconv.ParseFloat(strings.TrimSpace(maxAmtHeader), 64)
	if err != nil || maxAmount < 0 || math.IsNaN(maxAmount) || math.IsInf(maxAmount, 0) {
		return false, http.StatusBadRequest, "INVALID_MANDATE_AMOUNT: Max-Amount must be a valid non-negative number", nil
	}

	expiresUnix, err := strconv.ParseInt(strings.TrimSpace(expiresHeader), 10, 64)
	if err != nil {
		if t, tErr := time.Parse(time.RFC3339, expiresHeader); tErr == nil {
			expiresUnix = t.Unix()
		} else {
			return false, http.StatusBadRequest, "INVALID_MANDATE_EXPIRY: Expires header must be unix timestamp or RFC3339", nil
		}
	}

	now := time.Now().UTC()
	// 1. Expiration check
	if now.Unix() > expiresUnix {
		return false, http.StatusUnprocessableEntity, fmt.Sprintf("MANDATE_EXPIRED: User intent mandate expired at unix %d (current: %d)", expiresUnix, now.Unix()), nil
	}

	// 2. Cryptographic commitment verification
	expectedSig := ComputeIntentCommitment(
		intentSharedSecret,
		authorizerHeader,
		req.Action,
		maxAmount,
		currHeader,
		recipientHeader,
		mandateIDHeader,
		expiresUnix,
	)

	if !hmac.Equal([]byte(strings.ToLower(sigHeader)), []byte(strings.ToLower(expectedSig))) {
		return false, http.StatusUnauthorized, "INTENT_COMMITMENT_FORGERY: Cryptographic mandate commitment signature mismatch", nil
	}

	// 3. Mandate replay check (consumed only after cryptographic validity is verified)
	if ok, reason := globalMandateTracker.CheckAndConsume(mandateIDHeader, now); !ok {
		return false, http.StatusUnprocessableEntity, reason, nil
	}

	// 4. Action Drift Check
	if actionHeader := r.Header.Get("X-Sentinel-Intent-Action"); actionHeader != "" {
		if !strings.EqualFold(strings.TrimSpace(actionHeader), strings.TrimSpace(req.Action)) {
			return false, http.StatusUnprocessableEntity, fmt.Sprintf("INTENT_ACTION_DRIFT: Authorized action (%s) diverges from executed action (%s)", actionHeader, req.Action), nil
		}
	}

	// 5. Currency Drift Check
	payloadCurrency := extractRawCurrency(req.Payload)
	if !strings.EqualFold(payloadCurrency, currHeader) {
		return false, http.StatusUnprocessableEntity, fmt.Sprintf("INTENT_CURRENCY_DRIFT: Authorized currency (%s) diverges from executed currency (%s)", currHeader, payloadCurrency), nil
	}

	// 6. Amount Inflation Drift Check
	hasAmt, rawNativeAmt, amtErr := extractNativeFinancialAmount(req.Payload)
	if hasAmt {
		if amtErr != "" {
			return false, http.StatusBadRequest, amtErr, nil
		}
		if rawNativeAmt > maxAmount+0.0001 {
			return false, http.StatusUnprocessableEntity, fmt.Sprintf("INTENT_AMOUNT_INFLATION: Attempted amount (%.2f %s) exceeds authorized mandate ceiling (%.2f %s)", rawNativeAmt, payloadCurrency, maxAmount, currHeader), nil
		}
	}

	// 7. Recipient Substitution Drift Check
	payloadRecipient := extractPayloadRecipient(req.Payload)
	if recipientHeader != "" && payloadRecipient != "" {
		if !strings.EqualFold(strings.TrimSpace(payloadRecipient), strings.TrimSpace(recipientHeader)) {
			return false, http.StatusUnprocessableEntity, fmt.Sprintf("INTENT_RECIPIENT_DRIFT: Authorized recipient (%s) diverges from executed recipient (%s)", recipientHeader, payloadRecipient), nil
		}
	}

	mandate := &UserIntentMandate{
		MandateID:    mandateIDHeader,
		AuthorizerID: authorizerHeader,
		Action:       req.Action,
		MaxAmount:    maxAmount,
		Currency:     currHeader,
		Recipient:    recipientHeader,
		ExpiresAt:    time.Unix(expiresUnix, 0),
		Commitment:   sigHeader,
	}

	return true, http.StatusOK, "INTENT_MANDATE_VERIFIED", mandate
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

// publishAuditEvent delivers events to Kafka/Redpanda with zero-loss WAL protection
func publishAuditEvent(event GatewayEvent) {
	if globalAuditWAL != nil {
		// Ensure event is recorded in WAL if not already recorded (e.g., early guardrail denials)
		entries := globalAuditWAL.GetEntries(globalAuditWAL.GetLatestSequence(), 1)
		if len(entries) == 0 || entries[0].Event.Timestamp != event.Timestamp || entries[0].Event.AgentID != event.AgentID {
			_, _ = globalAuditWAL.WriteSync(event)
		}
		if globalAuditWAL.IsBrokerBroken() {
			log.Printf("⚠️ Kafka broker severed/unreachable. Event safely preserved in Zero-Loss WAL (Seq: %d)", globalAuditWAL.GetLatestSequence())
			return
		}
	}

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
		log.Printf("⚠️ Kafka producer queue full or error: %v (event preserved in WAL)", err)
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
