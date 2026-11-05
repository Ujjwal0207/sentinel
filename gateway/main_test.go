package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
)

func initTestEnforcer(t *testing.T) {
	var err error
	enforcer, err = casbin.NewEnforcer("../casbin_policies/model.conf", "../casbin_policies/policy.csv")
	if err != nil {
		t.Fatalf("Failed to initialize test casbin enforcer: %v", err)
	}
}

func generateSignedHeaders(agentID string, rawBody []byte, secret string, tDelta time.Duration, nonce string) map[string]string {
	ts := time.Now().Add(tDelta).UTC().Format(time.RFC3339)
	bodyHash := sha256.Sum256(rawBody)
	canonical := fmt.Sprintf("%s|%s|%s|%s", agentID, ts, nonce, hex.EncodeToString(bodyHash[:]))

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	sig := hex.EncodeToString(mac.Sum(nil))

	return map[string]string{
		"Content-Type":         "application/json",
		"X-Sentinel-Agent-ID":  agentID,
		"X-Sentinel-Timestamp": ts,
		"X-Sentinel-Nonce":      nonce,
		"X-Sentinel-Signature":  sig,
	}
}

func TestVerifyAgentAuth_Valid(t *testing.T) {
	agentID := "ag_Travel_Bot"
	body := []byte(`{"agent_id":"ag_Travel_Bot","action":"Issue_Refund","payload":{"amount":50.0}}`)
	headers := generateSignedHeaders(agentID, body, agentSharedSecret, 0, "test-nonce-12345678")

	req := httptest.NewRequest("POST", "/enforce", bytes.NewBuffer(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	valid, mode, errStr := verifyAgentAuth(req, body, agentID)
	if !valid {
		t.Fatalf("Expected auth to be valid, got false. Reason: %s", errStr)
	}
	if mode != "AUTHENTICATED_HMAC" {
		t.Fatalf("Expected AUTHENTICATED_HMAC, got %s", mode)
	}
}

func TestVerifyAgentAuth_InvalidSignature(t *testing.T) {
	agentID := "ag_Travel_Bot"
	body := []byte(`{"agent_id":"ag_Travel_Bot","action":"Issue_Refund","payload":{"amount":50.0}}`)
	headers := generateSignedHeaders(agentID, body, "wrong-secret-key-123", 0, "test-nonce-12345679")

	req := httptest.NewRequest("POST", "/enforce", bytes.NewBuffer(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	valid, _, errStr := verifyAgentAuth(req, body, agentID)
	if valid {
		t.Fatalf("Expected invalid signature to be rejected, but got valid=true")
	}
	if errStr != "Cryptographic signature verification failed" {
		t.Fatalf("Unexpected error string: %s", errStr)
	}
}

func TestVerifyAgentAuth_ReplayProtection(t *testing.T) {
	agentID := "ag_Travel_Bot"
	body := []byte(`{"agent_id":"ag_Travel_Bot","action":"Issue_Refund","payload":{"amount":50.0}}`)
	headers := generateSignedHeaders(agentID, body, agentSharedSecret, 0, "replayed-nonce-12345678")

	req1 := httptest.NewRequest("POST", "/enforce", bytes.NewBuffer(body))
	for k, v := range headers {
		req1.Header.Set(k, v)
	}

	valid1, _, _ := verifyAgentAuth(req1, body, agentID)
	if !valid1 {
		t.Fatalf("First request with nonce should succeed")
	}

	// Replay same request with same nonce
	req2 := httptest.NewRequest("POST", "/enforce", bytes.NewBuffer(body))
	for k, v := range headers {
		req2.Header.Set(k, v)
	}

	valid2, _, errStr := verifyAgentAuth(req2, body, agentID)
	if valid2 {
		t.Fatalf("Replayed request with identical nonce should be REJECTED")
	}
	if errStr != "Cryptographic nonce has already been consumed (replay attack prevention)" {
		t.Fatalf("Unexpected replay error: %s", errStr)
	}
}

func TestVerifyAgentAuth_ShortNonceRejected(t *testing.T) {
	agentID := "ag_Travel_Bot"
	body := []byte(`{"agent_id":"ag_Travel_Bot","action":"Issue_Refund","payload":{"amount":50.0}}`)
	// Nonce is too short (only 8 chars, minimum is 16)
	headers := generateSignedHeaders(agentID, body, agentSharedSecret, 0, "short123")

	req := httptest.NewRequest("POST", "/enforce", bytes.NewBuffer(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	valid, _, errStr := verifyAgentAuth(req, body, agentID)
	if valid {
		t.Fatalf("Expected short nonce to be rejected")
	}
	t.Logf("Short nonce rejected correctly: %s", errStr)
}

func TestVerifyAgentAuth_DelimiterInjectionRejected(t *testing.T) {
	// Attempt delimiter injection with pipe in Agent ID
	maliciousAgentID := "ag_admin|fake_timestamp|fake_nonce"
	body := []byte(`{"agent_id":"` + maliciousAgentID + `","action":"Issue_Refund","payload":{"amount":50.0}}`)
	headers := generateSignedHeaders(maliciousAgentID, body, agentSharedSecret, 0, "test-nonce-12345678")

	req := httptest.NewRequest("POST", "/enforce", bytes.NewBuffer(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	valid, _, errStr := verifyAgentAuth(req, body, maliciousAgentID)
	if valid {
		t.Fatalf("Expected delimiter injection in Agent ID to be rejected")
	}
	t.Logf("Delimiter injection correctly blocked: %s", errStr)
}

func TestVerifyAgentAuth_TimestampDrift(t *testing.T) {
	agentID := "ag_Travel_Bot"
	body := []byte(`{"agent_id":"ag_Travel_Bot","action":"Issue_Refund","payload":{"amount":50.0}}`)
	// 5 minutes in the past
	headers := generateSignedHeaders(agentID, body, agentSharedSecret, -5*time.Minute, "stale-nonce-12345678")

	req := httptest.NewRequest("POST", "/enforce", bytes.NewBuffer(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	valid, _, errStr := verifyAgentAuth(req, body, agentID)
	if valid {
		t.Fatalf("Stale timestamp request should be REJECTED")
	}
	if errStr != "Request timestamp outside permitted drift window (±60s)" {
		t.Fatalf("Unexpected drift error: %s", errStr)
	}
}

func TestVerifyAgentAuth_LegacyUnsignedPassesInDevMode(t *testing.T) {
	strictAuthEnabled = false
	agentID := "ag_Travel_Bot"
	body := []byte(`{"agent_id":"ag_Travel_Bot","action":"Issue_Refund","payload":{"amount":50.0}}`)

	req := httptest.NewRequest("POST", "/enforce", bytes.NewBuffer(body))
	valid, mode, _ := verifyAgentAuth(req, body, agentID)
	if !valid {
		t.Fatalf("Legacy unsigned request should be permitted in dev mode (zero side effects)")
	}
	if mode != "LEGACY_UNSIGNED" {
		t.Fatalf("Expected LEGACY_UNSIGNED mode, got %s", mode)
	}
}

func TestParameterGuardrails_SQLCommentBypass(t *testing.T) {
	// Attacker tries to bypass filter using inline SQL comments: DROP/**/TABLE
	payload := map[string]interface{}{
		"query": "SELECT * FROM users; DROP/**/TABLE/**/accounts;--",
		"time":  "12:00:00",
	}

	passed, reason := checkParameterGuardrails("QUERY_DB", payload)
	if passed {
		t.Fatalf("Comment-obfuscated SQL DDL (DROP/**/TABLE) should have been blocked")
	}
	t.Logf("Comment-obfuscated SQL successfully blocked: %s", reason)
}

func TestParameterGuardrails_BareTruncate(t *testing.T) {
	// Attacker executes TRUNCATE without the optional 'TABLE' keyword
	payload := map[string]interface{}{
		"query": "TRUNCATE users;",
		"time":  "12:00:00",
	}

	passed, reason := checkParameterGuardrails("QUERY_DB", payload)
	if passed {
		t.Fatalf("Bare TRUNCATE statement should have been blocked")
	}
	t.Logf("Bare TRUNCATE successfully blocked: %s", reason)
}

func TestParameterGuardrails_NaNAmountBypass(t *testing.T) {
	// Attacker sends math.NaN() to bypass amount > 10000 check
	payload := map[string]interface{}{
		"amount": math.NaN(),
		"time":   "12:00:00",
	}

	passed, reason := checkParameterGuardrails("Issue_Refund", payload)
	if passed {
		t.Fatalf("NaN amount should be blocked to prevent numeric comparison bypass")
	}
	t.Logf("NaN amount successfully blocked: %s", reason)
}

func TestParameterGuardrails_InfinityAmountBypass(t *testing.T) {
	// Attacker sends +Inf
	payload := map[string]interface{}{
		"amount": math.Inf(1),
		"time":   "12:00:00",
	}

	passed, reason := checkParameterGuardrails("Issue_Refund", payload)
	if passed {
		t.Fatalf("Infinity amount should be blocked")
	}
	t.Logf("Infinity amount successfully blocked: %s", reason)
}

func TestParameterGuardrails_ContextAwareShellInspection(t *testing.T) {
	// Legitimate customer dispute containing words like 'curl' and semicolons
	legitPayload := map[string]interface{}{
		"dispute_reason": "I purchased shirts & pants; also curl cream from this merchant.",
		"time":           "12:00:00",
	}

	passed, reason := checkParameterGuardrails("Issue_Refund", legitPayload)
	if !passed {
		t.Fatalf("False positive: legitimate dispute text blocked as shell injection: %s", reason)
	}
	t.Logf("Legitimate customer text passed without false positive")

	// Actual shell injection in a command parameter
	maliciousPayload := map[string]interface{}{
		"command": "cat /tmp/test; python3 -c 'import socket; s=socket.socket()'",
	}

	passedMal, reasonMal := checkParameterGuardrails("EXEC_TOOL", maliciousPayload)
	if passedMal {
		t.Fatalf("Actual shell command chaining should have been blocked")
	}
	t.Logf("Shell command injection in tool parameter blocked: %s", reasonMal)
}

func TestParameterGuardrails_ExceedRefundCeiling(t *testing.T) {
	payload := map[string]interface{}{
		"amount": 15000.0,
		"time":   "12:00:00",
	}

	passed, reason := checkParameterGuardrails("Issue_Refund", payload)
	if passed {
		t.Fatalf("Refund of $15,000 should exceed $10,000 threshold and be blocked")
	}
	t.Logf("Successfully blocked excessive refund: %s", reason)
}

func TestParameterGuardrails_LegitimateSimulatorRefund(t *testing.T) {
	payload := map[string]interface{}{
		"amount": 45.0,
		"time":   "12:00:00",
	}

	passed, reason := checkParameterGuardrails("Issue_Refund", payload)
	if !passed {
		t.Fatalf("Legitimate refund of $45 should pass guardrails, got blocked: %s", reason)
	}
}

func TestEnforceHandler_RBAC_Block(t *testing.T) {
	initTestEnforcer(t)

	// ag_Fraud_Bot is NOT authorized for Issue_Refund (only lock_tier)
	reqBody := []byte(`{"agent_id":"ag_Fraud_Bot","action":"Issue_Refund","payload":{"amount":50.0}}`)
	req := httptest.NewRequest("POST", "/enforce", bytes.NewBuffer(reqBody))
	rec := httptest.NewRecorder()

	enforceHandler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected HTTP 403 Forbidden for RBAC unauthorized agent, got %d", rec.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["status"] != "DENY" {
		t.Fatalf("Expected status DENY in body, got %v", resp["status"])
	}
}
