package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	headers := generateSignedHeaders(agentID, body, agentSharedSecret, 0, "test-nonce-1")

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
	headers := generateSignedHeaders(agentID, body, "wrong-secret-key", 0, "test-nonce-2")

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
	headers := generateSignedHeaders(agentID, body, agentSharedSecret, 0, "replayed-nonce-123")

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

func TestVerifyAgentAuth_TimestampDrift(t *testing.T) {
	agentID := "ag_Travel_Bot"
	body := []byte(`{"agent_id":"ag_Travel_Bot","action":"Issue_Refund","payload":{"amount":50.0}}`)
	// 5 minutes in the past
	headers := generateSignedHeaders(agentID, body, agentSharedSecret, -5*time.Minute, "stale-nonce-1")

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

func TestParameterGuardrails_DestructiveSQL(t *testing.T) {
	// Destructive SQL Injection attempt
	payload := map[string]interface{}{
		"query": "SELECT * FROM users; DROP TABLE accounts;--",
		"time":  "12:00:00",
	}

	passed, reason := checkParameterGuardrails("QUERY_DB", payload)
	if passed {
		t.Fatalf("Destructive SQL DDL DROP TABLE should have been blocked by Parameter Guardrails")
	}
	t.Logf("Successfully blocked destructive SQL: %s", reason)
}

func TestParameterGuardrails_ExceedRefundCeiling(t *testing.T) {
	// Exceeds $10,000 refund safety ceiling
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
	// Legitimate simulator traffic
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

