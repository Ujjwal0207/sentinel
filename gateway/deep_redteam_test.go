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
	"sync"
	"testing"
	"time"
)

// DeepRedTeamScenario tests the next-tier of subtle, systemic enterprise failure modes
type DeepRedTeamScenario struct {
	ID                string
	Category          string
	Name              string
	AgentID           string
	Action            string
	Payload           map[string]interface{}
	RawJSONOverride   string // For testing JSON duplicate key pollution
	ExpectedOutcome   string // What an enterprise CISO / Tier-1 Bank demands
	VulnerabilityNote string
}

func TestDeepRedTeamBenchmark(t *testing.T) {
	fmt.Println("\n========================================================================")
	fmt.Println("       SENTINEL DEEP RED-TEAM AUDIT: SYSTEMIC ENTERPRISE ATTACKS        ")
	fmt.Println("========================================================================")
	fmt.Println("Auditing Tier-1 Enterprise vulnerabilities: Rebinding, Homoglyphs, HPP...")

	scenarios := []DeepRedTeamScenario{
		{
			ID:                "RED-01",
			Category:          "SSRF DNS Rebinding",
			Name:              "Domain-Cloaked AWS Metadata (DNS Rebinding)",
			AgentID:           "ag_Travel_Bot",
			Action:            "TRANSFER",
			Payload:           map[string]interface{}{"webhook": "http://rebind.attacker-infra.internal/latest/meta-data/"},
			ExpectedOutcome:   "BLOCK (DNS resolution checks link-local / private IP before dial)",
			VulnerabilityNote: "Hostname Check Blindness: Sentinel only inspects IP literals; domain names bypass SSRF checks completely.",
		},
		{
			ID:                "RED-02",
			Category:          "Unicode Normalization",
			Name:              "Full-Width Unicode SQL Injection (ＵＰＤＡＴＥ)",
			AgentID:           "ag_Travel_Bot",
			Action:            "TRANSFER",
			Payload:           map[string]interface{}{"query": "ＵＰＤＡＴＥ accounts ＳＥＴ balance = 999999 WHERE id = 1"},
			ExpectedOutcome:   "BLOCK (NFKC Unicode normalization reveals UPDATE statement)",
			VulnerabilityNote: "Unicode Blindness: Regex only matches ASCII characters; full-width homoglyphs bypass DML detection.",
		},
		{
			ID:                "RED-03",
			Category:          "Unicode Normalization",
			Name:              "Zero-Width Space SQL Evasion (U\\u200BPDATE)",
			AgentID:           "ag_Travel_Bot",
			Action:            "TRANSFER",
			Payload:           map[string]interface{}{"query": "U\u200BPDATE accounts SET balance = 999999 WHERE id = 1"},
			ExpectedOutcome:   "BLOCK (Zero-width stripped before regex inspection)",
			VulnerabilityNote: "Zero-Width Evasion: Hidden bytes inside SQL keywords bypass exact substring matching.",
		},
		{
			ID:                "RED-04",
			Category:          "HTTP Parameter Pollution",
			Name:              "Duplicate Key Parsing Mismatch (HPP)",
			AgentID:           "ag_Travel_Bot",
			Action:            "TRANSFER",
			RawJSONOverride:   `{"agent_id":"ag_Travel_Bot","action":"TRANSFER","payload":{"transfer_amount":1000000,"transfer_amount":50}}`,
			ExpectedOutcome:   "BLOCK / REJECT (Strict RFC 8259 rejection of duplicate keys)",
			VulnerabilityNote: "JSON Ambiguity: Go overwrites with last key ($50), while downstream banking API may take the first ($1,000,000).",
		},
		{
			ID:                "RED-05",
			Category:          "Financial Precision",
			Name:              "Sub-Cent Precision & Float Rounding Salami Slicing",
			AgentID:           "ag_Travel_Bot",
			Action:            "Issue_Refund",
			Payload:           map[string]interface{}{"amount": 9999.999999999999},
			ExpectedOutcome:   "BLOCK / NORMALIZE (Fixed-point integer cents / Decimal precision)",
			VulnerabilityNote: "Float64 Imprecision: Binary floating point causes rounding errors near boundary limits.",
		},
	}

	mockEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"decision": "ALLOW",
			"status":   "ALLOW",
			"reason":   "Mock engine pass",
		})
	}))
	defer mockEngine.Close()

	t.Setenv("SENTINEL_CASE_LAW_URL", mockEngine.URL)
	agentSharedSecret = "sentinel_test_secret_for_reality_check_32bytes"
	strictAuthEnabled = false

	vulnerabilitiesFound := 0

	for _, s := range scenarios {
		var rawJSON []byte
		if s.RawJSONOverride != "" {
			rawJSON = []byte(s.RawJSONOverride)
		} else {
			reqBody := AgentRequest{
				AgentID: s.AgentID,
				Action:  s.Action,
				Payload: s.Payload,
			}
			rawJSON, _ = json.Marshal(reqBody)
		}

		req := httptest.NewRequest(http.MethodPost, "/enforce", bytes.NewBuffer(rawJSON))
		req.Header.Set("Content-Type", "application/json")

		ts := time.Now().UTC().Format(time.RFC3339)
		nonce := fmt.Sprintf("deep_nonce_%s_%d", s.ID, time.Now().UnixNano())
		bodyHash := sha256.Sum256(rawJSON)
		canonical := fmt.Sprintf("%s|%s|%s|%s", s.AgentID, ts, nonce, hex.EncodeToString(bodyHash[:]))
		mac := hmac.New(sha256.New, []byte(agentSharedSecret))
		mac.Write([]byte(canonical))
		sig := hex.EncodeToString(mac.Sum(nil))

		req.Header.Set("X-Sentinel-Agent-ID", s.AgentID)
		req.Header.Set("X-Sentinel-Timestamp", ts)
		req.Header.Set("X-Sentinel-Nonce", nonce)
		req.Header.Set("X-Sentinel-Signature", sig)

		rr := httptest.NewRecorder()
		enforceHandler(rr, req)

		observedStatus := rr.Code

		isVulnerable := (observedStatus == http.StatusOK)
		if isVulnerable {
			vulnerabilitiesFound++
			fmt.Printf("🔴 [VULNERABLE] %-8s | %-28s | Sentinel: %d (ALLOWED) | Expected: %s\n",
				s.ID, s.Name, observedStatus, s.ExpectedOutcome)
			fmt.Printf("    └── Exploit Vector: %s\n", s.VulnerabilityNote)
		} else {
			fmt.Printf("🟢 [DEFENDED]   %-8s | %-28s | Sentinel: %d | Expected: %s\n",
				s.ID, s.Name, observedStatus, s.ExpectedOutcome)
		}
	}

	// CONCURRENCY STRESS BENCHMARK: Test Lock Contention under 500 concurrent goroutines
	fmt.Println("\n--- CONCURRENCY HEAD-OF-LINE CONTENTION TEST ---")
	concurrency := 200
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			cPayload := map[string]interface{}{"amount": 10.0}
			cJSON, _ := json.Marshal(AgentRequest{AgentID: "ag_Travel_Bot", Action: "Issue_Refund", Payload: cPayload})
			cReq := httptest.NewRequest(http.MethodPost, "/enforce", bytes.NewBuffer(cJSON))
			cReq.Header.Set("Content-Type", "application/json")
			cNonce := fmt.Sprintf("conc_nonce_%d_%d", workerID, time.Now().UnixNano())
			cTs := time.Now().UTC().Format(time.RFC3339)
			cHash := sha256.Sum256(cJSON)
			cCanon := fmt.Sprintf("ag_Travel_Bot|%s|%s|%s", cTs, cNonce, hex.EncodeToString(cHash[:]))
			cMac := hmac.New(sha256.New, []byte(agentSharedSecret))
			cMac.Write([]byte(cCanon))
			cReq.Header.Set("X-Sentinel-Agent-ID", "ag_Travel_Bot")
			cReq.Header.Set("X-Sentinel-Timestamp", cTs)
			cReq.Header.Set("X-Sentinel-Nonce", cNonce)
			cReq.Header.Set("X-Sentinel-Signature", hex.EncodeToString(cMac.Sum(nil)))
			cRR := httptest.NewRecorder()
			enforceHandler(cRR, cReq)
		}(i)
	}
	wg.Wait()
	duration := time.Since(start)
	avgPerReq := duration / time.Duration(concurrency)
	fmt.Printf("Executed %d concurrent agent requests in %v (Average: %v/req)\n", concurrency, duration, avgPerReq)

	fmt.Println("\n------------------------------------------------------------------------")
	fmt.Printf("DEEP RED-TEAM SUMMARY: %d / %d Next-Tier Attack Vectors Bypassed Sentinel\n",
		vulnerabilitiesFound, len(scenarios))
	fmt.Println("------------------------------------------------------------------------")
}

