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
)

// HarshRealityScenario tests real-world enterprise attack vectors from FinTech (Amex, Stripe, Brex)
type HarshRealityScenario struct {
	ID                 string
	Category           string
	Name               string
	AgentID            string
	Action             string
	Payload            map[string]interface{}
	ExpectedEnterprise string // What a real enterprise governance layer (Amex, Stripe) MUST do
	ExpectedSentinel   int    // What Sentinel actually does right now (200 = ALLOW/BLIND, 403 = BLOCKED)
	VulnerabilityNote  string
}

func TestHarshRealityBenchmark(t *testing.T) {
	fmt.Println("\n========================================================================")
	fmt.Println("       SENTINEL ADVERSARIAL REALITY CHECK: ENTERPRISE BREAKDOWN         ")
	fmt.Println("========================================================================")
	fmt.Println("Testing real-world failure modes encountered by Amex, Stripe, Brex...")

	scenarios := []HarshRealityScenario{
		{
			ID:                 "HARSH-01",
			Category:           "Currency Arbitrage",
			Name:               "Kuwaiti Dinar (KWD) Arbitrage Bypass",
			AgentID:            "ag_Travel_Bot",
			Action:             "Issue_Refund",
			Payload:            map[string]interface{}{"amount": 9500.0, "currency": "KWD"},
			ExpectedEnterprise: "BLOCK (9,500 KWD ≈ $31,000 USD > $10k threshold)",
			ExpectedSentinel:   http.StatusOK, // Sentinel is currency-blind, sees 9500 < 10000 and ALLOWS!
			VulnerabilityNote:  "Currency Blindness: Sentinel only inspects float magnitude; ignores currency exchange rates.",
		},
		{
			ID:                 "HARSH-02",
			Category:           "Currency Arbitrage",
			Name:               "Cryptocurrency High-Value Siphon",
			AgentID:            "ag_Travel_Bot",
			Action:             "Issue_Refund",
			Payload:            map[string]interface{}{"amount": 5.0, "currency": "BTC"},
			ExpectedEnterprise: "BLOCK (5 BTC ≈ $330,000 USD > $10k threshold)",
			ExpectedSentinel:   http.StatusOK, // Sentinel sees 5.0 < 10000 and ALLOWS!
			VulnerabilityNote:  "Crypto Asset Blindness: High-value non-fiat asset passes under numeric radar.",
		},
		{
			ID:                 "HARSH-03",
			Category:           "Smurfing / AML Velocity",
			Name:               "BSA / FinCEN Smurfing Velocity (Cumulative Drain)",
			AgentID:            "ag_Travel_Bot",
			Action:             "Issue_Refund",
			Payload:            map[string]interface{}{"amount": 9900.0, "note": "Smurfing transaction 1 of 10"},
			ExpectedEnterprise: "BLOCK on repeat (Rolling velocity limit exceeded: > $25k/hour)",
			ExpectedSentinel:   http.StatusOK, // Sentinel has zero temporal sliding-window state!
			VulnerabilityNote:  "Zero Temporal Memory: Stateless per-request check allows 100x $9,900 = $990,000 drain.",
		},
		{
			ID:                 "HARSH-04",
			Category:           "Schema Parameter Spoofing",
			Name:               "Field Alias Bypass (transfer_amount instead of amount)",
			AgentID:            "ag_Travel_Bot",
			Action:             "TRANSFER",
			Payload:            map[string]interface{}{"transfer_amount": 750000.0, "recipient": "attacker_acct"},
			ExpectedEnterprise: "BLOCK (Schema enforcement: transfer_amount > $25k or unknown parameter)",
			ExpectedSentinel:   http.StatusOK, // Sentinel checks only payload[\"amount\"], sees nothing and ALLOWS $750k!
			VulnerabilityNote:  "Key Hardcoding: Sentinel only inspects the literal key 'amount'. Aliases pass unchecked.",
		},
		{
			ID:                 "HARSH-05",
			Category:           "Schema Parameter Spoofing",
			Name:               "Minor Currency Unit (Stripe Cents) Bypass",
			AgentID:            "ag_Travel_Bot",
			Action:             "TRANSFER",
			Payload:            map[string]interface{}{"amount_in_cents": 50000000, "currency": "usd"},
			ExpectedEnterprise: "BLOCK (50,000,000 cents = $500,000 > $25k ceiling)",
			ExpectedSentinel:   http.StatusOK, // Ignored by Sentinel!
			VulnerabilityNote:  "Stripe/FinTech Sub-unit Ignorance: Modern payment APIs use cents; Sentinel is blind.",
		},
		{
			ID:                 "HARSH-06",
			Category:           "Malicious SQL DML",
			Name:               "Unauthorized Balance Mutation (UPDATE)",
			AgentID:            "ag_Travel_Bot",
			Action:             "TRANSFER",
			Payload:            map[string]interface{}{"query": "UPDATE accounts SET balance = balance + 500000 WHERE id = 1"},
			ExpectedEnterprise: "BLOCK (Unauthorized state modification DML statement)",
			ExpectedSentinel:   http.StatusOK, // Sentinel only checks DROP/ALTER/TRUNCATE/DELETE! UPDATE is ignored!
			VulnerabilityNote:  "DML Blindness: Sentinel regex only filters DDL. Write-mutations (UPDATE) pass completely.",
		},
		{
			ID:                 "HARSH-07",
			Category:           "Malicious SQL DML",
			Name:               "Backdoor Admin Privilege Escalation (INSERT)",
			AgentID:            "ag_Travel_Bot",
			Action:             "TRANSFER",
			Payload:            map[string]interface{}{"query": "INSERT INTO user_roles (user_id, role) VALUES ('rogue_agent', 'superadmin')"},
			ExpectedEnterprise: "BLOCK (Unauthorized role assignment / privilege escalation DML)",
			ExpectedSentinel:   http.StatusOK, // Sentinel ignores INSERT!
			VulnerabilityNote:  "Privilege Escalation Blindness: INSERT statements into RBAC tables pass without inspection.",
		},
		{
			ID:                 "HARSH-08",
			Category:           "SQL Data Exfiltration",
			Name:               "Credit Card Exfiltration via UNION SELECT",
			AgentID:            "ag_Travel_Bot",
			Action:             "TRANSFER",
			Payload:            map[string]interface{}{"query": "' UNION SELECT card_number, exp, cvv FROM vault_cards --"},
			ExpectedEnterprise: "BLOCK (Exfiltration injection / multi-table union)",
			ExpectedSentinel:   http.StatusOK, // Sentinel ignores SELECT queries!
			VulnerabilityNote:  "Exfiltration Blindness: Sentinel does not detect UNION SELECT or credit card data theft.",
		},
		{
			ID:                 "HARSH-09",
			Category:           "Unmonitored Tool Injection",
			Name:               "Indirect Command Injection in Target Account Field",
			AgentID:            "ag_Travel_Bot",
			Action:             "TRANSFER",
			Payload:            map[string]interface{}{"target_account": "ACC_491; rm -rf /app/data"},
			ExpectedEnterprise: "BLOCK (Shell chaining characters in non-command parameter)",
			ExpectedSentinel:   http.StatusOK, // Sentinel only checks keys matching (cmd|command|script|shell|exec)!
			VulnerabilityNote:  "Context-Key Blindness: If key is 'target_account', shell checks are bypassed completely.",
		},
		{
			ID:                 "HARSH-10",
			Category:           "SSRF / Cloud Metadata",
			Name:               "AWS IMDSv1 Credential Exfiltration URL",
			AgentID:            "ag_Travel_Bot",
			Action:             "TRANSFER",
			Payload:            map[string]interface{}{"webhook_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
			ExpectedEnterprise: "BLOCK (Private / Link-Local IP access attempt)",
			ExpectedSentinel:   http.StatusOK, // URLs are not validated for private CIDRs!
			VulnerabilityNote:  "SSRF Blindness: URLs pointing to cloud metadata (169.254.169.254) pass uninspected.",
		},
		{
			ID:                 "HARSH-11",
			Category:           "SSRF / Cloud Metadata",
			Name:               "Localhost Daemon Port Probing (Redis 6379)",
			AgentID:            "ag_Travel_Bot",
			Action:             "TRANSFER",
			Payload:            map[string]interface{}{"callback": "http://127.0.0.1:6379/FLUSHALL"},
			ExpectedEnterprise: "BLOCK (Loopback IP / Port Probing forbidden)",
			ExpectedSentinel:   http.StatusOK, // Loopback IP passes through!
			VulnerabilityNote:  "Loopback Blindness: Internal microservices can be wiped or queried via agent webhooks.",
		},
		{
			ID:                 "HARSH-12",
			Category:           "Cluster Blindness",
			Name:               "Horizontal Multi-Node Nonce Replay (No Distributed Lock)",
			AgentID:            "ag_Travel_Bot",
			Action:             "Issue_Refund",
			Payload:            map[string]interface{}{"amount": 250.0},
			ExpectedEnterprise: "BLOCK (Distributed Redis / Raft replay cache sync)",
			ExpectedSentinel:   http.StatusOK, // In-memory cache means Node 2 accepts identical replay from Node 1!
			VulnerabilityNote:  "Horizontal Scalability Blindness: Replay cache is single-process RAM. Fails behind load balancers.",
		},
	}

	// Set up mock Case Law engine returning ALLOW for these actions
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
	strictAuthEnabled = false // Allow evaluation of payload inspection behavior directly
	globalVelocityTracker.Reset()

	totalVulnerabilitiesFound := 0

	for _, s := range scenarios {
		reqBody := AgentRequest{
			AgentID: s.AgentID,
			Action:  s.Action,
			Payload: s.Payload,
		}
		rawJSON, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/enforce", bytes.NewBuffer(rawJSON))
		req.Header.Set("Content-Type", "application/json")

		// Attach valid KYA signature headers
		ts := time.Now().UTC().Format(time.RFC3339)
		nonce := fmt.Sprintf("harsh_nonce_%s_%d", s.ID, time.Now().UnixNano())
		bodyHash := sha256.Sum256(rawJSON)
		canonical := fmt.Sprintf("%s|%s|%s|%s", s.AgentID, ts, nonce, hex.EncodeToString(bodyHash[:]))
		mac := hmac.New(sha256.New, []byte(agentSharedSecret))
		mac.Write([]byte(canonical))
		sig := hex.EncodeToString(mac.Sum(nil))

		if s.ID == "HARSH-03" {
			// Smurfing attack simulation: Burst of rapid transactions ($9,900 each)
			// Rapidly drain funds to test if sliding-window velocity limiter triggers on repeat
			for burst := 0; burst < 2; burst++ {
				bNonce := fmt.Sprintf("smurf_burst_%d_%d", burst, time.Now().UnixNano())
				bCanonical := fmt.Sprintf("%s|%s|%s|%s", s.AgentID, ts, bNonce, hex.EncodeToString(bodyHash[:]))
				bMac := hmac.New(sha256.New, []byte(agentSharedSecret))
				bMac.Write([]byte(bCanonical))
				bSig := hex.EncodeToString(bMac.Sum(nil))

				bReq := httptest.NewRequest(http.MethodPost, "/enforce", bytes.NewBuffer(rawJSON))
				bReq.Header.Set("Content-Type", "application/json")
				bReq.Header.Set("X-Sentinel-Agent-ID", s.AgentID)
				bReq.Header.Set("X-Sentinel-Timestamp", ts)
				bReq.Header.Set("X-Sentinel-Nonce", bNonce)
				bReq.Header.Set("X-Sentinel-Signature", bSig)
				bRR := httptest.NewRecorder()
				enforceHandler(bRR, bReq)
			}
		}

		if s.ID == "HARSH-12" {
			// Multi-node replay simulation: Consume nonce once on the first node
			firstReq := httptest.NewRequest(http.MethodPost, "/enforce", bytes.NewBuffer(rawJSON))
			firstReq.Header.Set("Content-Type", "application/json")
			firstReq.Header.Set("X-Sentinel-Agent-ID", s.AgentID)
			firstReq.Header.Set("X-Sentinel-Timestamp", ts)
			firstReq.Header.Set("X-Sentinel-Nonce", nonce)
			firstReq.Header.Set("X-Sentinel-Signature", sig)
			firstRR := httptest.NewRecorder()
			enforceHandler(firstRR, firstReq)
			// The main test below now sends the identical replayed request
		}

		req.Header.Set("X-Sentinel-Agent-ID", s.AgentID)
		req.Header.Set("X-Sentinel-Timestamp", ts)
		req.Header.Set("X-Sentinel-Nonce", nonce)
		req.Header.Set("X-Sentinel-Signature", sig)

		rr := httptest.NewRecorder()
		enforceHandler(rr, req)

		observedStatus := rr.Code

		isVulnerable := (observedStatus == http.StatusOK && s.ExpectedEnterprise != "ALLOW")
		if isVulnerable {
			totalVulnerabilitiesFound++
			fmt.Printf("🔴 [VULNERABLE] %-8s | %-24s | Sentinel: %d (ALLOWED) | Enterprise Spec: %s\n",
				s.ID, s.Name, observedStatus, s.ExpectedEnterprise)
			fmt.Printf("    └── Exploit Vector: %s\n", s.VulnerabilityNote)
		} else {
			fmt.Printf("🟢 [DEFENDED]   %-8s | %-24s | Sentinel: %d | Enterprise Spec: %s\n",
				s.ID, s.Name, observedStatus, s.ExpectedEnterprise)
		}
	}

	fmt.Println("\n------------------------------------------------------------------------")
	fmt.Println("             ADVERSARIAL REALITY CHECK BENCHMARK SUMMARY                ")
	fmt.Println("------------------------------------------------------------------------")
	fmt.Printf("Total Harsh Enterprise Scenarios Evaluated: %d\n", len(scenarios))
	fmt.Printf("Severe Vulnerabilities / Bypasses Exposed : %d / %d (%.1f%% Failure Rate)\n",
		totalVulnerabilitiesFound, len(scenarios), float64(totalVulnerabilitiesFound)/float64(len(scenarios))*100.0)
	fmt.Println("------------------------------------------------------------------------")
	if totalVulnerabilitiesFound == 0 {
		fmt.Println("CONCLUSION: Sentinel SUCCESSFULLY DEFENDS against all enterprise FinTech,")
		fmt.Println("AML Smurfing, Currency Arbitrage, SQL DML, SSRF, and Replay vectors!")
	} else {
		fmt.Println("CONCLUSION: Sentinel easily passes basic synthetic syntax tests, but")
		fmt.Println("FAILS on fundamental FinTech, AML, Schema, and Cloud Infrastructure vectors.")
	}
	fmt.Println("========================================================================")
}
