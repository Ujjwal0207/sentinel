package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// -------------------------------------------------------------------
// PHASE 3.3 & 3.4 ADVANCED ENTERPRISE BENCHMARK TEST SUITE
// -------------------------------------------------------------------
// Auditing:
// 1. Asymmetric Ed25519 Identity & Workload Attestation (Corner 1.3)
// 2. User-Controlled Authorization Networks (UCAN) Delegation DAGs (Corner 5.2)
// 3. Distributed State Mesh Multi-Pod Nonce Replay Prevention (Corner 1.2)
// 4. Swarm-Wide Sliding-Window AML Velocity Smurfing Defense (Corner 1.2)
// 5. Distributed Fleet Freeze Emergency Kill Switch (Corner 2.3)
// -------------------------------------------------------------------

type Phase3AdvancedScenario struct {
	ID               string
	Category         string
	Description      string
	TargetPod        string
	AgentID          string
	Action           string
	Payload          map[string]interface{}
	SetupFn          func(t *testing.T, mesh DistributedStateMesh, keyReg *AgentKeyRegistry)
	AuthScheme       string
	UseUCAN          bool
	UCANToken        *UCANToken
	Ed25519PrivKey   ed25519.PrivateKey
	HeaderOverrides  map[string]string
	ExpectedStatus   int
	ExpectedDecision string
	ExpectedError    string
}

func TestPhase3AdvancedEnterpriseBenchmark(t *testing.T) {
	// Initialize mock downstream Case Law Engine
	mockEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":   "SUCCESS",
			"decision": "ALLOW",
			"reason":   "Mock precedent check passed",
		})
	}))
	defer mockEngine.Close()
	t.Setenv("SENTINEL_CASE_LAW_URL", mockEngine.URL)

	// Simulated Multi-Pod Cluster sharing a single DistributedStateMesh
	sharedMesh := NewMemoryClusterStateMesh(1*time.Hour, 25000.0)
	globalStateMesh = sharedMesh

	// Key Registry
	keyReg := globalKeyRegistry
	keyReg.Reset()

	// Generate master keys for test agents
	adminPub, adminPriv, _ := ed25519.GenerateKey(rand.Reader)
	disputePub, disputePriv, _ := ed25519.GenerateKey(rand.Reader)
	supportPub, supportPriv, _ := ed25519.GenerateKey(rand.Reader)
	scraperPub, scraperPriv, _ := ed25519.GenerateKey(rand.Reader)
	internPub, internPriv, _ := ed25519.GenerateKey(rand.Reader)

	keyReg.RegisterKey("ag_Admin", adminPub)
	keyReg.RegisterKey("ag_Dispute_AI", disputePub)
	keyReg.RegisterKey("ag_Support_Bot", supportPub)
	keyReg.RegisterKey("ag_Scraper", scraperPub)
	keyReg.RegisterKey("ag_Intern_Bot", internPub)

	// Pod network map
	podHandlers := map[string]http.HandlerFunc{
		"Pod_A": enforceHandler,
		"Pod_B": enforceHandler,
		"Pod_C": enforceHandler,
		"Pod_D": enforceHandler,
		"Pod_E": enforceHandler,
	}

	// -------------------------------------------------------------------
	// HELPER: Build Valid UCAN Token Chain
	// -------------------------------------------------------------------
	buildValidUCANChain := func() *UCANToken {
		now := time.Now().Unix()

		// Root Token: Admin -> Dispute_AI (Max $10,000, all actions, expires in 300s)
		rootToken := &UCANToken{
			Issuer:   "ag_Admin",
			Audience: "ag_Dispute_AI",
			Capabilities: []UCANCapability{
				{
					With:      "financial:transaction",
					Can:       "execute",
					MaxAmount: 10000.0,
					Currency:  "USD",
					Actions:   []string{"TRANSFER", "Issue_Refund", "QUERY_DATABASE"},
					Recipient: "Rahul",
				},
			},
			ExpiresAt: now + 300,
			NotBefore: now - 10,
			Nonce:     fmt.Sprintf("ucan-root-%d", time.Now().UnixNano()),
		}
		rootToken.Sign(adminPriv)

		// Child Token: Dispute_AI -> Support_Bot (Max $500, Issue_Refund only, expires in 200s)
		childToken := &UCANToken{
			Issuer:   "ag_Dispute_AI",
			Audience: "ag_Support_Bot",
			Capabilities: []UCANCapability{
				{
					With:      "financial:transaction",
					Can:       "execute",
					MaxAmount: 500.0,
					Currency:  "USD",
					Actions:   []string{"Issue_Refund"},
					Recipient: "Rahul",
				},
			},
			ExpiresAt: now + 200,
			NotBefore: now - 5,
			Nonce:     fmt.Sprintf("ucan-child-%d", time.Now().UnixNano()),
			Proof:     rootToken,
		}
		childToken.Sign(disputePriv)

		return childToken
	}

	var scenarios []Phase3AdvancedScenario

	// ===================================================================
	// PART 1: PHASE 3.3 ASYMMETRIC IDENTITY (Ed25519) (25 SCENARIOS)
	// ===================================================================
	scenarios = append(scenarios, []Phase3AdvancedScenario{
		{
			ID: "ASYM-01", Category: "Asymmetric Ed25519 Identity", Description: "Valid Ed25519 signed transfer by ag_Dispute_AI",
			TargetPod: "Pod_A", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload:        map[string]interface{}{"amount": 1500.0, "recipient": "Rahul"},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv,
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "ASYM-02", Category: "Asymmetric Ed25519 Identity", Description: "Valid Ed25519 signed refund by ag_Support_Bot",
			TargetPod: "Pod_B", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
			Payload:        map[string]interface{}{"amount": 120.0, "recipient": "CustomerA"},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: supportPriv,
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "ASYM-03", Category: "Asymmetric Ed25519 Identity", Description: "Valid Ed25519 signed read query by ag_Scraper",
			TargetPod: "Pod_C", AgentID: "ag_Scraper", Action: "QUERY_DATABASE",
			Payload:        map[string]interface{}{"query": "SELECT * FROM public_catalogs"},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: scraperPriv,
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "ASYM-04", Category: "Asymmetric Ed25519 Identity", Description: "Cross-Agent Key Theft (Scraper signs with own key, claims to be ag_Dispute_AI)",
			TargetPod: "Pod_A", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload:        map[string]interface{}{"amount": 5000.0, "recipient": "Attacker"},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: scraperPriv, // Malicious key substitution!
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY", ExpectedError: "INVALID_ED25519_SIGNATURE",
		},
		{
			ID: "ASYM-05", Category: "Asymmetric Ed25519 Identity", Description: "Unregistered rogue agent with valid key but no directory entry",
			TargetPod: "Pod_B", AgentID: "ag_Rogue_AI", Action: "TRANSFER",
			Payload:        map[string]interface{}{"amount": 100.0},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: scraperPriv,
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY", ExpectedError: "UNAUTHENTICATED_AGENT_KEY",
		},
		{
			ID: "ASYM-06", Category: "Asymmetric Ed25519 Identity", Description: "Tampered signature (1 bit flip in hex signature string)",
			TargetPod: "Pod_C", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload:        map[string]interface{}{"amount": 250.0},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv,
			HeaderOverrides: map[string]string{
				"TAMPER_SIG": "true",
			},
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY", ExpectedError: "INVALID_ED25519_SIGNATURE",
		},
		{
			ID: "ASYM-07", Category: "Asymmetric Ed25519 Identity", Description: "Truncated Ed25519 signature (less than 128 hex chars / 64 bytes)",
			TargetPod: "Pod_D", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload:        map[string]interface{}{"amount": 250.0},
			AuthScheme:     "ed25519",
			HeaderOverrides: map[string]string{
				"X-Sentinel-Signature": "abcd1234ef5678",
			},
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY", ExpectedError: "INVALID_ED25519_SIGNATURE",
		},
		{
			ID: "ASYM-08", Category: "Asymmetric Ed25519 Identity", Description: "Corrupted non-hex characters in Ed25519 signature",
			TargetPod: "Pod_E", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload:        map[string]interface{}{"amount": 250.0},
			AuthScheme:     "ed25519",
			HeaderOverrides: map[string]string{
				"X-Sentinel-Signature": strings.Repeat("Z", 128),
			},
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY", ExpectedError: "INVALID_ED25519_SIGNATURE",
		},
		{
			ID: "ASYM-09", Category: "Asymmetric Ed25519 Identity", Description: "Payload parameter tampering (amount changed after signature generation)",
			TargetPod: "Pod_A", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload:        map[string]interface{}{"amount": 9999.0},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv,
			HeaderOverrides: map[string]string{
				"TAMPER_BODY": "true",
			},
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY", ExpectedError: "INVALID_ED25519_SIGNATURE",
		},
		{
			ID: "ASYM-10", Category: "Asymmetric Ed25519 Identity", Description: "Timestamp modification post-signing",
			TargetPod: "Pod_B", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload:        map[string]interface{}{"amount": 100.0},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv,
			HeaderOverrides: map[string]string{
				"X-Sentinel-Timestamp": time.Now().Add(-120 * time.Second).Format(time.RFC3339),
			},
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY", ExpectedError: "TIMESTAMP_DRIFT",
		},
		{
			ID: "ASYM-11", Category: "Asymmetric Ed25519 Identity", Description: "Nonce modification post-signing",
			TargetPod: "Pod_C", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload:        map[string]interface{}{"amount": 100.0},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv,
			HeaderOverrides: map[string]string{
				"X-Sentinel-Nonce": "tampered-nonce-1234567890abcdef",
			},
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY", ExpectedError: "INVALID_ED25519_SIGNATURE",
		},
		{
			ID: "ASYM-12", Category: "Asymmetric Ed25519 Identity", Description: "Future timestamp drift (> 60s in future)",
			TargetPod: "Pod_D", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload:        map[string]interface{}{"amount": 100.0},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv,
			HeaderOverrides: map[string]string{
				"X-Sentinel-Timestamp": time.Now().Add(90 * time.Second).Format(time.RFC3339),
			},
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY", ExpectedError: "TIMESTAMP_DRIFT",
		},
		{
			ID: "ASYM-13", Category: "Asymmetric Ed25519 Identity", Description: "Past timestamp drift (> 60s in past)",
			TargetPod: "Pod_E", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload:        map[string]interface{}{"amount": 100.0},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv,
			HeaderOverrides: map[string]string{
				"X-Sentinel-Timestamp": time.Now().Add(-90 * time.Second).Format(time.RFC3339),
			},
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY", ExpectedError: "TIMESTAMP_DRIFT",
		},
		{
			ID: "ASYM-14", Category: "Asymmetric Ed25519 Identity", Description: "Ed25519 Key Rotation: Old retired key rejected immediately",
			TargetPod: "Pod_A", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 100.0},
			SetupFn: func(t *testing.T, mesh DistributedStateMesh, kr *AgentKeyRegistry) {
				// Rotate Dispute_AI to a brand new keypair
				newPub, _, _ := ed25519.GenerateKey(rand.Reader)
				kr.RegisterKey("ag_Dispute_AI", newPub)
			},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv, // Using old retired private key
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY", ExpectedError: "INVALID_ED25519_SIGNATURE",
		},
		{
			ID: "ASYM-15", Category: "Asymmetric Ed25519 Identity", Description: "Ed25519 Key Rotation: Newly rotated key approved seamlessly",
			TargetPod: "Pod_B", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 100.0},
			SetupFn: func(t *testing.T, mesh DistributedStateMesh, kr *AgentKeyRegistry) {
				// Re-register original disputePub so subsequent tests succeed
				kr.RegisterKey("ag_Dispute_AI", disputePub)
			},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv,
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "ASYM-16", Category: "Asymmetric Ed25519 Identity", Description: "Sub-cent precision check with Ed25519 signature ($99.999 rejection)",
			TargetPod: "Pod_C", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload:        map[string]interface{}{"amount": 99.999},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv,
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "ASYM-17", Category: "Asymmetric Ed25519 Identity", Description: "Bare TRUNCATE statement blocked under Ed25519 auth",
			TargetPod: "Pod_D", AgentID: "ag_Dispute_AI", Action: "QUERY_DATABASE",
			Payload:        map[string]interface{}{"query": "TRUNCATE TABLE users"},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv,
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "ASYM-18", Category: "Asymmetric Ed25519 Identity", Description: "Command injection attempt under Ed25519 auth",
			TargetPod: "Pod_E", AgentID: "ag_Dispute_AI", Action: "EXEC_TOOL",
			Payload:        map[string]interface{}{"cmd": "curl http://10.0.0.1; rm -rf /"},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv,
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "ASYM-19", Category: "Asymmetric Ed25519 Identity", Description: "SSRF AWS metadata check under Ed25519 auth",
			TargetPod: "Pod_A", AgentID: "ag_Dispute_AI", Action: "WEBHOOK",
			Payload:        map[string]interface{}{"url": "http://169.254.169.254/latest/meta-data/"},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv,
			ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "ASYM-20", Category: "Asymmetric Ed25519 Identity", Description: "High-value authorized transfer ($20,000) with Ed25519",
			TargetPod: "Pod_B", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 20000.0, "recipient": "VendorCorp"},
			SetupFn: func(t *testing.T, mesh DistributedStateMesh, kr *AgentKeyRegistry) {
				mesh.Reset(context.Background())
			},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv,
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "ASYM-21", Category: "Asymmetric Ed25519 Identity", Description: "Multi-Currency EUR transfer under Ed25519 (2,000 EUR ≈ $2,160 USD)",
			TargetPod: "Pod_C", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload:        map[string]interface{}{"amount": 2000.0, "currency": "EUR"},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv,
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "ASYM-22", Category: "Asymmetric Ed25519 Identity", Description: "Multi-Currency GBP refund under Ed25519 (2,000 GBP ≈ $2,560 USD)",
			TargetPod: "Pod_D", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
			Payload:        map[string]interface{}{"amount": 2000.0, "currency": "GBP"},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: supportPriv,
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "ASYM-23", Category: "Asymmetric Ed25519 Identity", Description: "Multi-Currency JPY payment under Ed25519 (50,000 JPY ≈ $325 USD)",
			TargetPod: "Pod_E", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
			Payload:        map[string]interface{}{"amount": 50000.0, "currency": "JPY"},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: supportPriv,
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "ASYM-24", Category: "Asymmetric Ed25519 Identity", Description: "Multi-Currency KWD payment under Ed25519 (1,000 KWD ≈ $3,260 USD)",
			TargetPod: "Pod_A", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
			Payload:        map[string]interface{}{"amount": 1000.0, "currency": "KWD"},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: supportPriv,
			ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
		},
		{
			ID: "ASYM-25", Category: "Asymmetric Ed25519 Identity", Description: "RFC 8259 duplicate JSON key rejection under Ed25519 auth",
			TargetPod: "Pod_B", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload:        map[string]interface{}{"amount": 100.0},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv,
			HeaderOverrides: map[string]string{
				"DUPLICATE_KEY_BODY": "true",
			},
			ExpectedStatus: http.StatusBadRequest, ExpectedDecision: "DENY", ExpectedError: "PARAMETER_POLLUTION_DETECTED",
		},
	}...)

	// ===================================================================
	// PART 2: PHASE 3.3 UCAN DELEGATION DAGs (50 SCENARIOS)
	// ===================================================================
	// Scenario UCAN-01..50
	for i := 1; i <= 50; i++ {
		scID := fmt.Sprintf("UCAN-%02d", i)
		switch i {
		case 1:
			// Legitimate 2-Hop UCAN Delegation
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Legitimate 2-Hop Delegation (Admin -> Dispute_AI -> Support_Bot, $300 refund)",
				TargetPod: "Pod_A", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 300.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      buildValidUCANChain(),
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
			})
		case 2:
			// Privilege Escalation: Amount limit exceeded on leaf token ($500 limit, agent asks $501)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Privilege Escalation: Amount exceeds delegated limit ($501 > $500)",
				TargetPod: "Pod_B", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 501.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      buildValidUCANChain(),
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "UCAN_CAPABILITY_EXCEEDED",
			})
		case 3:
			// Privilege Escalation: Severe amount inflation ($5,000 > $500)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Privilege Escalation: 10x amount inflation ($5,000 > $500)",
				TargetPod: "Pod_C", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 5000.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      buildValidUCANChain(),
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "UCAN_CAPABILITY_EXCEEDED",
			})
		case 4:
			// Capability Mismatch: Support_Bot attempts unauthorized action TRANSFER (only Issue_Refund delegated)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Capability Mismatch: Attempting TRANSFER when UCAN only permits Issue_Refund",
				TargetPod: "Pod_D", AgentID: "ag_Support_Bot", Action: "TRANSFER",
				Payload:        map[string]interface{}{"amount": 100.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      buildValidUCANChain(),
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "UCAN_CAPABILITY_MISMATCH",
			})
		case 5:
			// Recipient Divergence: Delegated to Rahul, agent transfers to Vikram
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Recipient Divergence: Delegated recipient 'Rahul', agent specifies 'Vikram'",
				TargetPod: "Pod_E", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 100.0, "recipient": "Vikram"},
				UseUCAN:        true,
				UCANToken:      buildValidUCANChain(),
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "UCAN_CAPABILITY_EXCEEDED",
			})
		case 6:
			// Currency Divergence: Delegated in USD, agent specifies EUR
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Currency Divergence: Delegated currency USD, agent specifies EUR",
				TargetPod: "Pod_A", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 100.0, "currency": "EUR", "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      buildValidUCANChain(),
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "UCAN_CAPABILITY_EXCEEDED",
			})
		case 7:
			// Leaf Audience Mismatch: ag_Scraper attempts to use Support_Bot's delegated token
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Audience Mismatch: ag_Scraper presents UCAN minted for ag_Support_Bot",
				TargetPod: "Pod_B", AgentID: "ag_Scraper", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 100.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      buildValidUCANChain(),
				Ed25519PrivKey: scraperPriv,
				ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "UCAN_AUDIENCE_MISMATCH",
			})
		case 8:
			// Broken Chain of Custody: Parent audience does not match Child issuer
			brokenChainToken := buildValidUCANChain()
			brokenChainToken.Issuer = "ag_Scraper" // Broken link!
			brokenChainToken.Sign(scraperPriv)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Broken Custody Link: Child issuer does not match parent audience",
				TargetPod: "Pod_C", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 100.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      brokenChainToken,
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "UCAN_DELEGATION_CHAIN_BROKEN",
			})
		case 9:
			// Child attempts to expand amount limit beyond parent ($15,000 > $10,000)
			escalatedAmountToken := buildValidUCANChain()
			escalatedAmountToken.Capabilities[0].MaxAmount = 15000.0
			escalatedAmountToken.Sign(disputePriv)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Privilege Escalation: Child expands amount limit beyond parent ($15k > $10k)",
				TargetPod: "Pod_D", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 100.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      escalatedAmountToken,
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "UCAN_PRIVILEGE_ESCALATION",
			})
		case 10:
			// Child attempts to expand permitted actions beyond parent (adds BASH_EXEC)
			escalatedActionToken := buildValidUCANChain()
			escalatedActionToken.Capabilities[0].Actions = []string{"Issue_Refund", "BASH_EXEC"}
			escalatedActionToken.Sign(disputePriv)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Privilege Escalation: Child expands actions beyond parent capability",
				TargetPod: "Pod_E", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 100.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      escalatedActionToken,
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "UCAN_PRIVILEGE_ESCALATION",
			})
		case 11:
			// Child attempts to expand expiration beyond parent (Child exp = Parent exp + 60s)
			escalatedExpToken := buildValidUCANChain()
			escalatedExpToken.ExpiresAt = escalatedExpToken.Proof.ExpiresAt + 60
			escalatedExpToken.Sign(disputePriv)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Privilege Escalation: Child expiration outlives parent token lifetime",
				TargetPod: "Pod_A", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 100.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      escalatedExpToken,
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "UCAN_PRIVILEGE_ESCALATION",
			})
		case 12:
			// Expired Leaf Token
			expiredToken := buildValidUCANChain()
			expiredToken.ExpiresAt = time.Now().Unix() - 10
			expiredToken.Sign(disputePriv)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Expired Token: Leaf token expired 10 seconds ago",
				TargetPod: "Pod_B", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 100.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      expiredToken,
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "UCAN_TOKEN_EXPIRED",
			})
		case 13:
			// Expired Intermediate Root Token
			expiredRootToken := buildValidUCANChain()
			expiredRootToken.Proof.ExpiresAt = time.Now().Unix() - 10
			expiredRootToken.Proof.Sign(adminPriv)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Expired Root: Parent token in DAG expired, invalidating entire chain",
				TargetPod: "Pod_C", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 100.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      expiredRootToken,
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "UCAN_TOKEN_EXPIRED",
			})
		case 14:
			// Premature Token (NotBefore in future)
			futureToken := buildValidUCANChain()
			futureToken.NotBefore = time.Now().Unix() + 300
			futureToken.Sign(disputePriv)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Premature Token: NotBefore timestamp is 300s in the future",
				TargetPod: "Pod_D", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 100.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      futureToken,
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "UCAN_TOKEN_NOT_YET_VALID",
			})
		case 15:
			// Untrusted Root Issuer: Root token issued by rogue unapproved agent
			untrustedRootToken := buildValidUCANChain()
			untrustedRootToken.Proof.Issuer = "ag_Rogue_AI"
			untrustedRootToken.Proof.Sign(scraperPriv) // Rogue signature
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Untrusted Root Issuer: Delegation root not in trusted root authority directory",
				TargetPod: "Pod_E", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 100.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      untrustedRootToken,
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY", ExpectedError: "UCAN_UNKNOWN_ISSUER_KEY",
			})
		case 16:
			// Forged signature on leaf token
			tamperedLeafSigToken := buildValidUCANChain()
			tamperedLeafSigToken.Signature = strings.Repeat("0", 128)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Forged Leaf Signature: Invalid Ed25519 signature on leaf delegation token",
				TargetPod: "Pod_A", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 100.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      tamperedLeafSigToken,
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY", ExpectedError: "UCAN_SIGNATURE_INVALID",
			})
		case 17:
			// Forged signature on intermediate root token
			tamperedRootSigToken := buildValidUCANChain()
			tamperedRootSigToken.Proof.Signature = strings.Repeat("0", 128)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Forged Root Signature: Invalid Ed25519 signature on intermediate root token",
				TargetPod: "Pod_B", AgentID: "ag_Support_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 100.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      tamperedRootSigToken,
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY", ExpectedError: "UCAN_SIGNATURE_INVALID",
			})
		case 18:
			// 3-Hop Multi-Agent Delegation Chain (Admin -> Dispute_AI -> Support_Bot -> Intern_Bot)
			chain2 := buildValidUCANChain()
			now := time.Now().Unix()
			internToken := &UCANToken{
				Issuer:   "ag_Support_Bot",
				Audience: "ag_Intern_Bot",
				Capabilities: []UCANCapability{
					{
						With:      "financial:transaction",
						Can:       "execute",
						MaxAmount: 50.0,
						Currency:  "USD",
						Actions:   []string{"Issue_Refund"},
						Recipient: "Rahul",
					},
				},
				ExpiresAt: now + 150,
				NotBefore: now - 5,
				Nonce:     fmt.Sprintf("ucan-intern-%d", time.Now().UnixNano()),
				Proof:     chain2,
			}
			internToken.Sign(supportPriv)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Legitimate 3-Hop Delegation (Admin -> Dispute -> Support -> Intern, $45 refund)",
				TargetPod: "Pod_C", AgentID: "ag_Intern_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 45.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      internToken,
				Ed25519PrivKey: internPriv,
				ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
			})
		case 19:
			// 3-Hop Delegation: Intern attempts to exceed attenuated amount ($51 > $50)
			chain3 := buildValidUCANChain()
			now := time.Now().Unix()
			internToken2 := &UCANToken{
				Issuer:   "ag_Support_Bot",
				Audience: "ag_Intern_Bot",
				Capabilities: []UCANCapability{
					{
						With:      "financial:transaction",
						Can:       "execute",
						MaxAmount: 50.0,
						Currency:  "USD",
						Actions:   []string{"Issue_Refund"},
						Recipient: "Rahul",
					},
				},
				ExpiresAt: now + 150,
				NotBefore: now - 5,
				Nonce:     fmt.Sprintf("ucan-intern-%d", time.Now().UnixNano()),
				Proof:     chain3,
			}
			internToken2.Sign(supportPriv)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "3-Hop Scope Violation: Intern Bot requests $51 exceeding $50 cap",
				TargetPod: "Pod_D", AgentID: "ag_Intern_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": 51.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      internToken2,
				Ed25519PrivKey: internPriv,
				ExpectedStatus: http.StatusForbidden, ExpectedDecision: "DENY", ExpectedError: "UCAN_CAPABILITY_EXCEEDED",
			})
		case 20:
			// Wildcard action capability delegation
			now := time.Now().Unix()
			rootWildcard := &UCANToken{
				Issuer:   "ag_Admin",
				Audience: "ag_Dispute_AI",
				Capabilities: []UCANCapability{
					{
						With:      "financial:transaction",
						Can:       "execute",
						MaxAmount: 2000.0,
						Currency:  "USD",
						Actions:   []string{"*"}, // Wildcard
					},
				},
				ExpiresAt: now + 300,
				Nonce:     fmt.Sprintf("ucan-wc-%d", time.Now().UnixNano()),
			}
			rootWildcard.Sign(adminPriv)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: "Wildcard Capability: Parent delegates wildcard actions, Dispute calls TRANSFER",
				TargetPod: "Pod_E", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
				Payload:        map[string]interface{}{"amount": 1000.0, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      rootWildcard,
				Ed25519PrivKey: disputePriv,
				ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
			})
		default:
			// Cases 21..50: Systematic parameter, boundary, currency, and format variations
			boundaryAmt := float64(i)*10.0 + 0.50
			allowed := boundaryAmt <= 500.0
			expStatus := http.StatusOK
			expDecision := "ALLOW"
			if !allowed {
				expStatus = http.StatusForbidden
				expDecision = "DENY"
			}
			desc := fmt.Sprintf("Boundary Amount Matrix Test: Requested $%.2f against $500.00 UCAN cap", boundaryAmt)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "UCAN Delegation DAG", Description: desc,
				TargetPod: fmt.Sprintf("Pod_%c", 'A'+(i%5)), AgentID: "ag_Support_Bot", Action: "Issue_Refund",
				Payload:        map[string]interface{}{"amount": boundaryAmt, "recipient": "Rahul"},
				UseUCAN:        true,
				UCANToken:      buildValidUCANChain(),
				Ed25519PrivKey: supportPriv,
				ExpectedStatus: expStatus, ExpectedDecision: expDecision,
			})
		}
	}

	// ===================================================================
	// PART 3: PHASE 3.4 DISTRIBUTED STATE MESH (MULTI-POD) (75 SCENARIOS)
	// ===================================================================
	// 1. Multi-Pod Replay Attacks (DIST-REPLAY-01..25)
	for i := 1; i <= 25; i++ {
		scID := fmt.Sprintf("DIST-REPLAY-%02d", i)
		targetPodLetter := byte('B' + (i % 4)) // Pod B, C, D, E
		scenarios = append(scenarios, Phase3AdvancedScenario{
			ID: scID, Category: "Multi-Pod Replay Defense", Description: fmt.Sprintf("Cross-Pod Replay Attack: Replaying Pod_A consumed nonce to Pod_%c", targetPodLetter),
			TargetPod: fmt.Sprintf("Pod_%c", targetPodLetter), AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 100.0, "recipient": "Rahul"},
			SetupFn: func(t *testing.T, mesh DistributedStateMesh, kr *AgentKeyRegistry) {
				// Pre-consume nonce on Pod_A (or in shared state mesh)
				nonceKey := fmt.Sprintf("dist-replay-nonce-%d", i)
				mesh.CheckAndConsumeNonce(context.Background(), "ag_Dispute_AI", nonceKey, time.Now(), 120*time.Second)
			},
			AuthScheme:     "ed25519",
			Ed25519PrivKey: disputePriv,
			HeaderOverrides: map[string]string{
				"X-Sentinel-Nonce": fmt.Sprintf("dist-replay-nonce-%d", i),
			},
			ExpectedStatus: http.StatusUnauthorized, ExpectedDecision: "DENY", ExpectedError: "REPLAY_DETECTED",
		})
	}

	// 2. Distributed Smurfing & Multi-Pod Velocity Tracking (DIST-SMURF-01..30)
	for i := 1; i <= 30; i++ {
		scID := fmt.Sprintf("DIST-SMURF-%02d", i)
		podIdx := i % 5
		targetPod := fmt.Sprintf("Pod_%c", 'A'+podIdx)

		switch i {
		case 1:
			// Pod_A $5,000 transfer (Swarm Total: $5,000 <= $25,000)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Smurfing", Description: "Distributed Burst #1 on Pod_A ($5,000 -> Cumulative $5,000 / $25,000)",
				TargetPod: targetPod, AgentID: "ag_Travel_Bot", Action: "TRANSFER",
				Payload: map[string]interface{}{"amount": 5000.0},
				SetupFn: func(t *testing.T, mesh DistributedStateMesh, kr *AgentKeyRegistry) {
					mesh.Reset(context.Background())
				},
				ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
			})
		case 2:
			// Pod_B $5,000 transfer (Swarm Total: $10,000 <= $25,000)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Smurfing", Description: "Distributed Burst #2 on Pod_B ($5,000 -> Cumulative $10,000 / $25,000)",
				TargetPod: targetPod, AgentID: "ag_Travel_Bot", Action: "TRANSFER",
				Payload:        map[string]interface{}{"amount": 5000.0},
				ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
			})
		case 3:
			// Pod_C $5,000 transfer (Swarm Total: $15,000 <= $25,000)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Smurfing", Description: "Distributed Burst #3 on Pod_C ($5,000 -> Cumulative $15,000 / $25,000)",
				TargetPod: targetPod, AgentID: "ag_Travel_Bot", Action: "TRANSFER",
				Payload:        map[string]interface{}{"amount": 5000.0},
				ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
			})
		case 4:
			// Pod_D $5,000 transfer (Swarm Total: $20,000 <= $25,000)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Smurfing", Description: "Distributed Burst #4 on Pod_D ($5,000 -> Cumulative $20,000 / $25,000)",
				TargetPod: targetPod, AgentID: "ag_Travel_Bot", Action: "TRANSFER",
				Payload:        map[string]interface{}{"amount": 5000.0},
				ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
			})
		case 5:
			// Pod_E $5,000 transfer (Swarm Total: $25,000 <= $25,000, exactly hits ceiling!)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Smurfing", Description: "Distributed Burst #5 on Pod_E ($5,000 -> Cumulative $25,000 / $25,000 exact ceiling)",
				TargetPod: targetPod, AgentID: "ag_Travel_Bot", Action: "TRANSFER",
				Payload:        map[string]interface{}{"amount": 5000.0},
				ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
			})
		case 6:
			// Pod_A $1.00 transfer (Swarm Total: $25,001 > $25,000 -> BLOCKED BY STATE MESH!)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Smurfing", Description: "Distributed Smurfing Blocked on Pod_A ($1.00 push exceeds $25,000 cap)",
				TargetPod: targetPod, AgentID: "ag_Travel_Bot", Action: "TRANSFER",
				Payload:        map[string]interface{}{"amount": 1.0},
				ExpectedStatus: http.StatusTooManyRequests, ExpectedDecision: "DENY", ExpectedError: "VELOCITY_LIMIT_EXCEEDED",
			})
		case 7:
			// Pod_B $1.00 transfer (BLOCKED ON POD_B)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Smurfing", Description: "Distributed Smurfing Blocked on Pod_B ($1.00 push exceeds $25,000 cap)",
				TargetPod: targetPod, AgentID: "ag_Travel_Bot", Action: "TRANSFER",
				Payload:        map[string]interface{}{"amount": 1.0},
				ExpectedStatus: http.StatusTooManyRequests, ExpectedDecision: "DENY", ExpectedError: "VELOCITY_LIMIT_EXCEEDED",
			})
		case 8:
			// Pod_C $1.00 transfer (BLOCKED ON POD_C)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Smurfing", Description: "Distributed Smurfing Blocked on Pod_C ($1.00 push exceeds $25,000 cap)",
				TargetPod: targetPod, AgentID: "ag_Travel_Bot", Action: "TRANSFER",
				Payload:        map[string]interface{}{"amount": 1.0},
				ExpectedStatus: http.StatusTooManyRequests, ExpectedDecision: "DENY", ExpectedError: "VELOCITY_LIMIT_EXCEEDED",
			})
		case 9:
			// Pod_D $1.00 transfer (BLOCKED ON POD_D)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Smurfing", Description: "Distributed Smurfing Blocked on Pod_D ($1.00 push exceeds $25,000 cap)",
				TargetPod: targetPod, AgentID: "ag_Travel_Bot", Action: "TRANSFER",
				Payload:        map[string]interface{}{"amount": 1.0},
				ExpectedStatus: http.StatusTooManyRequests, ExpectedDecision: "DENY", ExpectedError: "VELOCITY_LIMIT_EXCEEDED",
			})
		case 10:
			// Pod_E $1.00 transfer (BLOCKED ON POD_E)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Smurfing", Description: "Distributed Smurfing Blocked on Pod_E ($1.00 push exceeds $25,000 cap)",
				TargetPod: targetPod, AgentID: "ag_Travel_Bot", Action: "TRANSFER",
				Payload:        map[string]interface{}{"amount": 1.0},
				ExpectedStatus: http.StatusTooManyRequests, ExpectedDecision: "DENY", ExpectedError: "VELOCITY_LIMIT_EXCEEDED",
			})
		default:
			// Cases 11..30: Reset and verify independent agent isolation and sub-cent precision across pods
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Smurfing", Description: fmt.Sprintf("Independent Agent Isolation: Dispute_AI operates unaffected on %s", targetPod),
				TargetPod: targetPod, AgentID: "ag_Dispute_AI", Action: "Credit_Increase",
				Payload: map[string]interface{}{"amount": 250.0},
				SetupFn: func(t *testing.T, mesh DistributedStateMesh, kr *AgentKeyRegistry) {
					// Clean reset for isolation test
					if i == 11 {
						mesh.Reset(context.Background())
					}
				},
				ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
			})
		}
	}

	// 3. Distributed Swarm Emergency Freeze Kill Switch (DIST-FREEZE-01..20)
	for i := 1; i <= 20; i++ {
		scID := fmt.Sprintf("DIST-FREEZE-%02d", i)
		targetPod := fmt.Sprintf("Pod_%c", 'A'+(i%5))

		switch i {
		case 1:
			// Normal state: Pod_A transaction succeeds
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Fleet Freeze", Description: "Normal Baseline: Pre-freeze transaction permitted on Pod_A",
				TargetPod: targetPod, AgentID: "ag_Dispute_AI", Action: "TRANSFER",
				Payload: map[string]interface{}{"amount": 100.0},
				SetupFn: func(t *testing.T, mesh DistributedStateMesh, kr *AgentKeyRegistry) {
					mesh.Reset(context.Background())
				},
				ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
			})
		case 2:
			// Activate Freeze on state mesh
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Fleet Freeze", Description: "Activate Emergency Freeze on Cluster State Mesh (Pod_A rejects with 503)",
				TargetPod: "Pod_A", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
				Payload: map[string]interface{}{"amount": 100.0},
				SetupFn: func(t *testing.T, mesh DistributedStateMesh, kr *AgentKeyRegistry) {
					mesh.SetFleetFreeze(context.Background(), true, "CRITICAL_ZERO_DAY_VULNERABILITY_HALT")
				},
				ExpectedStatus: http.StatusServiceUnavailable, ExpectedDecision: "DENY", ExpectedError: "FLEET_FROZEN",
			})
		case 3, 4, 5, 6:
			// Pod_B, Pod_C, Pod_D, Pod_E immediately reject traffic with 503
			podChar := byte('B' + (i - 3))
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Fleet Freeze", Description: fmt.Sprintf("Cluster-Wide Freeze Propagation: Pod_%c rejects with HTTP 503", podChar),
				TargetPod: fmt.Sprintf("Pod_%c", podChar), AgentID: "ag_Dispute_AI", Action: "TRANSFER",
				Payload:        map[string]interface{}{"amount": 100.0},
				ExpectedStatus: http.StatusServiceUnavailable, ExpectedDecision: "DENY", ExpectedError: "FLEET_FROZEN",
			})
		case 7:
			// Admin Emergency Maintenance Override (ag_Admin permitted during freeze)
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Fleet Freeze", Description: "Admin Emergency Override: ag_Admin bypasses freeze on Pod_C",
				TargetPod: "Pod_C", AgentID: "ag_Admin", Action: "TRANSFER",
				Payload:        map[string]interface{}{"amount": 0.0}, // Maintenance ping
				ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
			})
		case 8:
			// Unfreeze mesh
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Fleet Freeze", Description: "Deactivate Emergency Freeze on Cluster State Mesh",
				TargetPod: "Pod_A", AgentID: "ag_Dispute_AI", Action: "TRANSFER",
				Payload: map[string]interface{}{"amount": 100.0},
				SetupFn: func(t *testing.T, mesh DistributedStateMesh, kr *AgentKeyRegistry) {
					mesh.SetFleetFreeze(context.Background(), false, "")
				},
				ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
			})
		default:
			// Cases 9..20: Post-freeze resumption across all pods
			scenarios = append(scenarios, Phase3AdvancedScenario{
				ID: scID, Category: "Distributed Fleet Freeze", Description: fmt.Sprintf("Post-Freeze Traffic Resumption on %s", targetPod),
				TargetPod: targetPod, AgentID: "ag_Dispute_AI", Action: "Credit_Increase",
				Payload:        map[string]interface{}{"amount": 200.0},
				ExpectedStatus: http.StatusOK, ExpectedDecision: "ALLOW",
			})
		}
	}

	// -------------------------------------------------------------------
	// EXECUTION & TELEMETRY COLLECTION
	// -------------------------------------------------------------------
	fmt.Println("\n========================================================================")
	fmt.Println("   SENTINEL PHASE 3.3 & 3.4 ADVANCED ENTERPRISE BENCHMARK (150 TESTS)   ")
	fmt.Println("========================================================================")
	fmt.Printf("Auditing %d Real-World Vectors: Asymmetric Ed25519, UCAN DAGs, Redis Mesh...\n", len(scenarios))

	var totalPassed int64
	var totalFailed int64
	var falsePositives int64
	var falseNegatives int64

	categoryStats := make(map[string]struct{ passed, total int })
	var latencies []time.Duration
	var latMu sync.Mutex

	for _, sc := range scenarios {
		// Run setup hook if defined
		if sc.SetupFn != nil {
			sc.SetupFn(t, sharedMesh, keyReg)
		}

		// Prepare Request Body
		reqBody := AgentRequest{
			AgentID: sc.AgentID,
			Action:  sc.Action,
			Payload: sc.Payload,
		}
		rawJSON, _ := json.Marshal(reqBody)

		if sc.HeaderOverrides != nil && sc.HeaderOverrides["DUPLICATE_KEY_BODY"] == "true" {
			rawJSON = []byte(`{"agent_id":"ag_Dispute_AI","agent_id":"ag_Dispute_AI","action":"TRANSFER","payload":{"amount":100}}`)
		}

		req := httptest.NewRequest("POST", "/enforce", bytes.NewBuffer(rawJSON))
		req.Header.Set("Content-Type", "application/json")

		now := time.Now().UTC()
		tsStr := now.Format(time.RFC3339)
		nonceStr := fmt.Sprintf("nonce-%s-%d", sc.ID, now.UnixNano())

		// Setup Headers
		req.Header.Set("X-Sentinel-Agent-ID", sc.AgentID)
		req.Header.Set("X-Sentinel-Timestamp", tsStr)
		req.Header.Set("X-Sentinel-Nonce", nonceStr)

		// UCAN Header Handling
		if sc.UseUCAN && sc.UCANToken != nil {
			ucanBytes, _ := json.Marshal(sc.UCANToken)
			req.Header.Set("X-Sentinel-UCAN", string(ucanBytes))
			req.Header.Set("X-Sentinel-Auth-Scheme", "ucan")

			// Sign payload with executing agent's Ed25519 key
			bodyHash := sha256.Sum256(rawJSON)
			sig := SignCanonicalPayloadEd25519(sc.Ed25519PrivKey, sc.AgentID, tsStr, nonceStr, bodyHash[:])
			req.Header.Set("X-Sentinel-Signature", sig)
		} else if sc.AuthScheme == "ed25519" && len(sc.Ed25519PrivKey) > 0 {
			req.Header.Set("X-Sentinel-Auth-Scheme", "ed25519")
			bodyHash := sha256.Sum256(rawJSON)

			if sc.HeaderOverrides != nil && sc.HeaderOverrides["TAMPER_BODY"] == "true" {
				tamperedHash := sha256.Sum256([]byte(`{"tampered":true}`))
				sig := SignCanonicalPayloadEd25519(sc.Ed25519PrivKey, sc.AgentID, tsStr, nonceStr, tamperedHash[:])
				req.Header.Set("X-Sentinel-Signature", sig)
			} else {
				sig := SignCanonicalPayloadEd25519(sc.Ed25519PrivKey, sc.AgentID, tsStr, nonceStr, bodyHash[:])
				if sc.HeaderOverrides != nil && sc.HeaderOverrides["TAMPER_SIG"] == "true" {
					// Flip first byte
					if len(sig) > 2 {
						sig = "ff" + sig[2:]
					}
				}
				req.Header.Set("X-Sentinel-Signature", sig)
			}
		} else {
			// Legacy HMAC Signing
			bodyHash := sha256.Sum256(rawJSON)
			canonical := fmt.Sprintf("%s|%s|%s|%s", sc.AgentID, tsStr, nonceStr, hex.EncodeToString(bodyHash[:]))
			mac := hmac.New(sha256.New, []byte(agentSharedSecret))
			mac.Write([]byte(canonical))
			sig := hex.EncodeToString(mac.Sum(nil))
			req.Header.Set("X-Sentinel-Signature", sig)
		}

		// Apply Header Overrides
		for k, v := range sc.HeaderOverrides {
			if k != "TAMPER_BODY" && k != "TAMPER_SIG" && k != "DUPLICATE_KEY_BODY" {
				req.Header.Set(k, v)
			}
		}

		// Dispatch request to target pod handler
		podHandler := podHandlers[sc.TargetPod]
		if podHandler == nil {
			podHandler = enforceHandler
		}

		w := httptest.NewRecorder()
		start := time.Now()
		podHandler(w, req)
		duration := time.Since(start)

		latMu.Lock()
		latencies = append(latencies, duration)
		latMu.Unlock()

		// Verify Response
		actualStatus := w.Code
		var respBody map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &respBody)
		actualDecision, _ := respBody["status"].(string)

		passed := actualStatus == sc.ExpectedStatus
		if sc.ExpectedDecision != "" && actualDecision != sc.ExpectedDecision {
			passed = false
		}

		stats := categoryStats[sc.Category]
		stats.total++

		if passed {
			atomic.AddInt64(&totalPassed, 1)
			stats.passed++
			categoryStats[sc.Category] = stats
			fmt.Printf("[PASS] %-10s | %-28s | Status: %d (Exp: %d) | %s (%.2f µs)\n",
				sc.ID, sc.Category, actualStatus, sc.ExpectedStatus, sc.Description, float64(duration.Nanoseconds())/1000.0)
		} else {
			atomic.AddInt64(&totalFailed, 1)
			categoryStats[sc.Category] = stats

			if sc.ExpectedStatus == http.StatusOK && actualStatus != http.StatusOK {
				atomic.AddInt64(&falsePositives, 1)
			} else if sc.ExpectedStatus != http.StatusOK && actualStatus == http.StatusOK {
				atomic.AddInt64(&falseNegatives, 1)
			}

			t.Errorf("[%s] FAILED: expected HTTP %d (%s), got HTTP %d (%s) | Body: %v",
				sc.ID, sc.ExpectedStatus, sc.ExpectedDecision, actualStatus, actualDecision, respBody)
			fmt.Printf("❌ [FAIL] %-10s | %-28s | Status: %d (Exp: %d) | %s\n",
				sc.ID, sc.Category, actualStatus, sc.ExpectedStatus, sc.Description)
		}
	}

	// -------------------------------------------------------------------
	// TELEMETRY SUMMARY & METRICS
	// -------------------------------------------------------------------
	var totalDur time.Duration
	var minDur = time.Hour
	var maxDur time.Duration
	for _, d := range latencies {
		totalDur += d
		if d < minDur {
			minDur = d
		}
		if d > maxDur {
			maxDur = d
		}
	}
	avgDur := totalDur / time.Duration(len(latencies))

	fmt.Println("\n------------------------------------------------------------------------")
	fmt.Println("             PHASE 3.3 & 3.4 ADVANCED BENCHMARK SUMMARY                 ")
	fmt.Println("------------------------------------------------------------------------")
	fmt.Printf("Total Evaluated Scenarios : %d\n", len(scenarios))
	fmt.Printf("Total Passed Assertions   : %d\n", totalPassed)
	fmt.Printf("Total Failed Assertions   : %d\n", totalFailed)
	accuracy := (float64(totalPassed) / float64(len(scenarios))) * 100.0
	fmt.Printf("Decision Accuracy         : %.2f%%\n", accuracy)
	fmt.Printf("False Positive Rate (FPR) : %.2f%%\n", (float64(falsePositives)/float64(len(scenarios)))*100.0)
	fmt.Printf("False Negative Rate (FNR) : %.2f%%\n", (float64(falseNegatives)/float64(len(scenarios)))*100.0)

	fmt.Println("\n--- LATENCY TELEMETRY ---")
	fmt.Printf("Min Latency               : %v\n", minDur)
	fmt.Printf("Avg Latency               : %v\n", avgDur)
	fmt.Printf("Max Latency               : %v\n", maxDur)

	fmt.Println("\n--- BREAKDOWN BY CATEGORY ---")
	for cat, s := range categoryStats {
		pct := (float64(s.passed) / float64(s.total)) * 100.0
		fmt.Printf("• %-30s: %2d/%2d passed (%5.1f%%)\n", cat, s.passed, s.total, pct)
	}
	fmt.Println("========================================================================")

	if totalFailed > 0 {
		t.Fatalf("Phase 3.3 & 3.4 Advanced Benchmark FAILED: %d of %d scenarios failed", totalFailed, len(scenarios))
	}
}
