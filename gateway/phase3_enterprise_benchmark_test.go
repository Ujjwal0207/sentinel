package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
)

// Scenario represents a real-world enterprise test vector for Phase 3.1 & Phase 3.2
type Phase3Scenario struct {
	ID             string
	Phase          string
	Category       string
	Description    string
	AgentID        string
	Action         string
	Payload        map[string]interface{}
	IntentHeaders  map[string]string
	ExpectedStatus int
	ExpectedError  string
	VerifySocket   bool
	SocketTarget   string
}

func signPhase3Request(agentID, bodyStr, nonce string, ts time.Time) (string, string) {
	tsStr := ts.Format(time.RFC3339)
	bodyHash := sha256.Sum256([]byte(bodyStr))
	canonical := fmt.Sprintf("%s|%s|%s|%s", agentID, tsStr, nonce, hex.EncodeToString(bodyHash[:]))
	mac := hmac.New(sha256.New, []byte(agentSharedSecret))
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil)), tsStr
}

func TestPhase3EnterpriseBenchmark(t *testing.T) {
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

	// Initialize Casbin RBAC for realistic gateway operation
	var err error
	enforcer, err = casbin.NewEnforcer("../casbin_policies/model.conf", "../casbin_policies/policy.csv")
	if err != nil {
		t.Fatalf("Failed to initialize Casbin Enforcer: %v", err)
	}

	// Reset state trackers to ensure test isolation
	globalVelocityTracker.Reset()
	globalMandateTracker.Reset()

	now := time.Now().UTC()
	futureExpiry := now.Add(1 * time.Hour).Unix()
	pastExpiry := now.Add(-5 * time.Minute).Unix()

	// Helper to generate a valid mandate commitment signature
	genCommitment := func(authorizer, action string, maxAmt float64, curr, rcpt, mandateID string, expUnix int64) string {
		return ComputeIntentCommitment(intentSharedSecret, authorizer, action, maxAmt, curr, rcpt, mandateID, expUnix)
	}

	scenarios := []Phase3Scenario{
		// =========================================================================
		// PHASE 3.1: TRANSPORT SOCKET-LEVEL DEFENSE & TOCTOU DNS REBINDING (65 CASES)
		// =========================================================================

		// 1. Dynamic DNS Rebinding to Cloud Metadata (AWS, GCP, Azure, Oracle)
		{
			ID: "TOCTOU-01", Phase: "3.1", Category: "DNS Rebinding", Description: "Dynamic DNS flip to AWS IMDSv1 (169.254.169.254)",
			VerifySocket: true, SocketTarget: "169.254.169.254:80", ExpectedError: "Link-local cloud metadata",
		},
		{
			ID: "TOCTOU-02", Phase: "3.1", Category: "DNS Rebinding", Description: "Dynamic DNS flip to AWS ECS task metadata (169.254.170.2)",
			VerifySocket: true, SocketTarget: "169.254.170.2:80", ExpectedError: "Link-local cloud metadata",
		},
		{
			ID: "TOCTOU-03", Phase: "3.1", Category: "DNS Rebinding", Description: "Dynamic DNS flip to GCP link-local metadata (169.254.169.254)",
			VerifySocket: true, SocketTarget: "169.254.169.254:8080", ExpectedError: "Link-local cloud metadata",
		},
		{
			ID: "TOCTOU-04", Phase: "3.1", Category: "DNS Rebinding", Description: "Dynamic DNS flip to OpenStack metadata (169.254.169.254)",
			VerifySocket: true, SocketTarget: "169.254.169.254:8775", ExpectedError: "Link-local cloud metadata",
		},
		{
			ID: "TOCTOU-05", Phase: "3.1", Category: "DNS Rebinding", Description: "Dynamic DNS flip to IPv6 AWS IMDSv2 (fd00:ec2::254)",
			VerifySocket: true, SocketTarget: "[fd00:ec2::254]:80", ExpectedError: "Unique Local Address",
		},

		// 2. Dynamic DNS Rebinding to Internal RFC 1918 Private Subnets
		{
			ID: "TOCTOU-06", Phase: "3.1", Category: "DNS Rebinding", Description: "Dynamic DNS flip to RFC 1918 Class A Gateway (10.0.0.1)",
			VerifySocket: true, SocketTarget: "10.0.0.1:80", ExpectedError: "RFC 1918 private",
		},
		{
			ID: "TOCTOU-07", Phase: "3.1", Category: "DNS Rebinding", Description: "Dynamic DNS flip to RFC 1918 Class A Deep Host (10.254.254.1)",
			VerifySocket: true, SocketTarget: "10.254.254.1:443", ExpectedError: "RFC 1918 private",
		},
		{
			ID: "TOCTOU-08", Phase: "3.1", Category: "DNS Rebinding", Description: "Dynamic DNS flip to RFC 1918 Class B Start (172.16.0.1)",
			VerifySocket: true, SocketTarget: "172.16.0.1:80", ExpectedError: "RFC 1918 private",
		},
		{
			ID: "TOCTOU-09", Phase: "3.1", Category: "DNS Rebinding", Description: "Dynamic DNS flip to RFC 1918 Class B Mid (172.24.100.50)",
			VerifySocket: true, SocketTarget: "172.24.100.50:8080", ExpectedError: "RFC 1918 private",
		},
		{
			ID: "TOCTOU-10", Phase: "3.1", Category: "DNS Rebinding", Description: "Dynamic DNS flip to RFC 1918 Class B End (172.31.255.254)",
			VerifySocket: true, SocketTarget: "172.31.255.254:443", ExpectedError: "RFC 1918 private",
		},
		{
			ID: "TOCTOU-11", Phase: "3.1", Category: "DNS Rebinding", Description: "Dynamic DNS flip to RFC 1918 Class C Router (192.168.0.1)",
			VerifySocket: true, SocketTarget: "192.168.0.1:80", ExpectedError: "RFC 1918 private",
		},
		{
			ID: "TOCTOU-12", Phase: "3.1", Category: "DNS Rebinding", Description: "Dynamic DNS flip to RFC 1918 Class C Host (192.168.1.254)",
			VerifySocket: true, SocketTarget: "192.168.1.254:443", ExpectedError: "RFC 1918 private",
		},

		// 3. Loopback Variations (IPv4 & IPv6)
		{
			ID: "TOCTOU-13", Phase: "3.1", Category: "Loopback Evasion", Description: "Dynamic DNS flip to standard IPv4 loopback (127.0.0.1)",
			VerifySocket: true, SocketTarget: "127.0.0.1:80", ExpectedError: "loopback",
		},
		{
			ID: "TOCTOU-14", Phase: "3.1", Category: "Loopback Evasion", Description: "Dynamic DNS flip to non-standard loopback (127.0.0.2)",
			VerifySocket: true, SocketTarget: "127.0.0.2:80", ExpectedError: "loopback",
		},
		{
			ID: "TOCTOU-15", Phase: "3.1", Category: "Loopback Evasion", Description: "Dynamic DNS flip to deep loopback (127.100.200.1)",
			VerifySocket: true, SocketTarget: "127.100.200.1:80", ExpectedError: "loopback",
		},
		{
			ID: "TOCTOU-16", Phase: "3.1", Category: "Loopback Evasion", Description: "Dynamic DNS flip to loopback boundary (127.255.255.254)",
			VerifySocket: true, SocketTarget: "127.255.255.254:80", ExpectedError: "loopback",
		},
		{
			ID: "TOCTOU-17", Phase: "3.1", Category: "Loopback Evasion", Description: "Dynamic DNS flip to standard IPv6 loopback (::1)",
			VerifySocket: true, SocketTarget: "[::1]:80", ExpectedError: "Loopback",
		},
		{
			ID: "TOCTOU-18", Phase: "3.1", Category: "Loopback Evasion", Description: "Dynamic DNS flip to IPv6 unspecified address (::)",
			VerifySocket: true, SocketTarget: "[::]:80", ExpectedError: "Unspecified",
		},

		// 4. IPv4-Mapped IPv6 Dual-Stack Bypasses
		{
			ID: "TOCTOU-19", Phase: "3.1", Category: "IPv4-Mapped IPv6", Description: "IPv4-mapped IPv6 loopback (::ffff:127.0.0.1)",
			VerifySocket: true, SocketTarget: "[::ffff:127.0.0.1]:80", ExpectedError: "loopback",
		},
		{
			ID: "TOCTOU-20", Phase: "3.1", Category: "IPv4-Mapped IPv6", Description: "IPv4-mapped IPv6 metadata (::ffff:169.254.169.254)",
			VerifySocket: true, SocketTarget: "[::ffff:169.254.169.254]:80", ExpectedError: "Link-local cloud metadata",
		},
		{
			ID: "TOCTOU-21", Phase: "3.1", Category: "IPv4-Mapped IPv6", Description: "IPv4-mapped IPv6 RFC 1918 Class A (::ffff:10.0.0.1)",
			VerifySocket: true, SocketTarget: "[::ffff:10.0.0.1]:80", ExpectedError: "RFC 1918 private",
		},
		{
			ID: "TOCTOU-22", Phase: "3.1", Category: "IPv4-Mapped IPv6", Description: "IPv4-mapped IPv6 RFC 1918 Class B (::ffff:172.16.0.1)",
			VerifySocket: true, SocketTarget: "[::ffff:172.16.0.1]:80", ExpectedError: "RFC 1918 private",
		},
		{
			ID: "TOCTOU-23", Phase: "3.1", Category: "IPv4-Mapped IPv6", Description: "IPv4-mapped IPv6 RFC 1918 Class C (::ffff:192.168.1.1)",
			VerifySocket: true, SocketTarget: "[::ffff:192.168.1.1]:80", ExpectedError: "RFC 1918 private",
		},
		{
			ID: "TOCTOU-24", Phase: "3.1", Category: "IPv4-Mapped IPv6", Description: "IPv4-mapped IPv6 hex format metadata (::ffff:a9fe:a9fe)",
			VerifySocket: true, SocketTarget: "[::ffff:a9fe:a9fe]:80", ExpectedError: "Link-local cloud metadata",
		},

		// 5. IPv6 Link-Local and Unique-Local Addresses (ULA)
		{
			ID: "TOCTOU-25", Phase: "3.1", Category: "IPv6 Restrictions", Description: "IPv6 Link-Local address (fe80::1)",
			VerifySocket: true, SocketTarget: "[fe80::1]:80", ExpectedError: "Link-Local",
		},
		{
			ID: "TOCTOU-26", Phase: "3.1", Category: "IPv6 Restrictions", Description: "IPv6 Link-Local interface host (fe80::200:5efe:10.0.0.1)",
			VerifySocket: true, SocketTarget: "[fe80::200:5efe:10.0.0.1]:80", ExpectedError: "Link-Local",
		},
		{
			ID: "TOCTOU-27", Phase: "3.1", Category: "IPv6 Restrictions", Description: "IPv6 Unique Local Address ULA fc00::/8 (fc00::1)",
			VerifySocket: true, SocketTarget: "[fc00::1]:80", ExpectedError: "Unique Local Address",
		},
		{
			ID: "TOCTOU-28", Phase: "3.1", Category: "IPv6 Restrictions", Description: "IPv6 Unique Local Address ULA fd00::/8 (fd12:3456:789a::1)",
			VerifySocket: true, SocketTarget: "[fd12:3456:789a::1]:80", ExpectedError: "Unique Local Address",
		},
		{
			ID: "TOCTOU-29", Phase: "3.1", Category: "IPv6 Restrictions", Description: "IPv6 6to4 encapsulation embedding 127.0.0.1 (2002:7f00:0001::)",
			VerifySocket: true, SocketTarget: "[2002:7f00:0001::]:80", ExpectedError: "6to4 encapsulation embeds restricted address",
		},
		{
			ID: "TOCTOU-30", Phase: "3.1", Category: "IPv6 Restrictions", Description: "IPv6 6to4 encapsulation embedding metadata (2002:a9fe:a9fe::)",
			VerifySocket: true, SocketTarget: "[2002:a9fe:a9fe::]:80", ExpectedError: "6to4 encapsulation embeds restricted address",
		},

		// 6. Carrier-Grade NAT (RFC 6598: 100.64.0.0/10)
		{
			ID: "TOCTOU-31", Phase: "3.1", Category: "CGNAT Restrictions", Description: "Carrier-Grade NAT network start (100.64.0.1)",
			VerifySocket: true, SocketTarget: "100.64.0.1:80", ExpectedError: "Carrier-Grade NAT",
		},
		{
			ID: "TOCTOU-32", Phase: "3.1", Category: "CGNAT Restrictions", Description: "Carrier-Grade NAT network mid (100.100.50.25)",
			VerifySocket: true, SocketTarget: "100.100.50.25:8080", ExpectedError: "Carrier-Grade NAT",
		},
		{
			ID: "TOCTOU-33", Phase: "3.1", Category: "CGNAT Restrictions", Description: "Carrier-Grade NAT network ceiling (100.127.255.254)",
			VerifySocket: true, SocketTarget: "100.127.255.254:443", ExpectedError: "Carrier-Grade NAT",
		},

		// 7. Documentation & Benchmark Subnets (RFC 5737 & RFC 2544)
		{
			ID: "TOCTOU-34", Phase: "3.1", Category: "Reserved Subnets", Description: "TEST-NET-1 documentation subnet (192.0.2.1)",
			VerifySocket: true, SocketTarget: "192.0.2.1:80", ExpectedError: "Documentation subnet",
		},
		{
			ID: "TOCTOU-35", Phase: "3.1", Category: "Reserved Subnets", Description: "TEST-NET-2 documentation subnet (198.51.100.1)",
			VerifySocket: true, SocketTarget: "198.51.100.1:80", ExpectedError: "Documentation subnet",
		},
		{
			ID: "TOCTOU-36", Phase: "3.1", Category: "Reserved Subnets", Description: "TEST-NET-3 documentation subnet (203.0.113.1)",
			VerifySocket: true, SocketTarget: "203.0.113.1:80", ExpectedError: "Documentation subnet",
		},
		{
			ID: "TOCTOU-37", Phase: "3.1", Category: "Reserved Subnets", Description: "Benchmarking network start (198.18.0.1)",
			VerifySocket: true, SocketTarget: "198.18.0.1:80", ExpectedError: "Benchmarking network",
		},
		{
			ID: "TOCTOU-38", Phase: "3.1", Category: "Reserved Subnets", Description: "Benchmarking network ceiling (198.19.255.254)",
			VerifySocket: true, SocketTarget: "198.19.255.254:80", ExpectedError: "Benchmarking network",
		},

		// 8. Broadcast & Reserved Class E Subnets (RFC 1112)
		{
			ID: "TOCTOU-39", Phase: "3.1", Category: "Broadcast Subnets", Description: "Current network address (0.0.0.0)",
			VerifySocket: true, SocketTarget: "0.0.0.0:80", ExpectedError: "Broadcast / Current network",
		},
		{
			ID: "TOCTOU-40", Phase: "3.1", Category: "Broadcast Subnets", Description: "Current network host (0.0.0.1)",
			VerifySocket: true, SocketTarget: "0.0.0.1:80", ExpectedError: "Broadcast / Current network",
		},
		{
			ID: "TOCTOU-41", Phase: "3.1", Category: "Broadcast Subnets", Description: "Limited broadcast address (255.255.255.255)",
			VerifySocket: true, SocketTarget: "255.255.255.255:80", ExpectedError: "Limited broadcast",
		},
		{
			ID: "TOCTOU-42", Phase: "3.1", Category: "Broadcast Subnets", Description: "Class E reserved address (240.0.0.1)",
			VerifySocket: true, SocketTarget: "240.0.0.1:80", ExpectedError: "Reserved/Multicast",
		},
		{
			ID: "TOCTOU-43", Phase: "3.1", Category: "Broadcast Subnets", Description: "Class E reserved host (250.1.2.3)",
			VerifySocket: true, SocketTarget: "250.1.2.3:80", ExpectedError: "Reserved/Multicast",
		},
		{
			ID: "TOCTOU-44", Phase: "3.1", Category: "Broadcast Subnets", Description: "IPv4 Multicast address (224.0.0.1)",
			VerifySocket: true, SocketTarget: "224.0.0.1:80", ExpectedError: "Multicast address",
		},
		{
			ID: "TOCTOU-45", Phase: "3.1", Category: "Broadcast Subnets", Description: "SSDP Local Multicast (239.255.255.250)",
			VerifySocket: true, SocketTarget: "239.255.255.250:1900", ExpectedError: "Multicast address",
		},

		// 9. Decimal / Hex / Octal Encoded IPs through Gateway Guardrail
		{
			ID: "ENC-01", Phase: "3.1", Category: "IP Encodings", Description: "Dword integer 2130706433 (127.0.0.1) in webhook payload",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "webhook": "http://2130706433/callback"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "ENC-02", Phase: "3.1", Category: "IP Encodings", Description: "Dword integer 2852039166 (169.254.169.254) in webhook payload",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "webhook": "http://2852039166/latest/meta-data/"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "ENC-03", Phase: "3.1", Category: "IP Encodings", Description: "Dword integer 167772161 (10.0.0.1) in webhook payload",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "webhook": "http://167772161/admin"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "ENC-04", Phase: "3.1", Category: "IP Encodings", Description: "Hexadecimal 0x7f000001 (127.0.0.1) in webhook payload",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "webhook": "http://0x7f000001/status"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "ENC-05", Phase: "3.1", Category: "IP Encodings", Description: "Hexadecimal 0xa9fea9fe (169.254.169.254) in webhook payload",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "webhook": "http://0xa9fea9fe/metadata"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "ENC-06", Phase: "3.1", Category: "IP Encodings", Description: "Octal 0177.0.0.1 (127.0.0.1) in webhook payload",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "webhook": "http://0177.0.0.1/debug"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},

		// 10. Dangerous URI Schemes & Smuggling
		{
			ID: "SCHEME-01", Phase: "3.1", Category: "Dangerous Protocols", Description: "Gopher protocol Redis exfiltration payload",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "target": "gopher://127.0.0.1:6379/_flushall"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "SCHEME-02", Phase: "3.1", Category: "Dangerous Protocols", Description: "File URI local file disclosure attempt",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "target": "file:///etc/passwd"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "SCHEME-03", Phase: "3.1", Category: "Dangerous Protocols", Description: "Dict protocol Memcached dump attempt",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "target": "dict://127.0.0.1:11211/stat"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "SCHEME-04", Phase: "3.1", Category: "Dangerous Protocols", Description: "FTP internal credential relay attempt",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "target": "ftp://anonymous:test@internal-ftp.corp/"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "SCHEME-05", Phase: "3.1", Category: "Dangerous Protocols", Description: "LDAP directory harvest attempt",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "target": "ldap://internal-dc.corp/dc=corp"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "SCHEME-06", Phase: "3.1", Category: "Dangerous Protocols", Description: "TFTP router config extraction attempt",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "target": "tftp://10.0.0.1/config"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "SCHEME-07", Phase: "3.1", Category: "Dangerous Protocols", Description: "PHP input stream wrapper attempt",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "target": "php://input"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},

		// 11. Legitimate Public Webhooks & External Services (0% False Positives)
		{
			ID: "PUB-01", Phase: "3.1", Category: "Public Webhook", Description: "Stripe API legitimate charge webhook",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 75.0, "webhook": "https://api.stripe.com/v1/charges"},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "PUB-02", Phase: "3.1", Category: "Public Webhook", Description: "Slack incoming notifications webhook",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 75.0, "webhook": "https://hooks.slack.com/services/T00/B00/X123"},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "PUB-03", Phase: "3.1", Category: "Public Webhook", Description: "GitHub repo dispatch webhook",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 75.0, "webhook": "https://api.github.com/repos/corp/repo/dispatches"},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "PUB-04", Phase: "3.1", Category: "Public Webhook", Description: "Salesforce REST enterprise sync",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 75.0, "webhook": "https://na1.salesforce.com/services/data/v58.0"},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "PUB-05", Phase: "3.1", Category: "Public Webhook", Description: "Twilio outbound SMS dispatch",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 75.0, "webhook": "https://api.twilio.com/2010-04-01/Accounts/AC/Messages.json"},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "PUB-06", Phase: "3.1", Category: "Public Webhook", Description: "PagerDuty Event API v2 alert",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 75.0, "webhook": "https://events.pagerduty.com/v2/enqueue"},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "PUB-07", Phase: "3.1", Category: "Public Webhook", Description: "Shopify inventory webhook callback",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 75.0, "webhook": "https://store.myshopify.com/admin/api/2024-01/webhooks.json"},
			ExpectedStatus: http.StatusOK,
		},

		// =========================================================================
		// PHASE 3.2: GOOGLE AP2 USER INTENT MANDATE & DRIFT ANCHOR (70 CASES)
		// =========================================================================

		// 1. Amount Inflation Drift (The AP2 #1 Vulnerability: $300 -> $3,000)
		{
			ID: "AP2-INFL-01", Phase: "3.2", Category: "Amount Inflation", Description: "Single dollar inflation ($300 authorized -> $301 attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 301.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_infl_01",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_infl_01", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_AMOUNT_INFLATION",
		},
		{
			ID: "AP2-INFL-02", Phase: "3.2", Category: "Amount Inflation", Description: "16% drift ($300 authorized -> $350 attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 350.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_infl_02",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_infl_02", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_AMOUNT_INFLATION",
		},
		{
			ID: "AP2-INFL-03", Phase: "3.2", Category: "Amount Inflation", Description: "10x order-of-magnitude inflation ($300 authorized -> $3,000 attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 3000.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_infl_03",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_infl_03", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_AMOUNT_INFLATION",
		},
		{
			ID: "AP2-INFL-04", Phase: "3.2", Category: "Amount Inflation", Description: "100x inflation drift ($300 authorized -> $30,000 attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 30000.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_infl_04",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_infl_04", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_AMOUNT_INFLATION",
		},
		{
			ID: "AP2-INFL-05", Phase: "3.2", Category: "Amount Inflation", Description: "1-cent sub-cent drift ($1,500 authorized -> $1,500.01 attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 1500.01, "currency": "USD", "recipient": "Supplier_Corp"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_finance_mgr",
				"X-Sentinel-Intent-Mandate-ID": "mnd_infl_05",
				"X-Sentinel-Intent-Max-Amount": "1500.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Supplier_Corp",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_finance_mgr", "TRANSFER", 1500.0, "USD", "Supplier_Corp", "mnd_infl_05", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_AMOUNT_INFLATION",
		},
		{
			ID: "AP2-INFL-06", Phase: "3.2", Category: "Amount Inflation", Description: "Minor units inflation ($500 authorized -> 50,001 cents attempted = $500.01)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount_in_cents": 50001, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_infl_06",
				"X-Sentinel-Intent-Max-Amount": "500.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 500.0, "USD", "Rahul", "mnd_infl_06", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_AMOUNT_INFLATION",
		},
		{
			ID: "AP2-INFL-07", Phase: "3.2", Category: "Amount Inflation", Description: "Cents alias inflation ($500 authorized -> 60,000 cents attempted = $600.00)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"cents": 60000, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_infl_07",
				"X-Sentinel-Intent-Max-Amount": "500.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 500.0, "USD", "Rahul", "mnd_infl_07", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_AMOUNT_INFLATION",
		},
		{
			ID: "AP2-INFL-08", Phase: "3.2", Category: "Amount Inflation", Description: "Transfer amount alias inflation ($2,000 authorized -> $2,500 attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"transfer_amount": 2500.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_infl_08",
				"X-Sentinel-Intent-Max-Amount": "2000.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 2000.0, "USD", "Rahul", "mnd_infl_08", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_AMOUNT_INFLATION",
		},
		{
			ID: "AP2-INFL-09", Phase: "3.2", Category: "Amount Inflation", Description: "Formatted currency string inflation ($1,000 authorized -> '$1,050.00')",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": "$1,050.00", "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_infl_09",
				"X-Sentinel-Intent-Max-Amount": "1000.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 1000.0, "USD", "Rahul", "mnd_infl_09", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_AMOUNT_INFLATION",
		},
		{
			ID: "AP2-INFL-10", Phase: "3.2", Category: "Amount Inflation", Description: "Large treasury transfer inflation ($8,000 authorized -> $8,001 attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 8001.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_infl_10",
				"X-Sentinel-Intent-Max-Amount": "8000.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 8000.0, "USD", "Rahul", "mnd_infl_10", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_AMOUNT_INFLATION",
		},

		// 2. Amount Conformance & Underflow (Benign Validations)
		{
			ID: "AP2-AMT-OK-01", Phase: "3.2", Category: "Amount Conformance", Description: "Exact ceiling execution ($300 authorized == $300 executed)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_ok_01",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_ok_01", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-AMT-OK-02", Phase: "3.2", Category: "Amount Conformance", Description: "Slightly under ceiling ($300 authorized -> $299.99 executed)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 299.99, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_ok_02",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_ok_02", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-AMT-OK-03", Phase: "3.2", Category: "Amount Conformance", Description: "Partial discount execution ($300 authorized -> $150 executed)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 150.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_ok_03",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_ok_03", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-AMT-OK-04", Phase: "3.2", Category: "Amount Conformance", Description: "Micro-payment execution ($300 authorized -> $0.50 executed)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 0.50, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_ok_04",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_ok_04", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-AMT-OK-05", Phase: "3.2", Category: "Amount Conformance", Description: "Exact minor units match ($500 authorized == 50,000 cents executed)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount_in_cents": 50000, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_ok_05",
				"X-Sentinel-Intent-Max-Amount": "500.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 500.0, "USD", "Rahul", "mnd_ok_05", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-AMT-OK-06", Phase: "3.2", Category: "Amount Conformance", Description: "Formatted currency string ($1,250 authorized == '$1,250.00' executed)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": "$1,250.00", "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_ok_06",
				"X-Sentinel-Intent-Max-Amount": "1250.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 1250.0, "USD", "Rahul", "mnd_ok_06", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},

		// 3. Recipient Substitution Drift
		{
			ID: "AP2-RCPT-01", Phase: "3.2", Category: "Recipient Drift", Description: "Entity confusion ('Rahul' authorized -> 'Rahul Sharma' attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul Sharma"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_rcpt_01",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_rcpt_01", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_RECIPIENT_DRIFT",
		},
		{
			ID: "AP2-RCPT-02", Phase: "3.2", Category: "Recipient Drift", Description: "Phishing email substitution ('Rahul' authorized -> 'attacker@evil.com' attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "attacker@evil.com"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_rcpt_02",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_rcpt_02", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_RECIPIENT_DRIFT",
		},
		{
			ID: "AP2-RCPT-03", Phase: "3.2", Category: "Recipient Drift", Description: "Crypto wallet hijack ('Rahul' authorized -> '0xDeaD...00' attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "0xDeaD0000000000000000"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_rcpt_03",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_rcpt_03", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_RECIPIENT_DRIFT",
		},
		{
			ID: "AP2-RCPT-04", Phase: "3.2", Category: "Recipient Drift", Description: "One-digit account typo hijack ('acct_88912' -> 'acct_88913')",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "target_account": "acct_88913"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_rcpt_04",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "acct_88912",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "acct_88912", "mnd_rcpt_04", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_RECIPIENT_DRIFT",
		},
		{
			ID: "AP2-RCPT-05", Phase: "3.2", Category: "Recipient Drift", Description: "Payee alias substitution ('Alice' authorized -> payee: 'Eve')",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "payee": "Eve"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_rcpt_05",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Alice",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Alice", "mnd_rcpt_05", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_RECIPIENT_DRIFT",
		},
		{
			ID: "AP2-RCPT-06", Phase: "3.2", Category: "Recipient Drift", Description: "Beneficiary alias substitution ('Alice' authorized -> beneficiary: 'Mallory')",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "beneficiary": "Mallory"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_rcpt_06",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Alice",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Alice", "mnd_rcpt_06", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_RECIPIENT_DRIFT",
		},
		{
			ID: "AP2-RCPT-07", Phase: "3.2", Category: "Recipient Drift", Description: "To alias substitution ('Alice' authorized -> to: 'Bob')",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "to": "Bob"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_rcpt_07",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Alice",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Alice", "mnd_rcpt_07", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_RECIPIENT_DRIFT",
		},
		{
			ID: "AP2-RCPT-08", Phase: "3.2", Category: "Recipient Match", Description: "Case-insensitive recipient matching ('Rahul' authorized == 'rahul' executed)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_rcpt_08",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_rcpt_08", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-RCPT-09", Phase: "3.2", Category: "Recipient Match", Description: "Whitespace-trimmed recipient matching (' Rahul ' authorized == 'Rahul' executed)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_rcpt_09",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  " Rahul ",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_rcpt_09", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},

		// 4. Currency Divergence Drift
		{
			ID: "AP2-CURR-01", Phase: "3.2", Category: "Currency Drift", Description: "Currency switch (USD authorized -> EUR attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "EUR", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_curr_01",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_curr_01", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_CURRENCY_DRIFT",
		},
		{
			ID: "AP2-CURR-02", Phase: "3.2", Category: "Currency Drift", Description: "Currency switch (USD authorized -> GBP attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "GBP", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_curr_02",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_curr_02", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_CURRENCY_DRIFT",
		},
		{
			ID: "AP2-CURR-03", Phase: "3.2", Category: "Currency Drift", Description: "Currency switch (USD authorized -> KWD 3.26x attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "KWD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_curr_03",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_curr_03", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_CURRENCY_DRIFT",
		},
		{
			ID: "AP2-CURR-04", Phase: "3.2", Category: "Currency Drift", Description: "Currency switch (USD authorized -> JPY attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 15000.0, "currency": "JPY", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_curr_04",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_curr_04", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_CURRENCY_DRIFT",
		},
		{
			ID: "AP2-CURR-05", Phase: "3.2", Category: "Currency Drift", Description: "Currency switch (USD authorized -> BTC attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 0.05, "currency": "BTC", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_curr_05",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_curr_05", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_CURRENCY_DRIFT",
		},
		{
			ID: "AP2-CURR-06", Phase: "3.2", Category: "Currency Drift", Description: "Currency alias curr: 'CAD' drift (USD authorized -> CAD attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "curr": "CAD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_curr_06",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_curr_06", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_CURRENCY_DRIFT",
		},
		{
			ID: "AP2-CURR-07", Phase: "3.2", Category: "Currency Match", Description: "Lowercase currency match ('USD' authorized == 'usd' payload)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "usd", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_curr_07",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_curr_07", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},

		// 5. Action Drift & Scope Escalation
		{
			ID: "AP2-ACT-01", Phase: "3.2", Category: "Action Drift", Description: "Scope escalation ('Issue_Refund' authorized -> 'TRANSFER' attempted)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_act_01",
				"X-Sentinel-Intent-Action":     "Issue_Refund",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_act_01", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_ACTION_DRIFT",
		},
		{
			ID: "AP2-ACT-02", Phase: "3.2", Category: "Action Drift", Description: "Action drift ('TRANSFER' authorized -> 'Credit_Increase' attempted)",
			AgentID: "ag_Dispute_AI", Action: "Credit_Increase",
			Payload: map[string]interface{}{"amount": 5000.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_act_02",
				"X-Sentinel-Intent-Action":     "TRANSFER",
				"X-Sentinel-Intent-Max-Amount": "5000.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "Credit_Increase", 5000.0, "USD", "Rahul", "mnd_act_02", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_ACTION_DRIFT",
		},
		{
			ID: "AP2-ACT-03", Phase: "3.2", Category: "Action Match", Description: "Case-insensitive action match ('Issue_Refund' authorized == 'issue_refund' body)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 45.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_act_03",
				"X-Sentinel-Intent-Action":     "issue_refund",
				"X-Sentinel-Intent-Max-Amount": "100.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "Issue_Refund", 100.0, "USD", "Rahul", "mnd_act_03", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},

		// 6. Cryptographic Commitment Forgery & Tampering
		{
			ID: "AP2-FORGE-01", Phase: "3.2", Category: "Commitment Forgery", Description: "Forged HMAC commitment using incorrect secret key",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_forge_01",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			ExpectedStatus: http.StatusUnauthorized, ExpectedError: "INTENT_COMMITMENT_FORGERY",
		},
		{
			ID: "AP2-FORGE-02", Phase: "3.2", Category: "Commitment Forgery", Description: "Altered authorizer ID without updating commitment signature",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_malicious_attacker", // Changed from alice
				"X-Sentinel-Intent-Mandate-ID": "mnd_forge_02",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_forge_02", futureExpiry),
			},
			ExpectedStatus: http.StatusUnauthorized, ExpectedError: "INTENT_COMMITMENT_FORGERY",
		},
		{
			ID: "AP2-FORGE-03", Phase: "3.2", Category: "Commitment Forgery", Description: "Altered mandate ID without updating commitment signature",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_forge_tampered", // Changed mandate ID
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_forge_original", futureExpiry),
			},
			ExpectedStatus: http.StatusUnauthorized, ExpectedError: "INTENT_COMMITMENT_FORGERY",
		},

		// 7. Temporal Lifecycle & Replay Attacks
		{
			ID: "AP2-TIME-01", Phase: "3.2", Category: "Temporal Lifecycle", Description: "Expired mandate executed 5 minutes in the past",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_time_01",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", pastExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_time_01", pastExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "MANDATE_EXPIRED",
		},
		{
			ID: "AP2-TIME-02", Phase: "3.2", Category: "Temporal Lifecycle", Description: "Immediate mandate execution (expiring in 30 seconds)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_time_02",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", now.Add(30*time.Second).Unix()),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_time_02", now.Add(30*time.Second).Unix()),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-REPLAY-01", Phase: "3.2", Category: "Mandate Replay", Description: "One-time mandate initial consumption (Must Succeed)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_one_time_999",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_one_time_999", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-REPLAY-02", Phase: "3.2", Category: "Mandate Replay", Description: "One-time mandate replay attempt with same ID (Must Fail with Replay)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_one_time_999", // Replayed ID
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_one_time_999", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "MANDATE_REPLAY_DETECTED",
		},

		// 8. Incomplete / Malformed Header Fields
		{
			ID: "AP2-HDR-01", Phase: "3.2", Category: "Header Integrity", Description: "Missing Commitment Header while providing other intent headers",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_hdr_01",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
			},
			ExpectedStatus: http.StatusBadRequest, ExpectedError: "INCOMPLETE_INTENT_HEADERS",
		},
		{
			ID: "AP2-HDR-02", Phase: "3.2", Category: "Header Integrity", Description: "Missing Authorizer Header while providing other intent headers",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Commitment": "abcdef",
				"X-Sentinel-Intent-Mandate-ID": "mnd_hdr_02",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
			},
			ExpectedStatus: http.StatusBadRequest, ExpectedError: "INCOMPLETE_INTENT_HEADERS",
		},
		{
			ID: "AP2-HDR-03", Phase: "3.2", Category: "Header Integrity", Description: "Non-numeric Max-Amount in intent header",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Commitment": "abcdef",
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_hdr_03",
				"X-Sentinel-Intent-Max-Amount": "three_hundred_dollars",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
			},
			ExpectedStatus: http.StatusBadRequest, ExpectedError: "INVALID_MANDATE_AMOUNT",
		},
		{
			ID: "AP2-HDR-04", Phase: "3.2", Category: "Header Integrity", Description: "Negative Max-Amount in intent header",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Commitment": "abcdef",
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_hdr_04",
				"X-Sentinel-Intent-Max-Amount": "-50.00",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
			},
			ExpectedStatus: http.StatusBadRequest, ExpectedError: "INVALID_MANDATE_AMOUNT",
		},
		{
			ID: "AP2-HDR-05", Phase: "3.2", Category: "Header Integrity", Description: "Malformed non-timestamp expiry header",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Commitment": "abcdef",
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_hdr_05",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Expires":    "never_expires_tomorrow",
			},
			ExpectedStatus: http.StatusBadRequest, ExpectedError: "INVALID_MANDATE_EXPIRY",
		},

		// 9. Multi-Turn Autonomous Commerce Scenarios (Benign Clearances)
		{
			ID: "AP2-FLOW-01", Phase: "3.2", Category: "Autonomous Commerce", Description: "Autonomous travel flight purchase within $600 mandate",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{
				"amount":    549.50,
				"currency":  "USD",
				"recipient": "United_Airlines",
				"itinerary": map[string]interface{}{
					"flight": "UA102", "seat": "14A", "passengers": 1,
				},
			},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_traveler_101",
				"X-Sentinel-Intent-Mandate-ID": "mnd_flow_01",
				"X-Sentinel-Intent-Max-Amount": "600.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "United_Airlines",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_traveler_101", "TRANSFER", 600.0, "USD", "United_Airlines", "mnd_flow_01", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-FLOW-02", Phase: "3.2", Category: "Autonomous Commerce", Description: "Dispute AI approved claim settlement with exact mandate",
			AgentID: "ag_Dispute_AI", Action: "TRANSFER",
			Payload: map[string]interface{}{
				"amount":    1200.00,
				"currency":  "USD",
				"recipient": "Insured_Customer",
				"claim_id":  "CLM-2026-990",
			},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_claims_director",
				"X-Sentinel-Intent-Mandate-ID": "mnd_flow_02",
				"X-Sentinel-Intent-Max-Amount": "1200.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Insured_Customer",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_claims_director", "TRANSFER", 1200.0, "USD", "Insured_Customer", "mnd_flow_02", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-FLOW-03", Phase: "3.2", Category: "Autonomous Commerce", Description: "Corporate invoice line-item payment strictly conforming to mandate",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{
				"amount":    2400.00,
				"currency":  "USD",
				"recipient": "Cloud_Host_Inc",
				"invoice":   "INV-9901-APR",
			},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_cfo_office",
				"X-Sentinel-Intent-Mandate-ID": "mnd_flow_03",
				"X-Sentinel-Intent-Max-Amount": "2500.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Cloud_Host_Inc",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_cfo_office", "TRANSFER", 2500.0, "USD", "Cloud_Host_Inc", "mnd_flow_03", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},

		// 10. Additional Deep Real-World Parameter & Edge Vectors (116 to 140)
		{
			ID: "TOCTOU-EDGE-01", Phase: "3.1", Category: "6to4 RFC 1918", Description: "IPv6 6to4 encapsulation embedding RFC 1918 Class A 10.0.0.1",
			VerifySocket: true, SocketTarget: "[2002:0a00:0001::]:80", ExpectedError: "6to4 encapsulation embeds restricted address",
		},
		{
			ID: "TOCTOU-EDGE-02", Phase: "3.1", Category: "6to4 RFC 1918", Description: "IPv6 6to4 encapsulation embedding RFC 1918 Class C 192.168.1.1",
			VerifySocket: true, SocketTarget: "[2002:c0a8:0101::]:80", ExpectedError: "6to4 encapsulation embeds restricted address",
		},
		{
			ID: "TOCTOU-EDGE-03", Phase: "3.1", Category: "6to4 RFC 1918", Description: "IPv6 6to4 encapsulation embedding RFC 1918 Class B 172.16.0.1",
			VerifySocket: true, SocketTarget: "[2002:ac10:0001::]:80", ExpectedError: "6to4 encapsulation embeds restricted address",
		},
		{
			ID: "TOCTOU-EDGE-04", Phase: "3.1", Category: "6to4 CGNAT", Description: "IPv6 6to4 encapsulation embedding CGNAT 100.64.0.1",
			VerifySocket: true, SocketTarget: "[2002:6440:0001::]:80", ExpectedError: "6to4 encapsulation embeds restricted address",
		},
		{
			ID: "TOCTOU-EDGE-05", Phase: "3.1", Category: "IP Encodings", Description: "Hexadecimal IP with uppercase prefix 0X7F000001",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "webhook": "http://0X7F000001/status"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "TOCTOU-EDGE-06", Phase: "3.1", Category: "IP Encodings", Description: "Mixed octal with multiple leading zeros 00177.0.0.1",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "webhook": "http://00177.0.0.1/debug"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "TOCTOU-EDGE-07", Phase: "3.1", Category: "IP Encodings", Description: "Octal representation for internal router 0300.0250.0000.0001 (192.168.0.1)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "webhook": "http://0300.0250.0000.0001/admin"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "TOCTOU-EDGE-08", Phase: "3.1", Category: "IP Encodings", Description: "Octal representation for Class A 0012.0000.0000.0001 (10.0.0.1)",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "webhook": "http://0012.0000.0000.0001/corp"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "TOCTOU-EDGE-09", Phase: "3.1", Category: "SSRF URL Variations", Description: "URL with embedded credentials pointing to metadata http://admin:secret@169.254.169.254/",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "webhook": "http://admin:secret@169.254.169.254/latest"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "TOCTOU-EDGE-10", Phase: "3.1", Category: "SSRF URL Variations", Description: "URL with port pointing to metadata http://169.254.169.254:8080/",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "webhook": "http://169.254.169.254:8080/meta"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "TOCTOU-EDGE-11", Phase: "3.1", Category: "SSRF URL Variations", Description: "URL with trailing dot in hostname http://169.254.169.254./",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "webhook": "http://169.254.169.254./meta"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "TOCTOU-EDGE-12", Phase: "3.1", Category: "SSRF Subnet", Description: "Carrier-Grade NAT network border host 100.64.1.1 in webhook payload",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "webhook": "http://100.64.1.1/cgnat"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "TOCTOU-EDGE-13", Phase: "3.1", Category: "SSRF Subnet", Description: "Documentation subnet TEST-NET-2 host 198.51.100.5 in webhook payload",
			AgentID: "ag_Travel_Bot", Action: "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "webhook": "http://198.51.100.5/testnet"},
			ExpectedStatus: http.StatusForbidden, ExpectedError: "GUARDRAIL_VIOLATION",
		},
		{
			ID: "AP2-EDGE-01", Phase: "3.2", Category: "Sub-Cent Edge", Description: "Floating-point minor precision: Authorized $99.99, attempted $99.991 (Sub-cent drift)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 99.991, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_edge_01",
				"X-Sentinel-Intent-Max-Amount": "99.99",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 99.99, "USD", "Rahul", "mnd_edge_01", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_AMOUNT_INFLATION",
		},
		{
			ID: "AP2-EDGE-02", Phase: "3.2", Category: "Precision Match", Description: "Floating-point exact representation: Authorized $99.99 == $99.99 executed",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 99.99, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_edge_02",
				"X-Sentinel-Intent-Max-Amount": "99.99",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 99.99, "USD", "Rahul", "mnd_edge_02", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-EDGE-03", Phase: "3.2", Category: "Zero-Dollar Auth", Description: "Zero-dollar mandate authorized $0.00, attempted $0.01 (Must block inflation)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 0.01, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_edge_03",
				"X-Sentinel-Intent-Max-Amount": "0.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 0.00, "USD", "Rahul", "mnd_edge_03", futureExpiry),
			},
			ExpectedStatus: http.StatusUnprocessableEntity, ExpectedError: "INTENT_AMOUNT_INFLATION",
		},
		{
			ID: "AP2-EDGE-04", Phase: "3.2", Category: "Zero-Dollar Auth", Description: "Zero-dollar authorization ($0.00 authorized == $0.00 executed for verification ping)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 0.00, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_edge_04",
				"X-Sentinel-Intent-Max-Amount": "0.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 0.00, "USD", "Rahul", "mnd_edge_04", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-EDGE-05", Phase: "3.2", Category: "Long Identifiers", Description: "128-character long mandate ID tracking (RFC compliant boundary test)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 100.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_edge_long_id_01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678",
				"X-Sentinel-Intent-Max-Amount": "100.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 100.0, "USD", "Rahul", "mnd_edge_long_id_01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-EDGE-06", Phase: "3.2", Category: "Whitespace Padding", Description: "Max-Amount with surrounding whitespace '  300.00  ' parsed cleanly",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_edge_06",
				"X-Sentinel-Intent-Max-Amount": "  300.00  ",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_edge_06", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-EDGE-07", Phase: "3.2", Category: "Long Expiry", Description: "Mandate with 30-day temporal validity window (enterprise recurring mandate)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_edge_07",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", now.Add(30*24*time.Hour).Unix()),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_edge_07", now.Add(30*24*time.Hour).Unix()),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-EDGE-08", Phase: "3.2", Category: "RFC3339 Timestamp", Description: "RFC3339 formatted expiry timestamp string in intent header",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 300.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_edge_08",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    now.Add(1 * time.Hour).Format(time.RFC3339),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_edge_08", now.Add(1*time.Hour).Unix()),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-EDGE-09", Phase: "3.2", Category: "Multi-Recipient Map", Description: "Deeply structured payment object with user_id recipient",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{
				"amount": 250.0, "currency": "USD", "user_id": "Rahul",
				"metadata": map[string]interface{}{"session": "sess_123", "step": 14},
			},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_edge_09",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_edge_09", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-EDGE-10", Phase: "3.2", Category: "Destination Account", Description: "Destination account alias match ('destination_account': 'Rahul')",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"amount": 100.0, "currency": "USD", "destination_account": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_edge_10",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_edge_10", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-EDGE-11", Phase: "3.2", Category: "Value Alias Match", Description: "Value alias financial amount matching ('value': 275.00)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"value": 275.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_edge_11",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_edge_11", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			ID: "AP2-EDGE-12", Phase: "3.2", Category: "Payout Alias Match", Description: "Payout alias financial amount matching ('payout': 290.00)",
			AgentID: "ag_Travel_Bot", Action: "TRANSFER",
			Payload: map[string]interface{}{"payout": 290.0, "currency": "USD", "recipient": "Rahul"},
			IntentHeaders: map[string]string{
				"X-Sentinel-Intent-Authorizer": "usr_alice_889",
				"X-Sentinel-Intent-Mandate-ID": "mnd_edge_12",
				"X-Sentinel-Intent-Max-Amount": "300.00",
				"X-Sentinel-Intent-Currency":   "USD",
				"X-Sentinel-Intent-Recipient":  "Rahul",
				"X-Sentinel-Intent-Expires":    fmt.Sprintf("%d", futureExpiry),
				"X-Sentinel-Intent-Commitment": genCommitment("usr_alice_889", "TRANSFER", 300.0, "USD", "Rahul", "mnd_edge_12", futureExpiry),
			},
			ExpectedStatus: http.StatusOK,
		},
	}

	totalScenarios := len(scenarios)
	passedAssertions := 0
	failedAssertions := 0

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("    SENTINEL PHASE 3 ENTERPRISE BENCHMARK: TOCTOU & GOOGLE AP2 AUDIT")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Auditing %d Comprehensive Tier-1 Enterprise Vectors...\n\n", totalScenarios)

	for i, sc := range scenarios {
		start := time.Now()

		// Case A: Socket-level Transport Check (Phase 3.1)
		if sc.VerifySocket {
			host, _, err := net.SplitHostPort(sc.SocketTarget)
			if err != nil {
				host = sc.SocketTarget
			}
			ip := net.ParseIP(strings.Trim(host, "[]"))

			isRestricted, reason := IsRestrictedOrPrivateIP(ip)
			elapsed := time.Since(start)

			if !isRestricted {
				t.Errorf("[FAIL] %s | %s - Target %s was NOT blocked by socket filter!", sc.ID, sc.Description, sc.SocketTarget)
				failedAssertions++
			} else if sc.ExpectedError != "" && !strings.Contains(strings.ToLower(reason), strings.ToLower(sc.ExpectedError)) {
				t.Errorf("[FAIL] %s | %s - Expected reason containing %q, got %q", sc.ID, sc.Description, sc.ExpectedError, reason)
				failedAssertions++
			} else {
				fmt.Printf("[PASS] %-12s | Phase %s | %-18s | Socket Blocked: %s (%v)\n",
					sc.ID, sc.Phase, sc.Category, reason, elapsed)
				passedAssertions++
			}
			continue
		}

		// Case B: Gateway HTTP Handshake Check (Phase 3.1 & Phase 3.2)
		reqBody := AgentRequest{
			AgentID: sc.AgentID,
			Action:  sc.Action,
			Payload: sc.Payload,
		}
		rawBytes, _ := json.Marshal(reqBody)

		httpReq, _ := http.NewRequest(http.MethodPost, "/enforce", bytes.NewBuffer(rawBytes))
		httpReq.Header.Set("Content-Type", "application/json")

		// Apply standard cryptographic KYA signature
		nonce := fmt.Sprintf("phase3_test_nonce_%04d_%d", i, time.Now().UnixNano())
		sig, tsStr := signPhase3Request(sc.AgentID, string(rawBytes), nonce, time.Now())
		httpReq.Header.Set("X-Sentinel-Agent-ID", sc.AgentID)
		httpReq.Header.Set("X-Sentinel-Signature", sig)
		httpReq.Header.Set("X-Sentinel-Timestamp", tsStr)
		httpReq.Header.Set("X-Sentinel-Nonce", nonce)

		// Apply Google AP2 Intent Mandate Headers
		for k, v := range sc.IntentHeaders {
			httpReq.Header.Set(k, v)
		}

		rr := httptest.NewRecorder()
		enforceHandler(rr, httpReq)
		elapsed := time.Since(start)

		if rr.Code != sc.ExpectedStatus {
			t.Errorf("[FAIL] %s | %s - Expected HTTP %d, got %d. Body: %s",
				sc.ID, sc.Description, sc.ExpectedStatus, rr.Code, rr.Body.String())
			failedAssertions++
		} else if sc.ExpectedError != "" && !strings.Contains(strings.ToLower(rr.Body.String()), strings.ToLower(sc.ExpectedError)) {
			t.Errorf("[FAIL] %s | %s - Expected error containing %q, got: %s",
				sc.ID, sc.Description, sc.ExpectedError, rr.Body.String())
			failedAssertions++
		} else {
			fmt.Printf("[PASS] %-12s | Phase %s | %-18s | Status: %d (Exp: %d) | %s (%v)\n",
				sc.ID, sc.Phase, sc.Category, rr.Code, sc.ExpectedStatus, sc.Description, elapsed)
			passedAssertions++
		}
	}

	fmt.Println("\n" + strings.Repeat("-", 80))
	fmt.Println("              PHASE 3.1 & 3.2 BENCHMARK VERIFICATION REPORT             ")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("Total Evaluated Scenarios : %d\n", totalScenarios)
	fmt.Printf("Total Passed Assertions   : %d\n", passedAssertions)
	fmt.Printf("Total Failed Assertions   : %d\n", failedAssertions)
	accuracy := float64(passedAssertions) / float64(totalScenarios) * 100.0
	fmt.Printf("Verification Accuracy     : %.2f%%\n", accuracy)
	fmt.Println(strings.Repeat("=", 80))

	if failedAssertions > 0 {
		t.Fatalf("Phase 3 Enterprise Benchmark failed with %d assertion failures", failedAssertions)
	}
}
