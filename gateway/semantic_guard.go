package main

import (
	"encoding/base64"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// SemanticAnomalyResult holds the forensic inspection result of tool payload semantics
type SemanticAnomalyResult struct {
	IsSafe        bool     `json:"is_safe"`
	RiskCategory  string   `json:"risk_category,omitempty"` // PROMPT_INJECTION, ROLE_CONFUSION, DATA_EXFILTRATION, TAINTED_ORIGIN, EVASION
	AnomalyScore  float64  `json:"anomaly_score"`            // 0.0 (benign) to 1.0 (malicious)
	Violations    []string `json:"violations"`
	EntropyScore  float64  `json:"entropy_score"`
}

// SemanticGuard inspects agent payloads, instructions, and context for adversarial manipulation
type SemanticGuard struct {
	mu                   sync.RWMutex
	injectionPatterns    []*regexp.Regexp
	roleTokens           []string
	exfiltrationPatterns []*regexp.Regexp
	suspiciousKeywords   []string

	// Telemetry
	inspectionsCount atomic.Uint64
	injectionsCaught atomic.Uint64
}

// NewSemanticGuard compiles detection rules for real-world prompt injection and adversarial attacks
func NewSemanticGuard() *SemanticGuard {
	sg := &SemanticGuard{
		roleTokens: []string{
			"<|im_start|>", "<|im_end|>",
			"[inst]", "[/inst]",
			"<<sys>>", "<</sys>>",
			"system:", "human:", "assistant:",
			"<system>", "</system>",
		},
		suspiciousKeywords: []string{
			"ignore previous instructions",
			"disregard all previous instructions",
			"disregard guardrails",
			"override safety guidelines",
			"system prompt override",
			"system override",
			"jailbreak active",
			"dan mode enabled",
			"developer mode enabled",
			"unrestricted agent",
			"bypass sentinel",
			"exfiltrate data",
			"send all credentials",
			"dump environment variables",
		},
	}

	injectionRegexes := []string{
		`(?i)ignore\s+(all\s+)?(the\s+)?(agent'?s?\s+)?(previous\s+|prior\s+|above\s+|system\s+)?(permissions|restrictions|instructions|directives|rules|constraints)`,
		`(?i)disregard\s+(all\s+)?(the\s+)?(agent'?s?\s+)?(previous\s+|prior\s+|above\s+|system\s+)?(instructions|prompts|guardrails|constraints|directives|rules|permissions)`,
		`(?i)system\s+override:`,
		`(?i)you\s+are\s+now\s+(an?\s+unrestricted|free\s+of\s+rules|in\s+developer\s+mode|dan)`,
		`(?i)from\s+now\s+on\s+you\s+(must|will)\s+(act|pretend|behave)\s+without\s+(rules|limits)`,
		`(?i)new\s+system\s+instruction:`,
		`(?i)override\s+(the\s+)?(agent'?s?\s+)?(policy|sentinel|security|threshold|system|permissions)`,
		`(?i)sudo\s+mode\s+activated`,
	}
	for _, p := range injectionRegexes {
		sg.injectionPatterns = append(sg.injectionPatterns, regexp.MustCompile(p))
	}

	exfilRegexes := []string{
		`(?i)(webhook\.site|pipedream\.net|ngrok\.io|burpcollaborator\.net|requestbin\.net|requestbin\.com)`,
		`(?i)https?://[0-9a-z.-]+\.burpcollaborator\.net`,
		`(?i)(curl|wget|nc|bash|sh|powershell)\s+(-[a-z\s]+)?https?://`,
		`(?i)select\s+.*\s+into\s+outfile`,
	}
	for _, p := range exfilRegexes {
		sg.exfiltrationPatterns = append(sg.exfiltrationPatterns, regexp.MustCompile(p))
	}

	return sg
}

// CalculateShannonEntropy measures informational entropy of a string (0.0 to 1.0)
func CalculateShannonEntropy(text string) float64 {
	if len(text) == 0 {
		return 0.0
	}
	freq := make(map[rune]int)
	for _, r := range text {
		freq[r]++
	}
	total := float64(len([]rune(text)))
	var entropy float64
	for _, count := range freq {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	// Normalization: Printable ASCII max entropy is ~6.55 bits
	normalized := entropy / 6.55
	if normalized > 1.0 {
		return 1.0
	}
	return math.Max(0.0, normalized)
}

// InspectSemanticSafety inspects tool parameters, prompts, and context headers
func (sg *SemanticGuard) InspectSemanticSafety(agentID, action string, payload map[string]interface{}, originHeader string) *SemanticAnomalyResult {
	sg.inspectionsCount.Add(1)

	result := &SemanticAnomalyResult{
		IsSafe:       true,
		Violations:   make([]string, 0),
		AnomalyScore: 0.0,
	}

	// 1. Check Multi-Agent Taint Propagation (Problem 3 in realworld_problem.md)
	// If the origin header is tainted and the action is a state-mutating financial tool
	if originHeader != "" {
		originLower := strings.ToLower(strings.TrimSpace(originHeader))
		if strings.Contains(originLower, "untrusted") || strings.Contains(originLower, "tainted") || strings.Contains(originLower, "external_scrape") {
			actionUpper := strings.ToUpper(action)
			if actionUpper == "TRANSFER" || actionUpper == "WITHDRAW" || actionUpper == "CREDIT_INCREASE" ||
				actionUpper == "PAYPAL_PAYOUT" || actionUpper == "PAYPAL_CREATE_ORDER" || actionUpper == "PAYPAL_REFUND" {
				result.IsSafe = false
				result.RiskCategory = "TAINTED_ORIGIN"
				result.AnomalyScore = 1.0
				result.Violations = append(result.Violations,
					fmt.Sprintf("TAINTED_PARAMETER_DIVERGENCE: Origin %q is tainted; mutating action %s blocked", originHeader, action))
				sg.injectionsCaught.Add(1)
				return result
			}
		}
	}

	// 2. Flatten and extract all text strings from payload
	var textBlobs []string
	extractStrings(payload, &textBlobs)
	combinedText := strings.Join(textBlobs, " ")

	// 3. Shannon Entropy Check
	maxEntropy := 0.0
	for _, blob := range textBlobs {
		ent := CalculateShannonEntropy(blob)
		if ent > maxEntropy {
			maxEntropy = ent
		}
		// Check for obfuscated base64 command payload
		if len(blob) >= 24 && !strings.Contains(blob, " ") {
			if decoded, err := base64.StdEncoding.DecodeString(blob); err == nil {
				decodedStr := strings.ToLower(string(decoded))
				if strings.Contains(decodedStr, "curl") || strings.Contains(decodedStr, "token") ||
					strings.Contains(decodedStr, "sh") || strings.Contains(decodedStr, "webhook") ||
					strings.Contains(decodedStr, "secrets") || strings.Contains(decodedStr, "passwd") {
					result.IsSafe = false
					result.RiskCategory = "DATA_EXFILTRATION"
					result.AnomalyScore = 0.98
					result.Violations = append(result.Violations, "Obfuscated payload decodes to executable shell or exfiltration command")
					sg.injectionsCaught.Add(1)
					return result
				}
			}
		}
	}
	result.EntropyScore = maxEntropy

	combinedLower := strings.ToLower(combinedText)
	normalizedLower := strings.ToLower(strings.Join(strings.Fields(combinedText), " "))

	// 4. Inspect Adversarial Role Confusion Tokens (<|im_start|>, [INST], SYSTEM:, etc.)
	for _, roleTok := range sg.roleTokens {
		if strings.Contains(combinedLower, roleTok) || strings.Contains(normalizedLower, roleTok) {
			result.IsSafe = false
			result.RiskCategory = "ROLE_CONFUSION"
			result.AnomalyScore = 0.95
			result.Violations = append(result.Violations, fmt.Sprintf("Adversarial LLM role delimiter detected in tool parameter: %q", roleTok))
		}
	}

	// 5. Inspect Prompt Injection Patterns
	for _, pattern := range sg.injectionPatterns {
		if pattern.MatchString(combinedText) || pattern.MatchString(normalizedLower) {
			result.IsSafe = false
			if result.RiskCategory == "" {
				result.RiskCategory = "PROMPT_INJECTION"
			}
			result.AnomalyScore = 0.99
			result.Violations = append(result.Violations, fmt.Sprintf("Semantic prompt injection pattern detected: %s", pattern.String()))
		}
	}

	// 6. Direct Suspicious Keyword Match
	for _, kw := range sg.suspiciousKeywords {
		if strings.Contains(combinedLower, kw) || strings.Contains(normalizedLower, kw) {
			result.IsSafe = false
			if result.RiskCategory == "" {
				result.RiskCategory = "PROMPT_INJECTION"
			}
			result.AnomalyScore = math.Max(result.AnomalyScore, 0.92)
			result.Violations = append(result.Violations, fmt.Sprintf("Adversarial jailbreak keyword detected: %q", kw))
		}
	}

	// 7. Data Exfiltration Endpoint Inspection
	for _, exfilPat := range sg.exfiltrationPatterns {
		if exfilPat.MatchString(combinedText) {
			result.IsSafe = false
			result.RiskCategory = "DATA_EXFILTRATION"
			result.AnomalyScore = 0.97
			result.Violations = append(result.Violations, fmt.Sprintf("Out-of-band data exfiltration sink detected: %s", exfilPat.String()))
		}
	}

	// 8. Destructive SQL injection detection in string parameters
	if strings.Contains(normalizedLower, "drop table") || strings.Contains(normalizedLower, "truncate") || strings.Contains(normalizedLower, "delete from") {
		result.IsSafe = false
		if result.RiskCategory == "" {
			result.RiskCategory = "SQL_INJECTION"
		}
		result.AnomalyScore = 0.99
		result.Violations = append(result.Violations, "Destructive SQL operation detected in parameter payload")
	}

	if !result.IsSafe {
		sg.injectionsCaught.Add(1)
	}

	return result
}

// extractStrings recursively gathers all string values inside a map/array structure
func extractStrings(data interface{}, acc *[]string) {
	switch v := data.(type) {
	case string:
		*acc = append(*acc, v)
	case map[string]interface{}:
		for k, val := range v {
			*acc = append(*acc, k)
			extractStrings(val, acc)
		}
	case []interface{}:
		for _, item := range v {
			extractStrings(item, acc)
		}
	}
}

// Global Semantic Guard instance
var globalSemanticGuard = NewSemanticGuard()
