package main

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PolicyDecision encapsulates an in-process evaluation result with audit citations
type PolicyDecision struct {
	Decision   string   `json:"decision"` // ALLOW or DENY
	Reason     string   `json:"reason"`
	RiskScore  float64  `json:"risk_score"`  // 0.0 to 1.0
	Confidence float64  `json:"confidence"`  // 0.0 to 1.0
	LatencyNs  int64    `json:"latency_ns"`
	InProcess  bool     `json:"in_process"`
	Citations  []string `json:"citations"`
}

// PrecedentRule defines an in-process precedent boundary
type PrecedentRule struct {
	Action      string
	MaxAmount   float64
	AllowedCurrencies []string
	RiskWeight  float64
	RequiresMandate bool
	DefaultDecision string
}

// CircuitState represents the state of the external engine circuit breaker
type CircuitState int

const (
	StateClosed CircuitState = iota // Normal: Try external Python
	StateHalfOpen                   // Probing: Test single request
	StateOpen                       // Tripped: Bypass external Python, use in-process engine
)

func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateHalfOpen:
		return "HALF_OPEN"
	case StateOpen:
		return "OPEN"
	default:
		return "UNKNOWN"
	}
}

// EngineCircuitBreaker protects against external Python latency cliffs
type EngineCircuitBreaker struct {
	mu             sync.RWMutex
	state          CircuitState
	consecutiveFails int
	failThreshold  int
	latencyThreshold time.Duration
	recoveryTimeout  time.Duration
	lastStateChange time.Time

	// Telemetry
	tripsCount     atomic.Uint64
	fallbacksCount atomic.Uint64
}

// NewEngineCircuitBreaker constructs an adaptive circuit breaker
func NewEngineCircuitBreaker(failThreshold int, latencyThreshold, recoveryTimeout time.Duration) *EngineCircuitBreaker {
	if failThreshold <= 0 {
		failThreshold = 3
	}
	if latencyThreshold <= 0 {
		latencyThreshold = 100 * time.Millisecond
	}
	if recoveryTimeout <= 0 {
		recoveryTimeout = 5 * time.Second
	}
	return &EngineCircuitBreaker{
		state:            StateClosed,
		failThreshold:    failThreshold,
		latencyThreshold: latencyThreshold,
		recoveryTimeout:  recoveryTimeout,
		lastStateChange:  time.Now(),
	}
}

// ShouldTryExternal returns true if the request should attempt external Python evaluation
func (cb *EngineCircuitBreaker) ShouldTryExternal() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()
	if cb.state == StateOpen {
		if now.Sub(cb.lastStateChange) >= cb.recoveryTimeout {
			cb.state = StateHalfOpen
			cb.lastStateChange = now
			return true
		}
		return false
	}
	return true
}

// RecordSuccess marks a successful external call
func (cb *EngineCircuitBreaker) RecordSuccess(latency time.Duration) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if latency > cb.latencyThreshold {
		cb.consecutiveFails++
		if cb.consecutiveFails >= cb.failThreshold {
			cb.tripOpen()
		}
		return
	}

	cb.consecutiveFails = 0
	if cb.state == StateHalfOpen {
		cb.state = StateClosed
		cb.lastStateChange = time.Now()
	}
}

// RecordFailure marks a failed or timed-out external call
func (cb *EngineCircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveFails++
	if cb.state == StateHalfOpen || cb.consecutiveFails >= cb.failThreshold {
		cb.tripOpen()
	}
}

func (cb *EngineCircuitBreaker) tripOpen() {
	cb.state = StateOpen
	cb.lastStateChange = time.Now()
	cb.tripsCount.Add(1)
}

// Reset resets the circuit breaker to closed state
func (cb *EngineCircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = StateClosed
	cb.consecutiveFails = 0
	cb.lastStateChange = time.Now()
}

// GetState returns current circuit state
func (cb *EngineCircuitBreaker) GetState() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// InProcessPolicyEngine executes microsecond edge precedent evaluation
type InProcessPolicyEngine struct {
	mu         sync.RWMutex
	rules      map[string]PrecedentRule
	trustBudget map[string]float64 // agent_id -> trust % (0..100)
	cb         *EngineCircuitBreaker

	// Telemetry
	evalCount     atomic.Uint64
	evalLatencyNs atomic.Int64
}

// NewInProcessPolicyEngine creates an edge-native policy engine
func NewInProcessPolicyEngine() *InProcessPolicyEngine {
	engine := &InProcessPolicyEngine{
		rules:       make(map[string]PrecedentRule),
		trustBudget: make(map[string]float64),
		cb:          NewEngineCircuitBreaker(3, 100*time.Millisecond, 5*time.Second),
	}

	// Default enterprise precedent baselines
	engine.rules["TRANSFER"] = PrecedentRule{
		Action:            "TRANSFER",
		MaxAmount:         25000.0,
		AllowedCurrencies: []string{"USD", "EUR", "GBP", "INR"},
		RiskWeight:        0.8,
		RequiresMandate:   true,
		DefaultDecision:   "ALLOW",
	}
	engine.rules["ISSUE_REFUND"] = PrecedentRule{
		Action:            "ISSUE_REFUND",
		MaxAmount:         5000.0,
		AllowedCurrencies: []string{"USD", "EUR", "GBP", "INR"},
		RiskWeight:        0.5,
		RequiresMandate:   false,
		DefaultDecision:   "ALLOW",
	}
	engine.rules["REFUND"] = engine.rules["ISSUE_REFUND"]
	engine.rules["LOCK_CARD"] = PrecedentRule{
		Action:            "LOCK_CARD",
		MaxAmount:         0.0,
		AllowedCurrencies: []string{},
		RiskWeight:        0.3,
		RequiresMandate:   false,
		DefaultDecision:   "ALLOW",
	}
	engine.rules["LOGIN"] = PrecedentRule{
		Action:            "LOGIN",
		MaxAmount:         0.0,
		AllowedCurrencies: []string{},
		RiskWeight:        0.1,
		RequiresMandate:   false,
		DefaultDecision:   "ALLOW",
	}
	engine.rules["WITHDRAW"] = PrecedentRule{
		Action:            "WITHDRAW",
		MaxAmount:         10000.0,
		AllowedCurrencies: []string{"USD", "EUR"},
		RiskWeight:        0.9,
		RequiresMandate:   true,
		DefaultDecision:   "ALLOW",
	}
	engine.rules["CREDIT_INCREASE"] = PrecedentRule{
		Action:            "CREDIT_INCREASE",
		MaxAmount:         50000.0,
		AllowedCurrencies: []string{"USD", "EUR", "GBP", "INR"},
		RiskWeight:        0.7,
		RequiresMandate:   false,
		DefaultDecision:   "ALLOW",
	}
	engine.rules["QUERY_DATABASE"] = PrecedentRule{
		Action:            "QUERY_DATABASE",
		MaxAmount:         0.0,
		AllowedCurrencies: []string{},
		RiskWeight:        0.2,
		RequiresMandate:   false,
		DefaultDecision:   "ALLOW",
	}

	return engine
}

// SetAgentTrust records or adjusts an agent's trust economy score (0..100)
func (ipe *InProcessPolicyEngine) SetAgentTrust(agentID string, score float64) {
	ipe.mu.Lock()
	defer ipe.mu.Unlock()
	ipe.trustBudget[agentID] = math.Max(0.0, math.Min(100.0, score))
}

// GetAgentTrust returns the current trust score, defaulting to 100.0
func (ipe *InProcessPolicyEngine) GetAgentTrust(agentID string) float64 {
	ipe.mu.RLock()
	defer ipe.mu.RUnlock()
	score, exists := ipe.trustBudget[agentID]
	if !exists {
		return 100.0
	}
	return score
}

// Evaluate evaluates an agent request in-process in < 10 microseconds
func (ipe *InProcessPolicyEngine) Evaluate(ctx context.Context, agentID, action string, payload map[string]interface{}) PolicyDecision {
	start := time.Now()
	ipe.evalCount.Add(1)

	actionUpper := strings.ToUpper(strings.TrimSpace(action))

	// 1. Trust Economy Check (< 20.0 = quarantined)
	trust := ipe.GetAgentTrust(agentID)
	if trust <= 20.0 {
		elapsed := time.Since(start).Nanoseconds()
		ipe.evalLatencyNs.Store(elapsed)
		return PolicyDecision{
			Decision:   "DENY",
			Reason:     fmt.Sprintf("Agent %s quarantined by Trust Economy (Trust score %.1f%% <= 20.0%%)", agentID, trust),
			RiskScore:  1.0,
			Confidence: 0.99,
			LatencyNs:  elapsed,
			InProcess:  true,
			Citations:  []string{"PRECEDENT_QUARANTINE_01"},
		}
	}

	// 2. Check rule precedent mapping
	ipe.mu.RLock()
	rule, exists := ipe.rules[actionUpper]
	ipe.mu.RUnlock()

	if !exists {
		elapsed := time.Since(start).Nanoseconds()
		ipe.evalLatencyNs.Store(elapsed)
		return PolicyDecision{
			Decision:   "DENY",
			Reason:     fmt.Sprintf("Action %s has no legal precedent or policy rule in case law catalog", action),
			RiskScore:  0.95,
			Confidence: 0.90,
			LatencyNs:  elapsed,
			InProcess:  true,
			Citations:  []string{"PRECEDENT_UNKNOWN_ACTION"},
		}
	}

	// 3. Amount & Currency Bounds Check
	hasAmt, amt, _ := extractNativeFinancialAmount(payload)
	if hasAmt {
		if amt > rule.MaxAmount {
			elapsed := time.Since(start).Nanoseconds()
			ipe.evalLatencyNs.Store(elapsed)
			return PolicyDecision{
				Decision:   "DENY",
				Reason:     fmt.Sprintf("Amount $%.2f exceeds legal precedent ceiling of $%.2f for action %s", amt, rule.MaxAmount, action),
				RiskScore:  rule.RiskWeight,
				Confidence: 0.98,
				LatencyNs:  elapsed,
				InProcess:  true,
				Citations:  []string{"PRECEDENT_CEILING_EXCEEDED"},
			}
		}

		curr := extractRawCurrency(payload)
		if curr != "" && len(rule.AllowedCurrencies) > 0 {
			allowed := false
			for _, ac := range rule.AllowedCurrencies {
				if strings.EqualFold(ac, curr) {
					allowed = true
					break
				}
			}
			if !allowed {
				elapsed := time.Since(start).Nanoseconds()
				ipe.evalLatencyNs.Store(elapsed)
				return PolicyDecision{
					Decision:   "DENY",
					Reason:     fmt.Sprintf("Currency %s is not permitted under precedent for action %s", curr, action),
					RiskScore:  rule.RiskWeight,
					Confidence: 0.95,
					LatencyNs:  elapsed,
					InProcess:  true,
					Citations:  []string{"PRECEDENT_CURRENCY_RESTRICTED"},
				}
			}
		}
	}

	elapsed := time.Since(start).Nanoseconds()
	ipe.evalLatencyNs.Store(elapsed)
	return PolicyDecision{
		Decision:   rule.DefaultDecision,
		Reason:     fmt.Sprintf("Transaction matches authorized precedent baseline for %s (Risk: %.2f)", action, rule.RiskWeight),
		RiskScore:  rule.RiskWeight,
		Confidence: 0.96,
		LatencyNs:  elapsed,
		InProcess:  true,
		Citations:  []string{fmt.Sprintf("PRECEDENT_%s_BASELINE", actionUpper)},
	}
}

// Global In-Process Policy Engine instance
var globalInProcessEngine = NewInProcessPolicyEngine()
