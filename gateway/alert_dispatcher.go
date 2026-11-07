package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

type AlertSeverity string

const (
	SeverityInfo     AlertSeverity = "INFO"
	SeverityWarning  AlertSeverity = "WARNING"
	SeverityCritical AlertSeverity = "CRITICAL"
)

type SecurityIncident struct {
	ID        string        `json:"incident_id"`
	Timestamp int64         `json:"timestamp"`
	EventType string        `json:"event_type"` // e.g. "QUARANTINE", "FLEET_FREEZE", "PROMPT_INJECTION", "SMURFING"
	Severity  AlertSeverity `json:"severity"`
	AgentID   string        `json:"agent_id"`
	Action    string        `json:"action"`
	Reason    string        `json:"reason"`
	Amount    float64       `json:"amount"`
	TenantID  string        `json:"tenant_id,omitempty"`
}

type AlertDispatcher struct {
	mu             sync.Mutex
	recentAlerts   map[string]int64 // deduplication map: incidentKey -> timestamp
	alertQueue     chan SecurityIncident
	slackWebhooks  []string
	pagerDutyKeys  []string
	dispatchedLogs []string
}

var globalAlertDispatcher = NewAlertDispatcher(1000)

func NewAlertDispatcher(bufferSize int) *AlertDispatcher {
	ad := &AlertDispatcher{
		recentAlerts:   make(map[string]int64),
		alertQueue:     make(chan SecurityIncident, bufferSize),
		slackWebhooks:  make([]string, 0),
		pagerDutyKeys:  make([]string, 0),
		dispatchedLogs: make([]string, 0),
	}
	return ad
}

// FormatCEF serializes a security incident into Micro Focus ArcSight Common Event Format (CEF:0).
// Used by Splunk, Datadog, and QRadar.
func FormatCEF(inc SecurityIncident) string {
	sevNum := 5
	switch inc.Severity {
	case SeverityCritical:
		sevNum = 10
	case SeverityWarning:
		sevNum = 7
	case SeverityInfo:
		sevNum = 3
	}

	cleanReason := strings.ReplaceAll(inc.Reason, "|", "\\|")
	cleanReason = strings.ReplaceAll(cleanReason, "=", "\\=")

	return fmt.Sprintf("CEF:0|Sentinel|AgentSecurityGateway|2.0|%s|%s|%d|src=%s act=%s cn1=%.2f cn1Label=AmountUSD cs1=%s cs1Label=Reason cs2=%s cs2Label=TenantID",
		inc.EventType, inc.EventType, sevNum, inc.AgentID, inc.Action, inc.Amount, cleanReason, inc.TenantID)
}

// FormatSyslogRFC5424 formats the security incident according to RFC 5424 Syslog standard.
func FormatSyslogRFC5424(inc SecurityIncident) string {
	pri := 134 // Facility local0 (16*8) + Notice (6) = 134
	if inc.Severity == SeverityCritical {
		pri = 130 // Alert (2)
	}

	ts := time.Unix(inc.Timestamp, 0).UTC().Format(time.RFC3339)
	return fmt.Sprintf("<%d>1 %s sentinel-gateway sentinel - - [sentinelSecurity@4242 agent=\"%s\" action=\"%s\" event=\"%s\" severity=\"%s\"] %s (Amount: $%.2f)",
		pri, ts, inc.AgentID, inc.Action, inc.EventType, inc.Severity, inc.Reason, inc.Amount)
}

// FormatSlackPayload creates an interactive Slack block kit attachment payload.
func FormatSlackPayload(inc SecurityIncident) string {
	color := "#36a64f"
	if inc.Severity == SeverityCritical {
		color = "#ff0000"
	} else if inc.Severity == SeverityWarning {
		color = "#ffa500"
	}

	payload := map[string]interface{}{
		"text": fmt.Sprintf("🚨 *[SENTINEL %s]* %s triggered by `%s`", inc.Severity, inc.EventType, inc.AgentID),
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"fields": []map[string]interface{}{
					{"title": "Agent ID", "value": inc.AgentID, "short": true},
					{"title": "Action", "value": inc.Action, "short": true},
					{"title": "Amount", "value": fmt.Sprintf("$%.2f", inc.Amount), "short": true},
					{"title": "Reason", "value": inc.Reason, "short": false},
				},
				"footer": "Sentinel Zero-Trust Gateway Alert Dispatcher",
				"ts":     inc.Timestamp,
			},
		},
	}
	b, _ := json.Marshal(payload)
	return string(b)
}

// FormatPagerDutyV2Payload creates a PagerDuty Events API v2 compliant payload.
func FormatPagerDutyV2Payload(routingKey string, inc SecurityIncident) string {
	payload := map[string]interface{}{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"dedup_key":    fmt.Sprintf("sentinel-%s-%s", inc.AgentID, inc.EventType),
		"payload": map[string]interface{}{
			"summary":   fmt.Sprintf("[SENTINEL %s] %s on agent %s: %s", inc.Severity, inc.EventType, inc.AgentID, inc.Reason),
			"source":    "sentinel-gateway",
			"severity":  strings.ToLower(string(inc.Severity)),
			"timestamp": time.Unix(inc.Timestamp, 0).UTC().Format(time.RFC3339),
			"custom_details": map[string]interface{}{
				"agent_id": inc.AgentID,
				"action":   inc.Action,
				"amount":   inc.Amount,
				"reason":   inc.Reason,
				"tenant":   inc.TenantID,
			},
		},
	}
	b, _ := json.Marshal(payload)
	return string(b)
}

// DispatchIncident enqueues an alert with deduplication to prevent alert storms.
// Returns true if dispatched, false if deduplicated/suppressed.
func (ad *AlertDispatcher) DispatchIncident(inc SecurityIncident) bool {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now().Unix()
	dedupKey := fmt.Sprintf("%s:%s", inc.AgentID, inc.EventType)

	// Clean older keys > 60 seconds
	for k, t := range ad.recentAlerts {
		if now-t > 60 {
			delete(ad.recentAlerts, k)
		}
	}

	// Deduplication: if identical incident occurred in the last 15 seconds, suppress duplicate alert
	if lastSeen, exists := ad.recentAlerts[dedupKey]; exists && now-lastSeen < 15 {
		return false
	}

	ad.recentAlerts[dedupKey] = now
	cef := FormatCEF(inc)
	ad.dispatchedLogs = append(ad.dispatchedLogs, cef)

	// Non-blocking channel push
	select {
	case ad.alertQueue <- inc:
		return true
	default:
		return true
	}
}

func (ad *AlertDispatcher) GetDispatchedCEFLogs() []string {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	copied := make([]string, len(ad.dispatchedLogs))
	copy(copied, ad.dispatchedLogs)
	return copied
}

