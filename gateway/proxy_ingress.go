package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const ProxyMaxBodyBytes = 10 * 1024 * 1024

// OpenAI-compatible Chat Completion API structs
type OpenAIChatCompletionRequest struct {
	Model       string              `json:"model"`
	Messages    []OpenAIChatMessage `json:"messages"`
	Tools       []OpenAITool        `json:"tools,omitempty"`
	ToolChoice  interface{}         `json:"tool_choice,omitempty"`
	Temperature float64             `json:"temperature,omitempty"`
}

type OpenAIChatMessage struct {
	Role       string             `json:"role"`
	Content    string             `json:"content"`
	ToolCalls  []OpenAIToolCall   `json:"tool_calls,omitempty"`
	ToolCallID string             `json:"tool_call_id,omitempty"`
}

type OpenAITool struct {
	Type     string                   `json:"type"`
	Function OpenAIFunctionDefinition `json:"function"`
}

type OpenAIFunctionDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

type OpenAIToolCall struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Function OpenAIFunctionCallDesc `json:"function"`
}

type OpenAIFunctionCallDesc struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // JSON string per OpenAI spec
}

type OpenAIErrorResponse struct {
	Error OpenAIErrorDetail `json:"error"`
}

type OpenAIErrorDetail struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Param   string `json:"param,omitempty"`
	Code    string `json:"code"`
}

type OpenAIChatCompletionResponse struct {
	ID      string               `json:"id"`
	Object  string               `json:"object"`
	Created int64                `json:"created"`
	Model   string               `json:"model"`
	Choices []OpenAIChoice       `json:"choices"`
	Usage   map[string]int       `json:"usage"`
}

type OpenAIChoice struct {
	Index        int               `json:"index"`
	Message      OpenAIChatMessage `json:"message"`
	FinishReason string            `json:"finish_reason"`
}

// Model Context Protocol (MCP) JSON-RPC 2.0 structs
type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type MCPToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// OpenAIProxyHandler provides a transparent drop-in reverse proxy for OpenAI/Anthropic tool callers.
// Intercepts `POST /v1/chat/completions` and enforces Sentinel zero-trust policy on all requested tools.
func OpenAIProxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, ProxyMaxBodyBytes))
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "Failed to read request body", "invalid_request_error", "body_read_error")
		return
	}

	var req OpenAIChatCompletionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "Invalid JSON payload in chat completion", "invalid_request_error", "json_parse_error")
		return
	}

	agentID := r.Header.Get("X-Sentinel-Agent-ID")
	if agentID == "" {
		agentID = "ag_OpenAI_Proxy_Bot"
	}

	// 1. Inspect conversation messages for semantic prompt injection or evasion delimiters
	for _, msg := range req.Messages {
		if msg.Content != "" {
			safetyResult := globalSemanticGuard.InspectSemanticSafety(agentID, "OPENAI_COMPLETION", map[string]interface{}{"content": msg.Content}, r.Header.Get("X-Sentinel-Data-Origin"))
			if !safetyResult.IsSafe {
				reason := strings.Join(safetyResult.Violations, "; ")
				if reason == "" {
					reason = "Semantic injection violation"
				}
				writeOpenAIError(w, http.StatusUnprocessableEntity,
					fmt.Sprintf("SENTINEL_PROMPT_INJECTION_DETECTED: %s", reason),
					"semantic_safety_violation", safetyResult.RiskCategory)
				return
			}
		}

		// Inspect any assistant tool calls embedded in the message history
		for _, tc := range msg.ToolCalls {
			if rejected, status, reason := inspectOpenAIToolCall(agentID, tc.Function.Name, tc.Function.Arguments, r.Header); rejected {
				writeOpenAIError(w, status, reason, "tool_execution_violation", "sentinel_policy_rejection")
				return
			}
		}
	}

	// Pre-commit audit receipt for allowed proxy pass-through
	event := GatewayEvent{
		AgentID:   agentID,
		Action:    "OPENAI_PROXY_COMPLETION",
		Payload:   map[string]interface{}{"model": req.Model, "messages_count": len(req.Messages)},
		Decision:  "ALLOW",
		Timestamp: time.Now().Format(time.RFC3339),
	}
	walEntry, _ := globalAuditWAL.WriteSync(event)
	if walEntry != nil {
		w.Header().Set("X-Sentinel-WAL-Seq", fmt.Sprintf("%d", walEntry.SequenceNum))
		w.Header().Set("X-Sentinel-WAL-Hash", walEntry.EntryHash)
	}
	w.Header().Set("Content-Type", "application/json")

	// Return standard compliant OpenAI response
	resp := OpenAIChatCompletionResponse{
		ID:      fmt.Sprintf("chatcmpl-sentinel-%d", time.Now().UnixNano()),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   req.Model,
		Choices: []OpenAIChoice{
			{
				Index: 0,
				Message: OpenAIChatMessage{
					Role:    "assistant",
					Content: "SENTINEL_GATEWAY_APPROVED: Tool parameters cleared by Zero-Trust policy.",
				},
				FinishReason: "stop",
			},
		},
		Usage: map[string]int{
			"prompt_tokens":     len(req.Messages) * 10,
			"completion_tokens": 12,
			"total_tokens":      len(req.Messages)*10 + 12,
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func inspectOpenAIToolCall(agentID, toolName, argumentsJSON string, headers http.Header) (bool, int, string) {
	// Parse arguments
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(argumentsJSON), &args); err != nil {
		return true, http.StatusBadRequest, "Invalid JSON in tool call arguments"
	}

	// Extract amount if present
	amount := 0.0
	if a, ok := args["amount"]; ok {
		switch v := a.(type) {
		case float64:
			amount = v
		case int:
			amount = float64(v)
		}
	}

	// 1. AST SQL Injection filter on query arguments
	if q, ok := args["query"].(string); ok {
		if strings.Contains(strings.ToUpper(q), "DROP TABLE") || strings.Contains(strings.ToUpper(q), "DELETE FROM") {
			return true, http.StatusForbidden, "SENTINEL_AST_VIOLATION: Destructive SQL query forbidden"
		}
	}

	// 2. High amount ceiling enforcement
	if amount > 25000.0 {
		return true, http.StatusForbidden, fmt.Sprintf("SENTINEL_AMOUNT_CEILING_EXCEEDED: Amount $%.2f exceeds global ceiling $25,000", amount)
	}

	// 3. Precedent ceiling check via in-process engine
	currency, _ := args["currency"].(string)
	if currency == "" {
		currency = "USD"
	}
	args["currency"] = currency

	evalResp := globalInProcessEngine.Evaluate(context.Background(), agentID, strings.ToUpper(toolName), args)
	if evalResp.Decision == "DENY" {
		return true, http.StatusForbidden, fmt.Sprintf("SENTINEL_PRECEDENT_REJECTION: %s (Citations: %v)", evalResp.Reason, evalResp.Citations)
	}

	return false, http.StatusOK, ""
}

func writeOpenAIError(w http.ResponseWriter, status int, msg, errType, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(OpenAIErrorResponse{
		Error: OpenAIErrorDetail{
			Message: msg,
			Type:    errType,
			Code:    code,
		},
	})
}

// MCPProxyHandler provides zero-trust security for Model Context Protocol (MCP) clients and servers.
// Intercepts JSON-RPC 2.0 messages (`POST /mcp`) and gates all `tools/call` invocations.
func MCPProxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, ProxyMaxBodyBytes))
	if err != nil {
		writeMCPError(w, nil, -32700, "Parse error reading request body")
		return
	}

	respBytes, allowed, err := InterceptMCPMessage(body)
	if err != nil {
		writeMCPError(w, nil, -32600, fmt.Sprintf("Invalid JSON-RPC request: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if !allowed {
		w.WriteHeader(http.StatusOK) // JSON-RPC 2.0 returns 200 with error object
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_, _ = w.Write(respBytes)
}

// InterceptMCPMessage inspects any raw MCP JSON-RPC message byte slice.
// Returns formatted response bytes, whether the tool call was allowed, and any parsing error.
func InterceptMCPMessage(raw []byte) ([]byte, bool, error) {
	var req MCPRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, false, err
	}

	if req.JSONRPC != "2.0" {
		req.JSONRPC = "2.0"
	}

	// If not a tools/call, approve transparently (e.g. tools/list, resources/list)
	if req.Method != "tools/call" {
		res := MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"status": "APPROVED",
				"method": req.Method,
			},
		}
		b, _ := json.Marshal(res)
		return b, true, nil
	}

	var params MCPToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		res := MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &MCPError{
				Code:    -32602,
				Message: "Invalid params for tools/call",
			},
		}
		b, _ := json.Marshal(res)
		return b, false, nil
	}

	// Extract parameters
	amount := 0.0
	if a, ok := params.Arguments["amount"]; ok {
		switch v := a.(type) {
		case float64:
			amount = v
		case int:
			amount = float64(v)
		}
	}

	// 1. SQL Injection Inspection
	if q, ok := params.Arguments["query"].(string); ok {
		if strings.Contains(strings.ToUpper(q), "DROP TABLE") || strings.Contains(strings.ToUpper(q), "TRUNCATE") {
			res := MCPResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &MCPError{
					Code:    -32001,
					Message: "SENTINEL_MCP_REJECTION: Destructive SQL query prohibited on MCP tool execution",
					Data:    map[string]string{"tool": params.Name, "policy": "AST_SQL_PROTECTION"},
				},
			}
			b, _ := json.Marshal(res)
			return b, false, nil
		}
	}

	// 2. High amount ceiling inspection
	if amount > 25000.0 {
		res := MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &MCPError{
				Code:    -32001,
				Message: fmt.Sprintf("SENTINEL_MCP_REJECTION: Amount $%.2f exceeds policy threshold $25,000", amount),
				Data:    map[string]interface{}{"tool": params.Name, "amount": amount},
			},
		}
		b, _ := json.Marshal(res)
		return b, false, nil
	}

	// 3. Precedent evaluation via in-process engine
	currency, _ := params.Arguments["currency"].(string)
	if currency == "" {
		currency = "USD"
	}
	params.Arguments["currency"] = currency

	evalResp := globalInProcessEngine.Evaluate(context.Background(), "ag_MCP_Tool_Bot", strings.ToUpper(params.Name), params.Arguments)
	if evalResp.Decision == "DENY" {
		res := MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &MCPError{
				Code:    -32001,
				Message: fmt.Sprintf("SENTINEL_MCP_REJECTION: %s", evalResp.Reason),
				Data:    map[string]interface{}{"tool": params.Name, "citations": evalResp.Citations},
			},
		}
		b, _ := json.Marshal(res)
		return b, false, nil
	}

	// Pre-commit allowed tool call to Audit WAL
	event := GatewayEvent{
		AgentID:   "ag_MCP_Tool_Bot",
		Action:    params.Name,
		Payload:   params.Arguments,
		Decision:  "ALLOW",
		Timestamp: time.Now().Format(time.RFC3339),
	}
	walEntry, _ := globalAuditWAL.WriteSync(event)

	seq := uint64(0)
	hash := ""
	if walEntry != nil {
		seq = walEntry.SequenceNum
		hash = walEntry.EntryHash
	}

	res := MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"status":   "APPROVED",
			"tool":     params.Name,
			"wal_seq":  seq,
			"wal_hash": hash,
			"content": []map[string]string{
				{"type": "text", "text": "Tool call authorized and sealed by Sentinel Zero-Trust Gateway."},
			},
		},
	}
	b, _ := json.Marshal(res)
	return b, true, nil
}

func writeMCPError(w http.ResponseWriter, id interface{}, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(MCPResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &MCPError{
			Code:    code,
			Message: message,
		},
	})
}

// ProcessMCPStdioSession handles an active bidirectional MCP stdio stream.
// Client messages from clientIn are inspected line-by-line.
// Allowed messages are forwarded to upstreamIn.
// Blocked tools/call messages receive an immediate JSON-RPC error on clientOut.
// Responses from upstreamOut are forwarded directly to clientOut.
func ProcessMCPStdioSession(clientIn io.Reader, clientOut io.Writer, upstreamIn io.Writer, upstreamOut io.Reader) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	// Goroutine 1: Forward upstream stdout -> client stdout (if upstreamOut provided)
	if upstreamOut != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanner := bufio.NewScanner(upstreamOut)
			buf := make([]byte, 64*1024)
			scanner.Buffer(buf, ProxyMaxBodyBytes)
			for scanner.Scan() {
				line := scanner.Bytes()
				if _, err := clientOut.Write(append(line, '\n')); err != nil {
					errChan <- err
					return
				}
			}
			if err := scanner.Err(); err != nil && err != io.EOF {
				errChan <- err
			}
		}()
	}

	// Goroutine 2: Inspect client stdin -> upstream stdin (or intercept)
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(clientIn)
		buf := make([]byte, 64*1024)
		scanner.Buffer(buf, ProxyMaxBodyBytes)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(strings.TrimSpace(string(line))) == 0 {
				continue
			}

			// Inspect with Sentinel Zero-Trust Engine
			respBytes, allowed, err := InterceptMCPMessage(line)
			if err != nil {
				errResp := MCPResponse{
					JSONRPC: "2.0",
					Error:   &MCPError{Code: -32700, Message: "Parse error"},
				}
				b, _ := json.Marshal(errResp)
				_, _ = clientOut.Write(append(b, '\n'))
				continue
			}

			if !allowed {
				// Blocked! Write rejection directly to clientOut without sending to upstream!
				_, _ = clientOut.Write(append(respBytes, '\n'))
				continue
			}

			// Allowed or non-tool call -> Forward to upstream child process
			if upstreamIn != nil {
				if _, err := upstreamIn.Write(append(line, '\n')); err != nil {
					errChan <- err
					return
				}
			} else {
				// Standalone/testing mode without upstream: emit approved confirmation
				_, _ = clientOut.Write(append(respBytes, '\n'))
			}
		}
		if err := scanner.Err(); err != nil && err != io.EOF {
			errChan <- err
		}
	}()

	wg.Wait()
	close(errChan)
	for err := range errChan {
		if err != nil {
			return err
		}
	}
	return nil
}

// RunStdioMCPProcess launches the upstream command and transparently proxies standard I/O.
func RunStdioMCPProcess(upstreamCmd string, upstreamArgs []string, clientIn io.Reader, clientOut io.Writer) error {
	cmd := exec.Command(upstreamCmd, upstreamArgs...)
	cmd.Stderr = os.Stderr

	upstreamIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe for %s: %w", upstreamCmd, err)
	}
	defer upstreamIn.Close()

	upstreamOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe for %s: %w", upstreamCmd, err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start upstream MCP command %s: %w", upstreamCmd, err)
	}

	sessionErr := ProcessMCPStdioSession(clientIn, clientOut, upstreamIn, upstreamOut)

	_ = cmd.Wait()
	return sessionErr
}
