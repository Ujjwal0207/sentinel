package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestIndustryReadinessBenchmark audits Sentinel's dual-surface architecture:
// 1. Stdio & HTTP MCP Proxy Interception for Claude Desktop / Cursor
// 2. Offline Merkle WAL Audit Verifier CLI
// 3. Standalone Edge Mode vs. Distributed SaaS Mode Execution
func TestIndustryReadinessBenchmark(t *testing.T) {
	t.Run("Stdio_MCP_Proxy_Interception", func(t *testing.T) {
		// STDIO-001: Transparent approval of tools/list
		listReq := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
		respBytes, allowed, err := InterceptMCPMessage([]byte(listReq))
		if err != nil || !allowed {
			t.Fatalf("[STDIO-001 FAIL] tools/list should be transparently approved: %v", err)
		}
		var listResp MCPResponse
		if err := json.Unmarshal(respBytes, &listResp); err != nil || listResp.Error != nil {
			t.Fatalf("[STDIO-001 FAIL] Invalid tools/list response: %v", err)
		}

		// STDIO-002: Transparent approval of ping
		pingReq := `{"jsonrpc":"2.0","id":"ping-1","method":"ping"}`
		respBytes, allowed, err = InterceptMCPMessage([]byte(pingReq))
		if err != nil || !allowed {
			t.Fatalf("[STDIO-002 FAIL] ping should be approved: %v", err)
		}

		// STDIO-003: Authorized tool call (issue_refund $45.00)
		refundReq := `{"jsonrpc":"2.0","id":101,"method":"tools/call","params":{"name":"issue_refund","arguments":{"amount":45.0,"currency":"USD"}}}`
		respBytes, allowed, err = InterceptMCPMessage([]byte(refundReq))
		if err != nil || !allowed {
			t.Fatalf("[STDIO-003 FAIL] Benign issue_refund should be allowed: %v", err)
		}
		var refundResp MCPResponse
		_ = json.Unmarshal(respBytes, &refundResp)
		if refundResp.Error != nil {
			t.Fatalf("[STDIO-003 FAIL] Expected no error in refund response, got: %v", refundResp.Error)
		}

		// STDIO-004: Read-only SELECT query approved
		queryReq := `{"jsonrpc":"2.0","id":102,"method":"tools/call","params":{"name":"query","arguments":{"query":"SELECT id, name FROM customers WHERE active = true;"}}}`
		respBytes, allowed, err = InterceptMCPMessage([]byte(queryReq))
		if err != nil || !allowed {
			t.Fatalf("[STDIO-004 FAIL] Read-only SELECT should be allowed: %v", err)
		}

		// STDIO-005: Destructive SQL injection DROP TABLE intercepted
		dropReq := `{"jsonrpc":"2.0","id":103,"method":"tools/call","params":{"name":"query","arguments":{"query":"DROP TABLE users;"}}}`
		respBytes, allowed, err = InterceptMCPMessage([]byte(dropReq))
		if allowed {
			t.Fatalf("[STDIO-005 FAIL] Destructive DROP TABLE was allowed!")
		}
		var dropResp MCPResponse
		_ = json.Unmarshal(respBytes, &dropResp)
		if dropResp.Error == nil || dropResp.Error.Code != -32001 {
			t.Fatalf("[STDIO-005 FAIL] Expected error code -32001, got: %v", dropResp.Error)
		}

		// STDIO-006: Bare TRUNCATE rejected
		truncReq := `{"jsonrpc":"2.0","id":104,"method":"tools/call","params":{"name":"query","arguments":{"query":"TRUNCATE audit_logs;"}}}`
		respBytes, allowed, err = InterceptMCPMessage([]byte(truncReq))
		if allowed {
			t.Fatalf("[STDIO-006 FAIL] TRUNCATE was allowed!")
		}

		// STDIO-007: Amount ceiling violation ($30,000 > $25,000)
		ceilingReq := `{"jsonrpc":"2.0","id":105,"method":"tools/call","params":{"name":"transfer","arguments":{"amount":30000.0,"currency":"USD"}}}`
		respBytes, allowed, err = InterceptMCPMessage([]byte(ceilingReq))
		if allowed {
			t.Fatalf("[STDIO-007 FAIL] Over-ceiling transfer was allowed!")
		}
		var ceilingResp MCPResponse
		_ = json.Unmarshal(respBytes, &ceilingResp)
		if ceilingResp.Error == nil || ceilingResp.Error.Code != -32001 {
			t.Fatalf("[STDIO-007 FAIL] Expected error code -32001, got: %v", ceilingResp.Error)
		}

		// STDIO-008: Malformed JSON-RPC packet caught cleanly
		malformedReq := `{"jsonrpc":"2.0", incomplete_json...`
		_, allowed, err = InterceptMCPMessage([]byte(malformedReq))
		if err == nil || allowed {
			t.Fatalf("[STDIO-008 FAIL] Malformed JSON should return an error")
		}

		// STDIO-009 & STDIO-010: In-memory ProcessMCPStdioSession simulation
		clientIn := bytes.NewBufferString(strings.Join([]string{
			`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"issue_refund","arguments":{"amount":25.0,"currency":"USD"}}}`,
			`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query","arguments":{"query":"DROP TABLE accounts;"}}}`,
		}, "\n") + "\n")

		var clientOut bytes.Buffer
		var upstreamIn bytes.Buffer
		upstreamOut := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}` + "\n")

		err = ProcessMCPStdioSession(clientIn, &clientOut, &upstreamIn, upstreamOut)
		if err != nil {
			t.Fatalf("[STDIO-009 FAIL] ProcessMCPStdioSession returned error: %v", err)
		}

		outLines := strings.Split(strings.TrimSpace(clientOut.String()), "\n")
		if len(outLines) < 2 {
			t.Fatalf("[STDIO-010 FAIL] Expected client responses, got: %v", outLines)
		}

		// Verify that DROP TABLE was intercepted and NOT written to upstreamIn!
		upstreamText := upstreamIn.String()
		if strings.Contains(upstreamText, "DROP TABLE") {
			t.Fatalf("[STDIO-010 FAIL] Malicious DROP TABLE leaked into upstream process input!")
		}
	})

	t.Run("Offline_Merkle_WAL_Verifier", func(t *testing.T) {
		// WAL-VERIFY-001: Empty WAL stream
		emptyReader := bytes.NewReader([]byte(""))
		report, err := VerifyWALReader(emptyReader)
		if err != nil || !report.ChainValid || report.TotalEntries != 0 {
			t.Fatalf("[WAL-VERIFY-001 FAIL] Empty WAL failed: %v", err)
		}

		// Build a valid 10-entry synthetic WAL stream
		var walBuf bytes.Buffer
		genesisHex := globalGenesisEpochHash()
		prev := genesisHex

		for i := 1; i <= 10; i++ {
			seq := uint64(i)
			ts := time.Now().UTC().Format(time.RFC3339Nano)
			ev := GatewayEvent{
				AgentID:   "ag_Travel_Bot",
				Action:    "Issue_Refund",
				Payload:   map[string]interface{}{"amount": float64(i * 10)},
				Decision:  "ALLOW",
				Timestamp: ts,
			}
			currHash := ComputeEntryHash(prev, seq, ts, ev)
			entry := WALEntry{
				SequenceNum:  seq,
				Timestamp:    ts,
				PrevHash:     prev,
				EntryHash:    currHash,
				Event:        ev,
				SyncedToDisk: true,
			}
			b, _ := json.Marshal(entry)
			walBuf.Write(b)
			walBuf.WriteByte('\n')
			prev = currHash
		}

		// WAL-VERIFY-002: Verify 10-entry valid monotonic stream
		report, err = VerifyWALReader(bytes.NewReader(walBuf.Bytes()))
		if err != nil || !report.ChainValid || report.TotalEntries != 10 {
			t.Fatalf("[WAL-VERIFY-002 FAIL] Valid WAL stream failed: %v, report: %+v", err, report)
		}
		if report.EpochMerkleRoot == "" {
			t.Fatalf("[WAL-VERIFY-002 FAIL] EpochMerkleRoot should not be empty")
		}

		// WAL-VERIFY-004: Tampered entry_hash detection
		tamperedStr := strings.Replace(walBuf.String(), `"entry_hash":"`, `"entry_hash":"tampered_hash_`, 1)
		report, _ = VerifyWALReader(strings.NewReader(tamperedStr))
		if report.ChainValid {
			t.Fatalf("[WAL-VERIFY-004 FAIL] Tampered hash was not detected!")
		}

		// WAL-VERIFY-005: Sequence break detection
		tamperedSeq := strings.Replace(walBuf.String(), `"sequence_num":7`, `"sequence_num":9`, 1)
		report, _ = VerifyWALReader(strings.NewReader(tamperedSeq))
		if report.ChainValid {
			t.Fatalf("[WAL-VERIFY-005 FAIL] Sequence break was not detected!")
		}

		// WAL-VERIFY-006: Previous hash break detection
		tamperedPrev := strings.Replace(walBuf.String(), `"prev_hash":"`+genesisHex, `"prev_hash":"corrupted_genesis_hash`, 1)
		report, _ = VerifyWALReader(strings.NewReader(tamperedPrev))
		if report.ChainValid {
			t.Fatalf("[WAL-VERIFY-006 FAIL] Broken prev_hash link was not detected!")
		}

		// WAL-VERIFY-007: Malformed line handling
		malformedWAL := "valid_prefix\n{not_json}\nvalid_suffix\n"
		report, _ = VerifyWALReader(strings.NewReader(malformedWAL))
		if report.ChainValid {
			t.Fatalf("[WAL-VERIFY-007 FAIL] Malformed JSON was marked valid!")
		}

		// WAL-VERIFY-010: RunVerifyCLI on disk file
		tmpFile, err := os.CreateTemp("", "sentinel_audit_*.wal")
		if err != nil {
			t.Fatalf("Failed to create temp WAL file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		_, _ = tmpFile.Write(walBuf.Bytes())
		_ = tmpFile.Close()

		exitCode := RunVerifyCLI(tmpFile.Name())
		if exitCode != 0 {
			t.Fatalf("[WAL-VERIFY-010 FAIL] Expected exit code 0 on authentic WAL, got: %d", exitCode)
		}
	})

	t.Run("Dual_Surface_Execution_Modes", func(t *testing.T) {
		// MODE-001: Health endpoint reports running mode
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		healthHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("[MODE-001 FAIL] Health endpoint returned %d", w.Code)
		}
		var healthResp map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &healthResp)
		if healthResp["status"] != "HEALTHY" {
			t.Fatalf("[MODE-001 FAIL] Expected HEALTHY, got: %v", healthResp["status"])
		}
		if healthResp["mode"] == "" {
			t.Fatalf("[MODE-001 FAIL] Mode should be present in health response")
		}

		// MODE-003: Standalone Edge Mode in-process evaluation
		t.Setenv("SENTINEL_MODE", "standalone")
		t.Setenv("SENTINEL_INPROCESS_POLICY", "true")

		evalReq := AgentRequest{
			AgentID: "ag_Travel_Bot",
			Action:  "Issue_Refund",
			Payload: map[string]interface{}{"amount": 50.0, "currency": "USD"},
		}
		bodyBytes, _ := json.Marshal(evalReq)
		r := httptest.NewRequest(http.MethodPost, "/enforce", bytes.NewBuffer(bodyBytes))
		r.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()

		start := time.Now()
		enforceHandler(w, r)
		elapsed := time.Since(start)

		if w.Code != http.StatusOK {
			t.Fatalf("[MODE-003 FAIL] Standalone evaluation failed: HTTP %d, body: %s", w.Code, w.Body.String())
		}
		if elapsed > 10*time.Millisecond {
			t.Fatalf("[MODE-003 FAIL] Standalone evaluation took %v (expected < 10ms)", elapsed)
		}

		// MODE-007: Zero-loss WAL pre-commit headers emitted
		seqHeader := w.Header().Get("X-Sentinel-WAL-Seq")
		hashHeader := w.Header().Get("X-Sentinel-WAL-Hash")
		if seqHeader == "" || hashHeader == "" {
			t.Fatalf("[MODE-007 FAIL] Missing X-Sentinel-WAL headers in standalone response")
		}

		// MODE-008: Over-ceiling amount blocked in standalone mode
		overCeilingReq := AgentRequest{
			AgentID: "ag_Travel_Bot",
			Action:  "Issue_Refund",
			Payload: map[string]interface{}{"amount": 99999.0, "currency": "USD"},
		}
		overBytes, _ := json.Marshal(overCeilingReq)
		r = httptest.NewRequest(http.MethodPost, "/enforce", bytes.NewBuffer(overBytes))
		r.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		enforceHandler(w, r)

		if w.Code != http.StatusForbidden {
			t.Fatalf("[MODE-008 FAIL] Over-ceiling refund should be 403 Forbidden, got: %d", w.Code)
		}
	})
}

// Benchmark tests for Stdio MCP and Offline WAL Verification
func BenchmarkStdioMCP_InterceptMessage(b *testing.B) {
	reqBytes := []byte(`{"jsonrpc":"2.0","id":1001,"method":"tools/call","params":{"name":"issue_refund","arguments":{"amount":45.0,"currency":"USD"}}}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = InterceptMCPMessage(reqBytes)
	}
}

func BenchmarkOfflineWAL_VerifyReader(b *testing.B) {
	var walBuf bytes.Buffer
	prev := "0000000000000000000000000000000000000000000000000000000000000000"
	for i := 1; i <= 100; i++ {
		seq := uint64(i)
		ts := "2026-11-08T04:40:00Z"
		ev := GatewayEvent{
			AgentID:   "ag_Bench_Bot",
			Action:    "TRANSFER",
			Payload:   map[string]interface{}{"amount": 100.0},
			Decision:  "ALLOW",
			Timestamp: ts,
		}
		h := ComputeEntryHash(prev, seq, ts, ev)
		entry := WALEntry{
			SequenceNum:  seq,
			Timestamp:    ts,
			PrevHash:     prev,
			EntryHash:    h,
			Event:        ev,
			SyncedToDisk: true,
		}
		line, _ := json.Marshal(entry)
		walBuf.Write(line)
		walBuf.WriteByte('\n')
		prev = h
	}

	raw := walBuf.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = VerifyWALReader(bytes.NewReader(raw))
	}
}
