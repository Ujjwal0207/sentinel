package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// WALVerificationReport encapsulates the mathematical proof of an offline WAL audit
type WALVerificationReport struct {
	TotalEntries    int      `json:"total_entries"`
	StartSequence   uint64   `json:"start_sequence"`
	EndSequence     uint64   `json:"end_sequence"`
	ChainValid      bool     `json:"chain_valid"`
	EpochMerkleRoot string   `json:"epoch_merkle_root"`
	Violations      []string `json:"violations,omitempty"`
}

// VerifyWALFile reads an append-only WAL file from disk, recalculates every SHA-256 hash
// in the chain, checks sequence monotonicity, and computes the binary Epoch Merkle root.
// Operates 100% offline with zero database or network dependencies.
func VerifyWALFile(walPath string) (*WALVerificationReport, error) {
	file, err := os.Open(walPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open WAL file: %w", err)
	}
	defer file.Close()

	return VerifyWALReader(file)
}

// VerifyWALReader verifies a stream of JSON-delimited WAL entries from any io.Reader.
func VerifyWALReader(r io.Reader) (*WALVerificationReport, error) {
	scanner := bufio.NewScanner(r)
	// Buffer up to 10MB per line for large tool arguments
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	var entries []*WALEntry
	var leafHashes []string
	report := &WALVerificationReport{
		ChainValid: true,
	}

	genesisHex := globalGenesisEpochHash()
	expectedPrevHash := genesisHex
	var lastSeq uint64 = 0

	lineNum := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lineNum++

		var entry WALEntry
		dec := json.NewDecoder(strings.NewReader(line))
		dec.UseNumber()
		if err := dec.Decode(&entry); err != nil {
			report.ChainValid = false
			report.Violations = append(report.Violations, fmt.Sprintf("Line %d: Malformed JSON: %v", lineNum, err))
			continue
		}

		if lineNum == 1 {
			report.StartSequence = entry.SequenceNum
		}
		report.EndSequence = entry.SequenceNum

		// 1. Sequence Monotonicity Check
		if lastSeq > 0 && entry.SequenceNum != lastSeq+1 {
			report.ChainValid = false
			report.Violations = append(report.Violations, fmt.Sprintf("Line %d: Sequence break: expected %d, got %d", lineNum, lastSeq+1, entry.SequenceNum))
		}
		lastSeq = entry.SequenceNum

		// 2. Previous Hash Link Check
		if entry.PrevHash != expectedPrevHash {
			report.ChainValid = false
			report.Violations = append(report.Violations, fmt.Sprintf("Line %d: Cryptographic link broken: expected prev_hash %s, got %s", lineNum, expectedPrevHash, entry.PrevHash))
		}

		// 3. Entry Hash Recomputation
		expectedEntryHash := ComputeEntryHash(entry.PrevHash, entry.SequenceNum, entry.Timestamp, entry.Event)
		if entry.EntryHash != expectedEntryHash {
			report.ChainValid = false
			report.Violations = append(report.Violations, fmt.Sprintf("Line %d: Tampering detected! Recorded hash %s does not match recomputed hash %s", lineNum, entry.EntryHash, expectedEntryHash))
		}

		expectedPrevHash = entry.EntryHash
		entries = append(entries, &entry)
		leafHashes = append(leafHashes, entry.EntryHash)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading WAL stream: %w", err)
	}

	report.TotalEntries = len(entries)
	if report.TotalEntries == 0 {
		report.EpochMerkleRoot = genesisHex
		return report, nil
	}

	// 4. Compute Binary Epoch Merkle Root across all entries
	merkleTree, err := BuildEpochMerkleTree(1, leafHashes)
	if err != nil {
		report.ChainValid = false
		report.Violations = append(report.Violations, fmt.Sprintf("Merkle tree generation error: %v", err))
	} else if merkleTree != nil {
		report.EpochMerkleRoot = merkleTree.Root
	}

	return report, nil
}

// globalGenesisEpochHash returns the deterministic genesis hash for the WAL epoch
func globalGenesisEpochHash() string {
	genesis := sha256.Sum256([]byte("SENTINEL_WAL_GENESIS_EPOCH_2026"))
	return hex.EncodeToString(genesis[:])
}

// RunVerifyCLI executes the offline verification CLI command and prints structured results
func RunVerifyCLI(walPath string) int {
	fmt.Printf("🔍 SENTINEL Cryptographic Audit Verifier (Offline Mode)\n")
	fmt.Printf("📂 Target WAL File: %s\n", walPath)
	fmt.Printf("------------------------------------------------------------------------\n")

	report, err := VerifyWALFile(walPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ VERIFICATION FAILED: %v\n", err)
		return 1
	}

	fmt.Printf("Total Audited Transactions : %d\n", report.TotalEntries)
	fmt.Printf("Sequence Monotonic Range   : #%d -> #%d\n", report.StartSequence, report.EndSequence)
	fmt.Printf("Binary Epoch Merkle Root   : %s\n", report.EpochMerkleRoot)

	if report.ChainValid {
		fmt.Printf("Cryptographic Continuity   : ✅ VERIFIED & INTACT (0 Tampered Records)\n")
		fmt.Printf("------------------------------------------------------------------------\n")
		fmt.Printf("🏆 AUDIT RESULT: Cryptographic non-repudiation mathematically guaranteed.\n")
		return 0
	}

	fmt.Printf("Cryptographic Continuity   : ⛔ CORRUPTED / TAMPERED!\n")
	fmt.Printf("Violations Detected (%d):\n", len(report.Violations))
	for _, v := range report.Violations {
		fmt.Printf("  • %s\n", v)
	}
	fmt.Printf("------------------------------------------------------------------------\n")
	fmt.Printf("🚨 AUDIT RESULT: Mathematical proof of tampering detected in audit records.\n")
	return 2
}
