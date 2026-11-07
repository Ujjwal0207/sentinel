package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// PartitionBlock represents an immutable block within a single partition's sub-chain
type PartitionBlock struct {
	PartitionID int          `json:"partition_id"`
	SequenceNum uint64       `json:"sequence_num"`
	Timestamp   string       `json:"timestamp"`
	PrevHash    string       `json:"prev_hash"`
	BlockHash   string       `json:"block_hash"`
	Event       GatewayEvent `json:"event"`
}

// MerkleAuditProof holds the cryptographic co-path required to prove inclusion in an epoch root
type MerkleAuditProof struct {
	LeafIndex int      `json:"leaf_index"`
	LeafHash  string   `json:"leaf_hash"`
	AuditPath []string `json:"audit_path"` // sibling hashes from bottom to root
	EpochRoot string   `json:"epoch_root"`
	EpochID   uint64   `json:"epoch_id"`
}

// EpochRecord stores an immutable epoch snapshot anchoring multiple partition heads
type EpochRecord struct {
	EpochID       uint64            `json:"epoch_id"`
	Timestamp     string            `json:"timestamp"`
	MerkleRoot    string            `json:"merkle_root"`
	LeafCount     int               `json:"leaf_count"`
	PartitionHeads map[int]string   `json:"partition_heads"`
}

// EpochMerkleTree constructs a binary Merkle tree over a batch of leaf hashes
type EpochMerkleTree struct {
	EpochID uint64
	Leaves  []string
	Levels  [][]string
	Root    string
}

// MultiPartitionLedger provides fork-proof, zero-lock multi-consumer audit chaining
type MultiPartitionLedger struct {
	mu             sync.RWMutex
	partitions     map[int]*partitionState
	epochs         []*EpochRecord
	latestEpochID  uint64
	genesisPrefix  string
}

type partitionState struct {
	mu         sync.Mutex
	id         int
	latestSeq  uint64
	latestHash string
	blocks     []*PartitionBlock
}

// NewMultiPartitionLedger initializes the partition-safe Merkle ledger
func NewMultiPartitionLedger(partitionCount int) *MultiPartitionLedger {
	ledger := &MultiPartitionLedger{
		partitions:    make(map[int]*partitionState),
		genesisPrefix: "SENTINEL_PARTITION_GENESIS_",
	}

	for i := 0; i < partitionCount; i++ {
		gen := sha256.Sum256([]byte(fmt.Sprintf("%s%d_2026", ledger.genesisPrefix, i)))
		ledger.partitions[i] = &partitionState{
			id:         i,
			latestSeq:  0,
			latestHash: hex.EncodeToString(gen[:]),
			blocks:     make([]*PartitionBlock, 0, 1024),
		}
	}

	return ledger
}

// ComputePartitionBlockHash creates a tamper-evident partition-scoped block hash
func ComputePartitionBlockHash(partitionID int, seq uint64, prevHash string, ts string, event GatewayEvent) string {
	payloadBytes, _ := json.Marshal(event.Payload)
	payloadHash := sha256.Sum256(payloadBytes)

	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("P%d:SEQ%d:%s:%s:%s:%s:%s:",
		partitionID, seq, prevHash, ts, event.AgentID, event.Action, event.Decision)))
	h.Write(payloadHash[:])
	return hex.EncodeToString(h.Sum(nil))
}

// RecordEvent appends an audit event to a specific partition without cross-partition contention
func (mpl *MultiPartitionLedger) RecordEvent(partitionID int, event GatewayEvent) (*PartitionBlock, error) {
	mpl.mu.RLock()
	pState, exists := mpl.partitions[partitionID]
	mpl.mu.RUnlock()

	if !exists {
		// Auto-register partition if new
		mpl.mu.Lock()
		pState, exists = mpl.partitions[partitionID]
		if !exists {
			gen := sha256.Sum256([]byte(fmt.Sprintf("%s%d_2026", mpl.genesisPrefix, partitionID)))
			pState = &partitionState{
				id:         partitionID,
				latestSeq:  0,
				latestHash: hex.EncodeToString(gen[:]),
				blocks:     make([]*PartitionBlock, 0, 1024),
			}
			mpl.partitions[partitionID] = pState
		}
		mpl.mu.Unlock()
	}

	pState.mu.Lock()
	defer pState.mu.Unlock()

	pState.latestSeq++
	seq := pState.latestSeq
	ts := event.Timestamp
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339Nano)
		event.Timestamp = ts
	}

	prev := pState.latestHash
	currHash := ComputePartitionBlockHash(partitionID, seq, prev, ts, event)
	pState.latestHash = currHash

	block := &PartitionBlock{
		PartitionID: partitionID,
		SequenceNum: seq,
		Timestamp:   ts,
		PrevHash:    prev,
		BlockHash:   currHash,
		Event:       event,
	}

	pState.blocks = append(pState.blocks, block)
	return block, nil
}

// BuildEpochMerkleTree builds a balanced Merkle tree from an array of leaf hashes
func BuildEpochMerkleTree(epochID uint64, leaves []string) (*EpochMerkleTree, error) {
	if len(leaves) == 0 {
		return nil, errors.New("cannot build Merkle tree with empty leaves")
	}

	var levels [][]string
	currentLevel := make([]string, len(leaves))
	copy(currentLevel, leaves)
	levels = append(levels, currentLevel)

	for len(currentLevel) > 1 {
		var nextLevel []string
		for i := 0; i < len(currentLevel); i += 2 {
			left := currentLevel[i]
			var right string
			if i+1 < len(currentLevel) {
				right = currentLevel[i+1]
			} else {
				// Duplicate last odd node as per standard Merkle tree specification
				right = left
			}

			h := sha256.New()
			h.Write([]byte(left + right))
			parent := hex.EncodeToString(h.Sum(nil))
			nextLevel = append(nextLevel, parent)
		}
		levels = append(levels, nextLevel)
		currentLevel = nextLevel
	}

	return &EpochMerkleTree{
		EpochID: epochID,
		Leaves:  leaves,
		Levels:  levels,
		Root:    currentLevel[0],
	}, nil
}

// GenerateAuditProof produces an inclusion proof for the leaf at leafIndex
func (tree *EpochMerkleTree) GenerateAuditProof(leafIndex int) (*MerkleAuditProof, error) {
	if leafIndex < 0 || leafIndex >= len(tree.Leaves) {
		return nil, fmt.Errorf("leafIndex %d out of bounds (0..%d)", leafIndex, len(tree.Leaves)-1)
	}

	proof := &MerkleAuditProof{
		LeafIndex: leafIndex,
		LeafHash:  tree.Leaves[leafIndex],
		AuditPath: make([]string, 0),
		EpochRoot: tree.Root,
		EpochID:   tree.EpochID,
	}

	idx := leafIndex
	for level := 0; level < len(tree.Levels)-1; level++ {
		currentLevel := tree.Levels[level]
		var sibling string
		if idx%2 == 0 {
			// Sibling is to the right
			if idx+1 < len(currentLevel) {
				sibling = currentLevel[idx+1]
			} else {
				sibling = currentLevel[idx] // duplicated odd node
			}
		} else {
			// Sibling is to the left
			sibling = currentLevel[idx-1]
		}
		proof.AuditPath = append(proof.AuditPath, sibling)
		idx /= 2
	}

	return proof, nil
}

// VerifyMerkleAuditProof verifies that a leaf hash is part of the committed Merkle root
func VerifyMerkleAuditProof(leafHash string, leafIndex int, proof *MerkleAuditProof) bool {
	if proof == nil || leafHash != proof.LeafHash {
		return false
	}

	currentHash := leafHash
	idx := leafIndex

	for _, sibling := range proof.AuditPath {
		h := sha256.New()
		if idx%2 == 0 {
			h.Write([]byte(currentHash + sibling))
		} else {
			h.Write([]byte(sibling + currentHash))
		}
		currentHash = hex.EncodeToString(h.Sum(nil))
		idx /= 2
	}

	return currentHash == proof.EpochRoot
}

// FinalizeEpoch snapshots all partition latest hashes into an immutable Merkle root
func (mpl *MultiPartitionLedger) FinalizeEpoch(epochID uint64) (*EpochRecord, error) {
	mpl.mu.Lock()
	defer mpl.mu.Unlock()

	heads := make(map[int]string)
	var leafHashes []string

	for id, pState := range mpl.partitions {
		pState.mu.Lock()
		heads[id] = pState.latestHash
		leafHashes = append(leafHashes, pState.latestHash)
		pState.mu.Unlock()
	}

	if len(leafHashes) == 0 {
		return nil, errors.New("no partitions available to finalize epoch")
	}

	tree, err := BuildEpochMerkleTree(epochID, leafHashes)
	if err != nil {
		return nil, err
	}

	record := &EpochRecord{
		EpochID:        epochID,
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
		MerkleRoot:     tree.Root,
		LeafCount:      len(leafHashes),
		PartitionHeads: heads,
	}

	mpl.epochs = append(mpl.epochs, record)
	mpl.latestEpochID = epochID
	return record, nil
}

// VerifyLedgerIntegrity audits every partition chain and confirms zero forks or tampering
func (mpl *MultiPartitionLedger) VerifyLedgerIntegrity() (bool, error) {
	mpl.mu.RLock()
	defer mpl.mu.RUnlock()

	for id, pState := range mpl.partitions {
		pState.mu.Lock()
		defer pState.mu.Unlock()

		for i, block := range pState.blocks {
			recomputed := ComputePartitionBlockHash(block.PartitionID, block.SequenceNum, block.PrevHash, block.Timestamp, block.Event)
			if recomputed != block.BlockHash {
				return false, fmt.Errorf("PARTITION_TAMPER: Partition %d block %d hash mismatch (expected %s, got %s)",
					id, block.SequenceNum, block.BlockHash, recomputed)
			}
			if i > 0 {
				prevBlock := pState.blocks[i-1]
				if block.PrevHash != prevBlock.BlockHash {
					return false, fmt.Errorf("PARTITION_CHAIN_FORK: Partition %d block %d prev_hash (%s) != block %d hash (%s)",
						id, block.SequenceNum, block.PrevHash, prevBlock.SequenceNum, prevBlock.BlockHash)
				}
			}
		}
	}

	return true, nil
}

// Reset clears all partitions and epoch records (for clean benchmark testing)
func (mpl *MultiPartitionLedger) Reset() {
	mpl.mu.Lock()
	defer mpl.mu.Unlock()

	for id, pState := range mpl.partitions {
		pState.mu.Lock()
		gen := sha256.Sum256([]byte(fmt.Sprintf("%s%d_2026", mpl.genesisPrefix, id)))
		pState.latestSeq = 0
		pState.latestHash = hex.EncodeToString(gen[:])
		pState.blocks = make([]*PartitionBlock, 0, 1024)
		pState.mu.Unlock()
	}

	mpl.epochs = make([]*EpochRecord, 0)
	mpl.latestEpochID = 0
}

// Global Multi-Partition Merkle Ledger instance
var globalMerkleLedger = NewMultiPartitionLedger(16)
