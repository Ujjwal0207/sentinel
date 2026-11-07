package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// RaftRole defines the node state in the consensus cycle.
type RaftRole string

const (
	RoleFollower  RaftRole = "Follower"
	RoleCandidate RaftRole = "Candidate"
	RoleLeader    RaftRole = "Leader"
)

// RaftOpType specifies the state machine mutation operation.
type RaftOpType string

const (
	OpConsumeNonce RaftOpType = "CONSUME_NONCE"
	OpRecordAmount RaftOpType = "RECORD_VELOCITY"
	OpFleetFreeze  RaftOpType = "FLEET_FREEZE"
	OpClusterReset RaftOpType = "CLUSTER_RESET"
)

// RaftLogEntry represents an individual replicated state machine command.
type RaftLogEntry struct {
	Index   uint64
	Term    uint64
	Op      RaftOpType
	AgentID string
	Nonce   string
	Amount  float64
	Reason  string
	Time    time.Time
}

// EmbeddedRaftNode is a self-contained Raft consensus node.
type EmbeddedRaftNode struct {
	mu          sync.Mutex
	NodeID      string
	CurrentTerm uint64
	VotedFor    string
	Role        RaftRole
	Log         []RaftLogEntry
	CommitIndex uint64
	Cluster     *EmbeddedRaftCluster

	// In-memory state machine synchronized via consensus log
	nonces       map[string]time.Time
	velocitySets map[string][]VelocityEntry
	fleetFrozen  bool
	freezeReason string
	defaultWin   time.Duration
	defaultLimit float64
	isIsolated   bool // Network partition simulation flag
}

// EmbeddedRaftCluster coordinates a mesh of EmbeddedRaftNodes for air-gapped, zero-Redis state synchronization.
type EmbeddedRaftCluster struct {
	mu    sync.RWMutex
	Nodes map[string]*EmbeddedRaftNode
}

var globalRaftCluster = NewEmbeddedRaftCluster(3)

func NewEmbeddedRaftCluster(nodeCount int) *EmbeddedRaftCluster {
	cluster := &EmbeddedRaftCluster{
		Nodes: make(map[string]*EmbeddedRaftNode),
	}

	for i := 1; i <= nodeCount; i++ {
		nodeID := fmt.Sprintf("sentinel-raft-node-%d", i)
		node := &EmbeddedRaftNode{
			NodeID:       nodeID,
			CurrentTerm:  1,
			Role:         RoleFollower,
			Log:          make([]RaftLogEntry, 0),
			Cluster:      cluster,
			nonces:       make(map[string]time.Time),
			velocitySets: make(map[string][]VelocityEntry),
			defaultWin:   1 * time.Hour,
			defaultLimit: 25000.00,
		}
		cluster.Nodes[nodeID] = node
	}

	// Bootstrap Node 1 as initial Leader
	leader := cluster.Nodes["sentinel-raft-node-1"]
	leader.Role = RoleLeader
	leader.VotedFor = "sentinel-raft-node-1"

	return cluster
}

// GetLeader returns the currently elected Raft leader.
func (c *EmbeddedRaftCluster) GetLeader() *EmbeddedRaftNode {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, node := range c.Nodes {
		node.mu.Lock()
		if node.Role == RoleLeader && !node.isIsolated {
			node.mu.Unlock()
			return node
		}
		node.mu.Unlock()
	}
	return nil
}

// ElectLeader triggers leader election on a specific node.
func (node *EmbeddedRaftNode) ElectLeader() bool {
	node.mu.Lock()
	defer node.mu.Unlock()

	if node.isIsolated {
		return false
	}

	node.Role = RoleCandidate
	node.CurrentTerm++
	node.VotedFor = node.NodeID
	votes := 1

	// Request votes from peers in cluster
	totalNodes := 0
	for _, peer := range node.Cluster.Nodes {
		if peer.NodeID == node.NodeID {
			totalNodes++
			continue
		}
		peer.mu.Lock()
		totalNodes++
		if !peer.isIsolated && peer.CurrentTerm <= node.CurrentTerm {
			peer.CurrentTerm = node.CurrentTerm
			peer.VotedFor = node.NodeID
			peer.Role = RoleFollower
			votes++
		}
		peer.mu.Unlock()
	}

	// Quorum check: strictly greater than half
	quorum := (totalNodes / 2) + 1
	if votes >= quorum {
		node.Role = RoleLeader
		return true
	}

	node.Role = RoleFollower
	return false
}

// Propose applies a state command through the Raft consensus log across cluster peers.
func (node *EmbeddedRaftNode) Propose(op RaftOpType, agentID, nonce string, amount float64, reason string, t time.Time) (bool, error) {
	node.mu.Lock()
	defer node.mu.Unlock()

	if node.isIsolated {
		return false, errors.New("node is network partitioned from consensus cluster")
	}

	if node.Role != RoleLeader {
		return false, fmt.Errorf("node %s is not leader; current role: %s", node.NodeID, node.Role)
	}

	entry := RaftLogEntry{
		Index:   uint64(len(node.Log) + 1),
		Term:    node.CurrentTerm,
		Op:      op,
		AgentID: agentID,
		Nonce:   nonce,
		Amount:  amount,
		Reason:  reason,
		Time:    t,
	}

	// Append locally
	node.Log = append(node.Log, entry)

	// Replicate to cluster peers
	acks := 1
	totalNodes := len(node.Cluster.Nodes)

	for _, peer := range node.Cluster.Nodes {
		if peer.NodeID == node.NodeID {
			continue
		}
		peer.mu.Lock()
		if !peer.isIsolated {
			peer.Log = append(peer.Log, entry)
			peer.CommitIndex = entry.Index
			peer.applyLogEntry(entry)
			acks++
		}
		peer.mu.Unlock()
	}

	quorum := (totalNodes / 2) + 1
	if acks >= quorum {
		node.CommitIndex = entry.Index
		node.applyLogEntry(entry)
		return true, nil
	}

	return false, fmt.Errorf("consensus quorum not reached (%d/%d acks)", acks, totalNodes)
}

// applyLogEntry mutates local state machine upon consensus commit.
func (node *EmbeddedRaftNode) applyLogEntry(entry RaftLogEntry) {
	switch entry.Op {
	case OpConsumeNonce:
		node.nonces[entry.Nonce] = entry.Time
	case OpRecordAmount:
		entries := node.velocitySets[entry.AgentID]
		node.velocitySets[entry.AgentID] = append(entries, VelocityEntry{
			Timestamp: entry.Time,
			Amount:    entry.Amount,
		})
	case OpFleetFreeze:
		node.fleetFrozen = (entry.Amount > 0)
		node.freezeReason = entry.Reason
	case OpClusterReset:
		node.nonces = make(map[string]time.Time)
		node.velocitySets = make(map[string][]VelocityEntry)
		node.fleetFrozen = false
		node.freezeReason = ""
	}
}

// SimulatePartition isolates a node from the cluster to test split-brain resistance.
func (node *EmbeddedRaftNode) SimulatePartition(isolated bool) {
	node.mu.Lock()
	defer node.mu.Unlock()
	node.isIsolated = isolated
	if isolated && node.Role == RoleLeader {
		node.Role = RoleFollower
	}
}

// --- Implementation of DistributedStateMesh Interface ---

type EmbeddedRaftStateMesh struct {
	Cluster *EmbeddedRaftCluster
}

func NewEmbeddedRaftStateMesh(cluster *EmbeddedRaftCluster) *EmbeddedRaftStateMesh {
	return &EmbeddedRaftStateMesh{Cluster: cluster}
}

func (r *EmbeddedRaftStateMesh) CheckAndConsumeNonce(ctx context.Context, agentID, nonce string, now time.Time, ttl time.Duration) (bool, string) {
	leader := r.Cluster.GetLeader()
	if leader == nil {
		return false, "RAFT_NO_LEADER: Cluster has no active quorum leader"
	}

	leader.mu.Lock()
	// Check existing nonce in state machine
	if exp, exists := leader.nonces[nonce]; exists {
		if now.Sub(exp) < ttl {
			leader.mu.Unlock()
			return false, "REPLAY_ATTACK: Nonce already consumed in consensus log"
		}
	}
	leader.mu.Unlock()

	// Propose through consensus log
	ok, err := leader.Propose(OpConsumeNonce, agentID, nonce, 0, "", now)
	if !ok || err != nil {
		return false, fmt.Sprintf("RAFT_CONSENSUS_ERROR: %v", err)
	}
	return true, ""
}

func (r *EmbeddedRaftStateMesh) CheckAndRecordVelocity(ctx context.Context, agentID string, amount float64, window time.Duration, limit float64, now time.Time) (bool, float64, float64, error) {
	leader := r.Cluster.GetLeader()
	if leader == nil {
		return false, 0, limit, errors.New("RAFT_NO_LEADER: Cluster has no active quorum leader")
	}

	leader.mu.Lock()
	cutoff := now.Add(-window)
	currentTotal := 0.0

	// Calculate sliding-window sum from state machine
	if entries, exists := leader.velocitySets[agentID]; exists {
		for _, e := range entries {
			if e.Timestamp.After(cutoff) {
				currentTotal += e.Amount
			}
		}
	}

	if currentTotal+amount > limit {
		leader.mu.Unlock()
		return false, currentTotal, limit, nil
	}
	leader.mu.Unlock()

	// Propose velocity append to cluster
	ok, err := leader.Propose(OpRecordAmount, agentID, "", amount, "", now)
	if !ok || err != nil {
		return false, currentTotal, limit, err
	}

	return true, currentTotal + amount, limit, nil
}

func (r *EmbeddedRaftStateMesh) IsFleetFrozen(ctx context.Context) (bool, string, error) {
	leader := r.Cluster.GetLeader()
	if leader == nil {
		return false, "", errors.New("RAFT_NO_LEADER: Consensus leader unavailable")
	}
	leader.mu.Lock()
	defer leader.mu.Unlock()
	return leader.fleetFrozen, leader.freezeReason, nil
}

func (r *EmbeddedRaftStateMesh) SetFleetFreeze(ctx context.Context, frozen bool, reason string) error {
	leader := r.Cluster.GetLeader()
	if leader == nil {
		return errors.New("RAFT_NO_LEADER: Consensus leader unavailable")
	}
	val := 0.0
	if frozen {
		val = 1.0
	}
	ok, err := leader.Propose(OpFleetFreeze, "ag_Admin", "", val, reason, time.Now())
	if !ok || err != nil {
		return fmt.Errorf("freeze proposal failed: %w", err)
	}
	return nil
}

func (r *EmbeddedRaftStateMesh) Reset(ctx context.Context) error {
	leader := r.Cluster.GetLeader()
	if leader == nil {
		return nil
	}
	_, err := leader.Propose(OpClusterReset, "", "", 0, "", time.Now())
	return err
}

