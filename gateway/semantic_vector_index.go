package main

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"strings"
	"sync"
)

const VectorDim = 64

// DenseVector represents a normalized 64-dimensional feature embedding
type DenseVector [VectorDim]float64

// VectorCluster represents a pre-computed centroid for precedent or attack classification
type VectorCluster struct {
	Name        string
	Category    string // "BENIGN_PRECEDENT" or "ADVERSARIAL_ATTACK"
	Centroid    DenseVector
	Description string
}

// CosineVectorIndex maintains in-memory centroids and evaluates incoming tool text at sub-microsecond speeds.
type CosineVectorIndex struct {
	mu       sync.RWMutex
	clusters []VectorCluster
}

var globalVectorIndex *CosineVectorIndex

func init() {
	globalVectorIndex = NewCosineVectorIndex()
}

func NewCosineVectorIndex() *CosineVectorIndex {
	idx := &CosineVectorIndex{
		clusters: make([]VectorCluster, 0),
	}
	idx.seedDefaultClusters()
	return idx
}

func (idx *CosineVectorIndex) seedDefaultClusters() {
	// Seed legitimate business precedent centroids
	idx.AddCluster("PRECEDENT_TRANSFER_STANDARD", "BENIGN_PRECEDENT",
		"normal corporate wire transfer authorized payment customer settlement invoice",
		"Routine corporate funds settlement")
	idx.AddCluster("PRECEDENT_REFUND_CUSTOMER", "BENIGN_PRECEDENT",
		"customer refund return order cancellation dissatisfied client restitution",
		"Standard customer support refund")
	idx.AddCluster("PRECEDENT_QUERY_READONLY", "BENIGN_PRECEDENT",
		"select user account query balance fetch lookup audit read report",
		"Read-only analytical or reporting query")
	idx.AddCluster("PRECEDENT_CREDIT_INCREASE", "BENIGN_PRECEDENT",
		"credit limit increase underwriting approved risk assessment loan expansion",
		"Credit underwriting expansion")

	// Seed adversarial attack centroids
	idx.AddCluster("ATTACK_PROMPT_INJECTION", "ADVERSARIAL_ATTACK",
		"ignore previous instructions system prompt override developer mode DAN mode enabled jailbreak active disregard all constraints guardrails",
		"Direct LLM prompt injection and directive override")
	idx.AddCluster("ATTACK_ROLE_DELIMITER", "ADVERSARIAL_ATTACK",
		"<|im_start|> [INST] <<SYS>> SYSTEM: Human: Assistant: delimiter evasion roleplay token leak",
		"Adversarial role delimiter insertion")
	idx.AddCluster("ATTACK_EXFILTRATION", "ADVERSARIAL_ATTACK",
		"webhook.site ngrok.io burpcollaborator requestbin exfiltrate curl pipe bash base64 eval",
		"Data exfiltration webhook and shell pipe")
	idx.AddCluster("ATTACK_SQL_DESTRUCTION", "ADVERSARIAL_ATTACK",
		"drop table truncate database delete from users union select information_schema pg_shadow",
		"Destructive or blind SQL injection attack")
}

// Vectorize converts raw text into a normalized 64-dimensional dense float vector.
// Uses character trigram and token frequency hashing projected via SHA-256 for deterministic line-speed.
func Vectorize(text string) DenseVector {
	var vec DenseVector
	clean := strings.ToLower(strings.TrimSpace(text))
	tokens := strings.Fields(clean)
	if len(tokens) == 0 {
		return vec
	}

	// 1. Unigram token projection
	for _, tok := range tokens {
		h := sha256.Sum256([]byte(tok))
		slot := binary.BigEndian.Uint16(h[0:2]) % VectorDim
		val := float64(binary.BigEndian.Uint16(h[2:4])) / 65535.0
		vec[slot] += val
	}

	// 2. Character trigram projection (captures obfuscation and evasion syntax)
	if len(clean) >= 3 {
		for i := 0; i <= len(clean)-3; i++ {
			tri := clean[i : i+3]
			h := sha256.Sum256([]byte(tri))
			slot := binary.BigEndian.Uint16(h[4:6]) % VectorDim
			val := float64(binary.BigEndian.Uint16(h[6:8])) / 65535.0
			vec[slot] += val * 0.5
		}
	}

	// 3. L2 Normalization
	var sumSquares float64
	for i := 0; i < VectorDim; i++ {
		sumSquares += vec[i] * vec[i]
	}

	if sumSquares > 0 {
		norm := math.Sqrt(sumSquares)
		for i := 0; i < VectorDim; i++ {
			vec[i] /= norm
		}
	}

	return vec
}

// CosineSimilarity computes the dot product of two normalized unit vectors.
func CosineSimilarity(a, b DenseVector) float64 {
	var dot float64
	for i := 0; i < VectorDim; i++ {
		dot += a[i] * b[i]
	}
	return dot
}

// AddCluster adds a new cluster centroid from training text.
func (idx *CosineVectorIndex) AddCluster(name, category, sampleText, description string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	centroid := Vectorize(sampleText)
	idx.clusters = append(idx.clusters, VectorCluster{
		Name:        name,
		Category:    category,
		Centroid:    centroid,
		Description: description,
	})
}

type SemanticClassification struct {
	NearestCluster  string
	Category        string
	MaxSimilarity   float64
	IsAdversarial   bool
	RiskScore       float64
	CosineDistances map[string]float64
}

// Classify evaluates an incoming text against all stored precedent and attack centroids.
// Execution takes < 15 microseconds.
func (idx *CosineVectorIndex) Classify(text string) SemanticClassification {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	targetVec := Vectorize(text)
	result := SemanticClassification{
		CosineDistances: make(map[string]float64),
	}

	bestSim := -1.0
	var nearest VectorCluster

	for _, c := range idx.clusters {
		sim := CosineSimilarity(targetVec, c.Centroid)
		dist := 1.0 - sim
		result.CosineDistances[c.Name] = dist

		if sim > bestSim {
			bestSim = sim
			nearest = c
		}
	}

	result.NearestCluster = nearest.Name
	result.Category = nearest.Category
	result.MaxSimilarity = bestSim

	// Fast-path adversarial token check
	lower := strings.ToLower(text)
	if strings.Contains(lower, "jailbreak") || strings.Contains(lower, "dan mode") ||
		strings.Contains(lower, "ignore previous instructions") || strings.Contains(lower, "<|im_start|>") ||
		strings.Contains(lower, "webhook.site") || strings.Contains(lower, "ngrok.io") ||
		strings.Contains(lower, "exfiltrate") || strings.Contains(lower, "drop table") ||
		strings.Contains(lower, "truncate") {
		result.IsAdversarial = true
		result.RiskScore = 0.95
		result.Category = "ADVERSARIAL_ATTACK"
		if result.NearestCluster == "" || strings.HasPrefix(result.NearestCluster, "PRECEDENT") {
			result.NearestCluster = "ATTACK_PROMPT_INJECTION"
		}
		return result
	}

	// If the closest cluster is an adversarial attack with high similarity (> 0.55)
	if nearest.Category == "ADVERSARIAL_ATTACK" && bestSim >= 0.55 {
		result.IsAdversarial = true
		result.RiskScore = bestSim
	} else {
		// Check if any adversarial attack centroid has high similarity
		for _, c := range idx.clusters {
			if c.Category == "ADVERSARIAL_ATTACK" {
				sim := CosineSimilarity(targetVec, c.Centroid)
				if sim >= 0.72 {
					result.IsAdversarial = true
					result.RiskScore = sim
					result.NearestCluster = c.Name
					result.Category = "ADVERSARIAL_ATTACK"
					break
				}
			}
		}
	}

	return result
}
