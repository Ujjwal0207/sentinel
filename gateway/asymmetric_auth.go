package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// -------------------------------------------------------------------
// PHASE 3.3: Asymmetric Cryptographic Identity (Ed25519)
// -------------------------------------------------------------------

// AgentKeyRegistry manages public keys for all agents in the swarm
type AgentKeyRegistry struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
}

var globalKeyRegistry = NewAgentKeyRegistry()

func NewAgentKeyRegistry() *AgentKeyRegistry {
	return &AgentKeyRegistry{
		keys: make(map[string]ed25519.PublicKey),
	}
}

func (r *AgentKeyRegistry) RegisterKey(agentID string, pubKey ed25519.PublicKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[agentID] = pubKey
}

func (r *AgentKeyRegistry) GetKey(agentID string) (ed25519.PublicKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	key, exists := r.keys[agentID]
	return key, exists
}

func (r *AgentKeyRegistry) RemoveKey(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.keys, agentID)
}

func (r *AgentKeyRegistry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = make(map[string]ed25519.PublicKey)
}

// SignCanonicalPayloadEd25519 signs the canonical message representation with an Ed25519 private key
func SignCanonicalPayloadEd25519(privKey ed25519.PrivateKey, agentID, ts, nonce string, bodyHash []byte) string {
	canonical := fmt.Sprintf("%s|%s|%s|%s", agentID, ts, nonce, hex.EncodeToString(bodyHash))
	sig := ed25519.Sign(privKey, []byte(canonical))
	return hex.EncodeToString(sig)
}

// VerifyCanonicalPayloadEd25519 verifies an Ed25519 signature over canonical request fields
func VerifyCanonicalPayloadEd25519(pubKey ed25519.PublicKey, agentID, ts, nonce string, bodyHash []byte, sigHex string) bool {
	sigBytes, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	canonical := fmt.Sprintf("%s|%s|%s|%s", agentID, ts, nonce, hex.EncodeToString(bodyHash))
	return ed25519.Verify(pubKey, []byte(canonical), sigBytes)
}

// -------------------------------------------------------------------
// PHASE 3.3: UCAN (User-Controlled Authorization Networks) Delegation DAG
// -------------------------------------------------------------------

// UCANCapability defines attenuated permission boundaries granted in a delegation token
type UCANCapability struct {
	With      string   `json:"with"`                 // Resource URI / namespace, e.g. "financial:transaction"
	Can       string   `json:"can"`                  // Action verb, e.g. "execute"
	MaxAmount float64  `json:"max_amount,omitempty"` // Ceiling on financial mutations
	Currency  string   `json:"currency,omitempty"`   // Currency restriction (e.g. "USD")
	Actions   []string `json:"actions,omitempty"`    // Whitelisted actions, e.g. ["REFUND", "TRANSFER"]
	Recipient string   `json:"recipient,omitempty"`  // Whitelisted recipient or pattern
}

// UCANToken represents a cryptographically signed, scope-attenuated delegation token
type UCANToken struct {
	Issuer       string           `json:"iss"`                  // Agent ID or DID who signs the delegation
	Audience     string           `json:"aud"`                  // Agent ID or DID who receives the delegation
	Capabilities []UCANCapability `json:"att"`                  // Attenuated capabilities
	ExpiresAt    int64            `json:"exp"`                  // Unix timestamp of token expiration
	NotBefore    int64            `json:"nbf,omitempty"`        // Unix timestamp before which token is invalid
	Nonce        string           `json:"nonce"`                // Replay prevention nonce
	Proof        *UCANToken       `json:"prf,omitempty"`        // Parent UCAN token in delegation DAG
	Signature    string           `json:"sig"`                  // Ed25519 signature (hex-encoded) over canonical payload
}

// CanonicalPayload generates a deterministic byte representation for signing and verification
func (u *UCANToken) CanonicalPayload() []byte {
	// Sort / deterministic serialization of capabilities
	capsJSON, _ := json.Marshal(u.Capabilities)
	canonical := fmt.Sprintf("%s|%s|%s|%d|%d|%s",
		strings.TrimSpace(u.Issuer),
		strings.TrimSpace(u.Audience),
		string(capsJSON),
		u.ExpiresAt,
		u.NotBefore,
		strings.TrimSpace(u.Nonce),
	)
	hash := sha256.Sum256([]byte(canonical))
	return hash[:]
}

// Sign signs the UCAN token using the issuer's Ed25519 private key
func (u *UCANToken) Sign(privKey ed25519.PrivateKey) {
	hash := u.CanonicalPayload()
	sig := ed25519.Sign(privKey, hash)
	u.Signature = hex.EncodeToString(sig)
}

// VerifySignature verifies the token's cryptographic signature against the issuer's public key
func (u *UCANToken) VerifySignature(pubKey ed25519.PublicKey) bool {
	sigBytes, err := hex.DecodeString(strings.TrimSpace(u.Signature))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	hash := u.CanonicalPayload()
	return ed25519.Verify(pubKey, hash, sigBytes)
}

// VerifyUCANDelegationChain validates a complete UCAN delegation DAG from root authority to leaf agent
func VerifyUCANDelegationChain(
	leafToken *UCANToken,
	executingAgent string,
	targetAction string,
	payload map[string]interface{},
	now time.Time,
	keyRegistry *AgentKeyRegistry,
	trustedRootAuthorities map[string]bool,
) (bool, int, string) {
	if leafToken == nil {
		return false, http.StatusBadRequest, "UCAN_TOKEN_NULL: Leaf delegation token is nil"
	}

	// 1. Target Audience Match: Leaf token audience must match the executing agent
	if leafToken.Audience != executingAgent {
		return false, http.StatusForbidden, fmt.Sprintf("UCAN_AUDIENCE_MISMATCH: Leaf audience (%s) does not match executing agent (%s)", leafToken.Audience, executingAgent)
	}

	// 2. Traverse and validate delegation chain up to the root
	currentToken := leafToken
	var visitedIssuers = make(map[string]bool)
	var chain []*UCANToken

	for currentToken != nil {
		// Circular delegation cycle check
		if visitedIssuers[currentToken.Issuer] {
			return false, http.StatusForbidden, fmt.Sprintf("UCAN_CIRCULAR_DELEGATION: Cycle detected on issuer (%s)", currentToken.Issuer)
		}
		visitedIssuers[currentToken.Issuer] = true
		chain = append(chain, currentToken)

		// A. Temporal Validation
		if now.Unix() >= currentToken.ExpiresAt {
			return false, http.StatusForbidden, fmt.Sprintf("UCAN_TOKEN_EXPIRED: Token issued by (%s) expired at %d (current %d)", currentToken.Issuer, currentToken.ExpiresAt, now.Unix())
		}
		if currentToken.NotBefore > 0 && now.Unix() < currentToken.NotBefore {
			return false, http.StatusForbidden, fmt.Sprintf("UCAN_TOKEN_NOT_YET_VALID: Token issued by (%s) not valid before %d", currentToken.Issuer, currentToken.NotBefore)
		}

		// B. Cryptographic Signature Verification
		pubKey, hasKey := keyRegistry.GetKey(currentToken.Issuer)
		if !hasKey {
			return false, http.StatusUnauthorized, fmt.Sprintf("UCAN_UNKNOWN_ISSUER_KEY: No public key registered for token issuer (%s)", currentToken.Issuer)
		}
		if !currentToken.VerifySignature(pubKey) {
			return false, http.StatusUnauthorized, fmt.Sprintf("UCAN_SIGNATURE_INVALID: Cryptographic signature failed on token issued by (%s)", currentToken.Issuer)
		}

		// Check parent link
		if currentToken.Proof != nil {
			parent := currentToken.Proof
			// Custody / Handshake Check: Parent Audience MUST match Child Issuer
			if parent.Audience != currentToken.Issuer {
				return false, http.StatusForbidden, fmt.Sprintf("UCAN_DELEGATION_CHAIN_BROKEN: Parent audience (%s) does not match child issuer (%s)", parent.Audience, currentToken.Issuer)
			}

			// Scope Attenuation Check: Child cannot expand privileges beyond parent
			// 1. Expiration monotonic attenuation: child cannot outlive parent
			if currentToken.ExpiresAt > parent.ExpiresAt {
				return false, http.StatusForbidden, fmt.Sprintf("UCAN_PRIVILEGE_ESCALATION: Child token lifetime (%d) exceeds parent token lifetime (%d)", currentToken.ExpiresAt, parent.ExpiresAt)
			}

			// 2. Capability Monotonic Attenuation
			for _, childCap := range currentToken.Capabilities {
				parentPermits := false
				for _, parentCap := range parent.Capabilities {
					if parentCap.With == childCap.With || parentCap.With == "*" {
						// Amount Attenuation
						if parentCap.MaxAmount > 0 {
							if childCap.MaxAmount == 0 || childCap.MaxAmount > parentCap.MaxAmount {
								return false, http.StatusForbidden, fmt.Sprintf("UCAN_PRIVILEGE_ESCALATION: Child amount limit ($%.2f) exceeds parent ceiling ($%.2f)", childCap.MaxAmount, parentCap.MaxAmount)
							}
						}
						// Currency Attenuation
						if parentCap.Currency != "" && childCap.Currency != "" && parentCap.Currency != childCap.Currency {
							return false, http.StatusForbidden, fmt.Sprintf("UCAN_PRIVILEGE_ESCALATION: Child currency (%s) conflicts with parent currency (%s)", childCap.Currency, parentCap.Currency)
						}
						// Recipient Attenuation
						if parentCap.Recipient != "" && childCap.Recipient != "" && parentCap.Recipient != childCap.Recipient {
							return false, http.StatusForbidden, fmt.Sprintf("UCAN_PRIVILEGE_ESCALATION: Child recipient (%s) conflicts with parent recipient restriction (%s)", childCap.Recipient, parentCap.Recipient)
						}
						// Actions Attenuation
						if len(parentCap.Actions) > 0 {
							parentActionMap := make(map[string]bool)
							for _, a := range parentCap.Actions {
								parentActionMap[strings.ToUpper(strings.TrimSpace(a))] = true
							}
							for _, ca := range childCap.Actions {
								if !parentActionMap[strings.ToUpper(strings.TrimSpace(ca))] {
									return false, http.StatusForbidden, fmt.Sprintf("UCAN_PRIVILEGE_ESCALATION: Child requests action (%s) not permitted by parent capability", ca)
								}
							}
						}
						parentPermits = true
						break
					}
				}
				if !parentPermits {
					return false, http.StatusForbidden, fmt.Sprintf("UCAN_PRIVILEGE_ESCALATION: Parent does not grant capability namespace (%s)", childCap.With)
				}
			}

			currentToken = parent
		} else {
			// Reached root token: verify root authority
			if !trustedRootAuthorities[currentToken.Issuer] {
				return false, http.StatusForbidden, fmt.Sprintf("UCAN_UNTRUSTED_ROOT_ISSUER: Root delegation issuer (%s) is not in trusted root authority directory", currentToken.Issuer)
			}
			break
		}
	}

	// 3. Match Requested Action & Payload Against Leaf Capabilities
	hasMatchingCap := false
	var capReason string

	// Extract payload details
	_, nativeAmount, _ := extractNativeFinancialAmount(payload)
	recipient := extractPayloadRecipient(payload)
	currency := extractRawCurrency(payload)

	for _, cap := range leafToken.Capabilities {
		// Action Check
		actionAllowed := false
		if len(cap.Actions) == 0 || cap.Actions[0] == "*" {
			actionAllowed = true
		} else {
			for _, a := range cap.Actions {
				if strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(targetAction)) {
					actionAllowed = true
					break
				}
			}
		}

		if !actionAllowed {
			capReason = fmt.Sprintf("Target action (%s) not in permitted UCAN actions %v", targetAction, cap.Actions)
			continue
		}

		// Amount Ceiling Check
		if cap.MaxAmount > 0 && nativeAmount > cap.MaxAmount {
			return false, http.StatusForbidden, fmt.Sprintf("UCAN_CAPABILITY_EXCEEDED: Requested amount ($%.2f) exceeds UCAN delegated limit ($%.2f)", nativeAmount, cap.MaxAmount)
		}

		// Currency Check
		if cap.Currency != "" && currency != "" && !strings.EqualFold(cap.Currency, currency) {
			return false, http.StatusForbidden, fmt.Sprintf("UCAN_CAPABILITY_EXCEEDED: Requested currency (%s) diverges from UCAN delegated currency (%s)", currency, cap.Currency)
		}

		// Recipient Check
		if cap.Recipient != "" && recipient != "" && !strings.EqualFold(cap.Recipient, recipient) {
			return false, http.StatusForbidden, fmt.Sprintf("UCAN_CAPABILITY_EXCEEDED: Recipient (%s) does not match UCAN delegated recipient (%s)", recipient, cap.Recipient)
		}

		hasMatchingCap = true
		break
	}

	if !hasMatchingCap {
		if capReason == "" {
			capReason = fmt.Sprintf("No matching UCAN capability for action (%s)", targetAction)
		}
		return false, http.StatusForbidden, "UCAN_CAPABILITY_MISMATCH: " + capReason
	}

	return true, http.StatusOK, "UCAN_DELEGATION_VERIFIED"
}

