package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type TenantTier string

const (
	TierStarter    TenantTier = "STARTER"
	TierGrowth     TenantTier = "GROWTH"
	TierEnterprise TenantTier = "ENTERPRISE"
)

type TenantRole string

const (
	RoleTenantAdmin TenantRole = "TENANT_ADMIN"
	RoleSecOps      TenantRole = "SECOPS"
	RoleAuditor     TenantRole = "AUDITOR"
	RoleAgentWorker TenantRole = "AGENT_WORKER"
)

type APIKeyMetadata struct {
	KeyHash        string
	Role           TenantRole
	AllowedActions []string
	CreatedAt      int64
	ExpiresAt      int64
	IsRevoked      bool
}

type Tenant struct {
	ID             string
	Name           string
	Tier           TenantTier
	HourlyQuota    float64
	CurrentSpend   float64
	SpendWindowEnd int64
	IsFrozen       bool
	APIKeys        map[string]APIKeyMetadata
	mu             sync.RWMutex
}

type TenantRegistry struct {
	mu      sync.RWMutex
	tenants map[string]*Tenant
}

var globalTenantRegistry *TenantRegistry

func init() {
	globalTenantRegistry = NewTenantRegistry()
}

func NewTenantRegistry() *TenantRegistry {
	reg := &TenantRegistry{
		tenants: make(map[string]*Tenant),
	}
	reg.seedDefaultTenants()
	return reg
}

func (r *TenantRegistry) seedDefaultTenants() {
	// 1. Enterprise FinTech Tenant
	t1 := &Tenant{
		ID:             "tenant_fintech_corp",
		Name:           "Apex Global FinTech",
		Tier:           TierEnterprise,
		HourlyQuota:    100000.0,
		SpendWindowEnd: time.Now().Add(1 * time.Hour).Unix(),
		APIKeys:        make(map[string]APIKeyMetadata),
	}
	// Add admin key: sk_live_tenant_fintech_corp_admin_secret
	adminHash := hashAPIKey("sk_live_tenant_fintech_corp_admin_secret")
	t1.APIKeys[adminHash] = APIKeyMetadata{
		KeyHash:        adminHash,
		Role:           RoleTenantAdmin,
		AllowedActions: []string{"*"},
		CreatedAt:      time.Now().Unix(),
		ExpiresAt:      time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
	// Add worker key: sk_live_tenant_fintech_corp_worker_key
	workerHash := hashAPIKey("sk_live_tenant_fintech_corp_worker_key")
	t1.APIKeys[workerHash] = APIKeyMetadata{
		KeyHash:        workerHash,
		Role:           RoleAgentWorker,
		AllowedActions: []string{"TRANSFER", "ISSUE_REFUND", "CREDIT_INCREASE", "QUERY"},
		CreatedAt:      time.Now().Unix(),
		ExpiresAt:      time.Now().Add(30 * 24 * time.Hour).Unix(),
	}
	r.tenants[t1.ID] = t1

	// 2. Healthcare AI Tenant
	t2 := &Tenant{
		ID:             "tenant_healthcare_ai",
		Name:           "BioPulse Medical Intelligence",
		Tier:           TierGrowth,
		HourlyQuota:    25000.0,
		SpendWindowEnd: time.Now().Add(1 * time.Hour).Unix(),
		APIKeys:        make(map[string]APIKeyMetadata),
	}
	hospWorkerHash := hashAPIKey("sk_live_tenant_healthcare_ai_worker_key")
	t2.APIKeys[hospWorkerHash] = APIKeyMetadata{
		KeyHash:        hospWorkerHash,
		Role:           RoleAgentWorker,
		AllowedActions: []string{"QUERY_PATIENT", "ROUTE_CLAIM", "AUDIT_RECORD"},
		CreatedAt:      time.Now().Unix(),
		ExpiresAt:      time.Now().Add(30 * 24 * time.Hour).Unix(),
	}
	r.tenants[t2.ID] = t2

	// 3. E-Commerce Hub Tenant
	t3 := &Tenant{
		ID:             "tenant_ecommerce_hub",
		Name:           "OmniShop Global",
		Tier:           TierStarter,
		HourlyQuota:    5000.0,
		SpendWindowEnd: time.Now().Add(1 * time.Hour).Unix(),
		APIKeys:        make(map[string]APIKeyMetadata),
	}
	ecomWorkerHash := hashAPIKey("sk_live_tenant_ecommerce_hub_worker_key")
	t3.APIKeys[ecomWorkerHash] = APIKeyMetadata{
		KeyHash:        ecomWorkerHash,
		Role:           RoleAgentWorker,
		AllowedActions: []string{"ISSUE_REFUND", "CANCEL_ORDER"},
		CreatedAt:      time.Now().Unix(),
		ExpiresAt:      time.Now().Add(30 * 24 * time.Hour).Unix(),
	}
	r.tenants[t3.ID] = t3
}

func hashAPIKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}

// AuthenticateTenantKey extracts and authenticates an incoming API key string.
// Form: sk_live_{tenant_id}_{secret}
func (r *TenantRegistry) AuthenticateTenantKey(rawKey string) (*Tenant, *APIKeyMetadata, error) {
	if rawKey == "" {
		return nil, nil, errors.New("missing API key")
	}

	if !strings.HasPrefix(rawKey, "sk_live_") {
		return nil, nil, errors.New("malformed API key format; expected sk_live_{tenant}_{secret}")
	}

	keyHash := hashAPIKey(rawKey)

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, tenant := range r.tenants {
		tenant.mu.RLock()
		meta, exists := tenant.APIKeys[keyHash]
		isFrozen := tenant.IsFrozen
		tenant.mu.RUnlock()

		if exists {
			if isFrozen {
				return tenant, nil, fmt.Errorf("tenant %s is administratively FROZEN", tenant.ID)
			}
			if meta.IsRevoked {
				return tenant, nil, errors.New("API key has been REVOKED")
			}
			if time.Now().Unix() > meta.ExpiresAt {
				return tenant, nil, errors.New("API key has EXPIRED")
			}
			return tenant, &meta, nil
		}
	}

	return nil, nil, errors.New("invalid or unassigned API key for tenant")
}

// RecordTenantSpend records an amount against the tenant's isolated hourly quota.
func (t *Tenant) RecordTenantSpend(amount float64) (bool, float64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().Unix()
	if now > t.SpendWindowEnd {
		t.CurrentSpend = 0
		t.SpendWindowEnd = now + 3600
	}

	if t.CurrentSpend+amount > t.HourlyQuota {
		return false, t.HourlyQuota - t.CurrentSpend, fmt.Errorf("tenant %s hourly quota exceeded: requested $%.2f exceeds remaining $%.2f",
			t.ID, amount, t.HourlyQuota-t.CurrentSpend)
	}

	t.CurrentSpend += amount
	return true, t.HourlyQuota - t.CurrentSpend, nil
}

// SetTenantFrozen sets the administrative kill-switch exclusively for this tenant.
func (r *TenantRegistry) SetTenantFrozen(tenantID string, frozen bool) error {
	r.mu.RLock()
	tenant, exists := r.tenants[tenantID]
	r.mu.RUnlock()

	if !exists {
		return fmt.Errorf("tenant %s not found", tenantID)
	}

	tenant.mu.Lock()
	defer tenant.mu.Unlock()
	tenant.IsFrozen = frozen
	return nil
}

// CheckRBAC verifies if the key's role has permission for the requested action.
func CheckRBAC(meta *APIKeyMetadata, action string) bool {
	if meta == nil {
		return false
	}
	if meta.Role == RoleTenantAdmin {
		return true
	}
	actUpper := strings.ToUpper(action)
	for _, a := range meta.AllowedActions {
		if a == "*" || strings.ToUpper(a) == actUpper {
			return true
		}
	}
	return false
}
