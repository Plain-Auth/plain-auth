package scim

import (
	"context"
	"errors"
	"time"
)

// Retirement records the durable progress of one directory's retirement.
type Retirement struct {
	ConnectionID         string     `json:"connectionId"`
	ProvisioningDomainID string     `json:"provisioningDomainId"`
	Status               string     `json:"status"`
	DecommissionedAt     *time.Time `json:"decommissionedAt"`
	CompletedAt          *time.Time `json:"completedAt"`
	RetryAfter           *time.Time `json:"retryAfter"`
	ReconciledUsers      int        `json:"reconciledUsers"`
	Batches              int        `json:"batches"`
}

// ManagedRetirement contains the credential catalog and its directory progress.
type ManagedRetirement struct {
	ManagedState
	Decommission Retirement `json:"decommission"`
}

type RetirementStore interface {
	SCIMDecommission(context.Context, Directory) (Retirement, error)
}
type ManagedRetirementStore interface {
	SCIMDecommissionManaged(context.Context, Directory, string) (ManagedRetirement, error)
}

// Decommission permanently retires a static or externally verified directory.
// Callers authorize the tenant administrator before invoking this server-only operation.
func (h *Handler) Decommission(ctx context.Context, d Directory) (Retirement, error) {
	if !identifier(d.ID) || !identifier(d.ProvisioningDomainID) {
		return Retirement{}, invalid("invalidValue", "Expected a directory and provisioning domain")
	}
	if managedDirectory(d) {
		return Retirement{}, invalid("invalidValue", "Retire a managed connection through its credential catalog")
	}
	if declared, ok := h.declared[d.ID]; ok && declared.ProvisioningDomainID != d.ProvisioningDomainID {
		return Retirement{}, ErrDomain
	}
	store, ok := h.store.(RetirementStore)
	if !ok {
		return Retirement{}, errors.New("scim: store does not support directory decommissioning")
	}
	return store.SCIMDecommission(ctx, d)
}

// Decommission permanently retires a managed connection and all its active credentials.
func (c *Catalog) Decommission(ctx context.Context, d Directory, actor string) (ManagedRetirement, error) {
	if !managedDirectory(d) {
		return ManagedRetirement{}, ErrManagedNotFound
	}
	if !identifier(actor) {
		return ManagedRetirement{}, invalid("invalidValue", "Expected an administrator ID")
	}
	store, ok := c.store.(ManagedRetirementStore)
	if !ok {
		return ManagedRetirement{}, errors.New("scim: store does not support managed directory decommissioning")
	}
	return store.SCIMDecommissionManaged(ctx, d, actor)
}
