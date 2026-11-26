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

// RetirementStore retires a directory. An empty ProvisioningDomainID means
// the domain the connection is bound to; a connection without a binding then
// answers ErrNoBinding.
type RetirementStore interface {
	SCIMDecommission(context.Context, Directory) (Retirement, error)
}

// ErrNoBinding answers a retirement without a provisioning domain for a
// connection that was never bound to one.
var ErrNoBinding = errors.New("scim: the connection has no persisted binding")

type ManagedRetirementStore interface {
	SCIMDecommissionManaged(context.Context, Directory, string) (ManagedRetirement, error)
}

// Decommission permanently retires a static or externally verified directory.
// Callers authorize the tenant administrator before invoking this server-only operation.
// The provisioning domain may be left empty to retire the domain the
// connection is bound to; a connection never bound then answers
// ErrNoBinding, as in another runtime.
func (h *Handler) Decommission(ctx context.Context, d Directory) (Retirement, error) {
	d = trimmedDirectory(d)
	_, okID := apiText(d.ID, 1)
	_, okDomain := apiText(d.ProvisioningDomainID, 1)
	if !okID || d.ProvisioningDomainID != "" && !okDomain {
		return Retirement{}, invalid("invalidValue", "Expected a directory and provisioning domain")
	}
	// A managed connection is retired only through its catalog, which ends
	// its credentials too; another runtime retires its binding here and
	// leaves the catalog row active.
	if managedDirectory(d) {
		return Retirement{}, invalid("invalidValue", "Retire a managed connection through its credential catalog")
	}
	// A configured connection is retired only in its configured domain, so a
	// mistyped domain cannot bind it to another one for good; another runtime
	// retires it in any supplied domain.
	if declared, ok := h.declared[d.ID]; ok && d.ProvisioningDomainID != "" && declared.ProvisioningDomainID != d.ProvisioningDomainID {
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
	if d = trimmedDirectory(d); !managedDirectory(d) {
		return ManagedRetirement{}, ErrManagedNotFound
	}
	actor, ok := apiText(actor, 1)
	if !ok {
		return ManagedRetirement{}, invalid("invalidValue", "Expected an administrator ID")
	}
	store, ok := c.store.(ManagedRetirementStore)
	if !ok {
		return ManagedRetirement{}, errors.New("scim: store does not support managed directory decommissioning")
	}
	return store.SCIMDecommissionManaged(ctx, d, actor)
}
