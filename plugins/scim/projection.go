package scim

import (
	"context"
	"database/sql"
)

// ProjectionTx runs queries on the directory mutation's transaction. Bind
// converts ? parameters and double-quoted identifiers to the store dialect.
type ProjectionTx interface {
	Bind(string) string
	// Exact compares a trusted SQL column expression byte-for-byte on MySQL.
	Exact(string) string
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}
type AuthorizationGroup struct{ ID, ExternalID, DisplayName string }
type RoleMapping struct {
	Directory
	SCIMUserID, UserID string
	Group              AuthorizationGroup
}
type RoleLookup struct {
	Directory
	Role string
}
type IdentitySource struct {
	Directory
	SCIMUserID string
	Active     bool
}
type ProjectedGrant struct {
	RoleMapping
	Role, GrantKey string
}
type ProjectedUser struct {
	ProvisioningDomainID, UserID string
	Active                       bool
	Sources                      []IdentitySource
	Grants                       []ProjectedGrant
}

// Projection describes a trusted application's policy for one provisioning
// domain. All instances using the same PolicyID must run equivalent callbacks.
// Map and Exists are a pair; both may be omitted for lifecycle-only projection.
type Projection struct {
	PolicyID      string
	Map           func(context.Context, ProjectionTx, RoleMapping) ([]string, error)
	Exists        func(context.Context, ProjectionTx, RoleLookup) (bool, error)
	ReconcileUser func(context.Context, ProjectionTx, ProjectedUser) error
}
