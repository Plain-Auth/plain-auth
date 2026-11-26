package organization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/Plain-Org/plain-auth/plugins/access"
)

// StoredRoleGrants are the resource actions attached to a role in one organization.
type StoredRoleGrants struct {
	Role       string
	Permission access.Statements
}

// DecodeStoredRoleGrants checks the JSON shape used by the organization-roles schema.
func DecodeStoredRoleGrants(raw string) (access.Statements, error) {
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStoredRole, err)
	}
	grants, ok := permissionStatements(value)
	if !ok {
		return nil, ErrInvalidStoredRole
	}
	return grants, nil
}

// ErrInvalidStoredRole reports a stored role whose permission value is not a
// statement object.
var ErrInvalidStoredRole = errors.New("organization: invalid stored role permissions")

// WithStoredRoles returns the effective policy for a single organization. Each
// stored row extends only the role it names. The host's base policy stays immutable.
func (p RolePolicy) WithStoredRoles(rows []StoredRoleGrants) RolePolicy {
	if len(rows) == 0 {
		return p
	}
	base := p.roles
	if base == nil {
		base = defaultPermissions
	}
	p.roles = copyRoles(base)
	for _, row := range rows {
		grants := p.roles[row.Role]
		if grants == nil {
			grants = access.Statements{}
			p.roles[row.Role] = grants
		}
		for resource, actions := range row.Permission {
			for _, action := range actions {
				if !slices.Contains(grants[resource], action) {
					grants[resource] = append(grants[resource], action)
				}
			}
		}
	}
	return p
}

// OrganizationPermissionStore reads the live session, membership and role grants
// together. A dynamic role store uses the same policy within its mutations.
type OrganizationPermissionStore interface {
	CheckOrganizationPermission(ctx context.Context, sessionID, actorID, organizationID string, requested access.Statements) (bool, error)
}

// DynamicRoleStore resolves grants and validates requested invitation roles in
// the same organization scope as the protected operation.
type DynamicRoleStore interface {
	Store
	MemberRoleReader
	OrganizationPermissionStore
	PreparedInvitationStore
}

// DynamicRoleStoreProvider binds tenant-specific role resolution to an adapter.
type DynamicRoleStoreProvider interface {
	WithOrganizationDynamicRoles() (DynamicRoleStore, error)
}
