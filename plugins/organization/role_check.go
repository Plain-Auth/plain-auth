package organization

import (
	"context"
	"errors"
	"slices"

	"github.com/Plain-Auth/plain-auth/plugins/access"
)

// RolePermissionCheck asks whether a membership role grants permissions in an
// organization. Role may list several comma-separated roles.
type RolePermissionCheck struct {
	OrganizationID string
	Role           string
	Permissions    access.Statements
	// AllowCreatorAllPermissions lets the creator role pass every check.
	AllowCreatorAllPermissions bool
}

// OrganizationRolePolicyStore resolves the role policy in effect for one
// organization, including the roles it stored with dynamic access control.
type OrganizationRolePolicyStore interface {
	OrganizationRolePolicyFor(ctx context.Context, organizationID string) (RolePolicy, error)
}

// HasRolePermission reports whether check.Role grants every requested
// permission in the organization. With DynamicAccessControl it merges the
// organization's stored roles with the configured ones. It does not look up a
// member, so the caller supplies the role it already holds.
func (service *Service) HasRolePermission(ctx context.Context, check RolePermissionCheck) (bool, error) {
	if len(check.Permissions) == 0 {
		return false, nil
	}
	o := service.options
	policy := o.rolePolicy
	if o.DynamicAccessControl && check.OrganizationID != "" {
		store, ok := o.Store.(OrganizationRolePolicyStore)
		if !ok {
			return false, errors.New("organization: role checks with dynamic access control require an OrganizationRolePolicyStore")
		}
		var err error
		if policy, err = store.OrganizationRolePolicyFor(ctx, check.OrganizationID); err != nil {
			return false, err
		}
	}
	if check.AllowCreatorAllPermissions && slices.Contains(NormalizeRoles(check.Role), policy.CreatorRole()) {
		return true, nil
	}
	return policy.HasPermission(check.Role, check.Permissions), nil
}
