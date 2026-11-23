package organization

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Plain-Auth/plain-auth/plugins/access"
)

// RolePolicy is the host's immutable organization role configuration. Its zero
// value uses the built-in roles and grants the creator the owner membership.
type RolePolicy struct {
	creator string
	roles   map[string]access.Statements
}

// RolePolicyStoreProvider binds the policy to all organization operations on
// the returned adapter. Other services using the same pool keep their own policy.
type RolePolicyStoreProvider interface {
	OrganizationRolePolicy() RolePolicy
	WithOrganizationRolePolicy(RolePolicy) (Store, error)
}

func copyRoles(source map[string]access.Statements) map[string]access.Statements {
	if source == nil {
		return nil
	}
	roles := make(map[string]access.Statements, len(source))
	for name, statements := range source {
		grants := make(access.Statements, len(statements))
		for resource, actions := range statements {
			grants[resource] = slices.Clone(actions)
		}
		roles[name] = grants
	}
	return roles
}

// DefaultRoles returns an independent copy of the built-in grants for hosts
// that want to add or change selected roles.
func DefaultRoles() map[string]access.Statements { return copyRoles(defaultPermissions) }

// NewRolePolicy copies the supplied grants for use by services, custom storage
// adapters and local permission checks. A nil role map selects the defaults.
func NewRolePolicy(creator string, roles map[string]access.Statements) (RolePolicy, error) {
	valid := func(name string) bool {
		return name != "" && strings.TrimSpace(name) == name && !strings.Contains(name, ",")
	}
	if creator != "" && !valid(creator) {
		return RolePolicy{}, fmt.Errorf("organization: invalid creator role %q", creator)
	}
	for name := range roles {
		if !valid(name) {
			return RolePolicy{}, fmt.Errorf("organization: invalid role name %q", name)
		}
	}
	return RolePolicy{creator: creator, roles: copyRoles(roles)}, nil
}

// CreatorRole is the role assigned at creation and protected from removal
// when held by the last creator in an organization.
func (p RolePolicy) CreatorRole() string {
	if p.creator == "" {
		return "owner"
	}
	return p.creator
}

// Recognizes reports whether the name can be assigned to a member.
func (p RolePolicy) Recognizes(name string) bool {
	_, configured := p.roles[name]
	return configured || builtinRole(name)
}

// HasPermission requires one of the member's roles to grant the whole request.
func (p RolePolicy) HasPermission(membership string, request access.Statements) bool {
	grants := p.roles
	if grants == nil {
		grants = defaultPermissions
	}
	for role := range strings.SplitSeq(membership, ",") {
		if grants[strings.TrimSpace(role)].AllowsAll(request) {
			return true
		}
	}
	return false
}

// HasAction checks one resource action in a storage operation.
func (p RolePolicy) HasAction(membership, resource, action string) bool {
	return p.HasPermission(membership, access.Statements{resource: {action}})
}
