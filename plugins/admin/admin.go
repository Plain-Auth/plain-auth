// Package admin provides role-checked user and session administration.
package admin

import (
	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/access"
)

type Options = authn.AdminOptions
type Permissions = authn.AdminPermissions

func New(options Options) (authn.Plugin, error) { return authn.NewAdmin(options) }

// defaultStatements lists every built-in administrative resource and action.
// No built-in role grants user:impersonate-admins.
var defaultStatements = access.Statements{
	"user":    {"create", "list", "set-role", "ban", "impersonate", "impersonate-admins", "delete", "set-password", "set-email", "set-phone", "get", "update"},
	"session": {"list", "revoke", "delete"},
}

// DefaultRoleControl defines the built-in user and session resources and
// their actions. Check a custom role with its NewRole before adding the role
// to Options.Roles. The plugin itself accepts any resource and action, so
// host handlers can check their own resources with HasPermission.
func DefaultRoleControl() *access.Control {
	control := access.New(defaultStatements)
	return &control
}

// DefaultRoles returns an independent copy of the built-in "admin" and
// "user" roles. A non-nil Options.Roles replaces the built-in roles, so start
// from this copy to keep or extend them.
func DefaultRoles() map[string]Permissions { return authn.DefaultAdminRoles() }
