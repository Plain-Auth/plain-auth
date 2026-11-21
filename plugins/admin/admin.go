// Package admin provides role-checked user and session administration.
package admin

import authn "github.com/FineStack/frost-auth"

type Options = authn.AdminOptions
type Permissions = authn.AdminPermissions

func New(options Options) (authn.Plugin, error) { return authn.NewAdmin(options) }
