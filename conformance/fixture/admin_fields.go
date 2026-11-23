package main

import (
	"os"

	auth "github.com/Plain-Org/plain-auth"
)

func fixtureAdminOptions() auth.AdminOptions {
	if os.Getenv("CONFORMANCE_ADMIN_FIELDS") != "1" {
		return auth.AdminOptions{}
	}
	return auth.AdminOptions{Roles: map[string]auth.AdminPermissions{
		"user": {}, "creator": {"user": {"create"}},
		"admin": {"user": {"create", "get", "list", "set-role", "set-email", "ban"}},
	}}
}
