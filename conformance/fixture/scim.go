package main

import (
	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlstore"
	"github.com/Stonewrit/stonewrit-auth/plugins/scim"
)

func scimFixture(host *auth.Auth, store *sqlstore.Store) (*scim.Handler, error) {
	return scim.New(host, scim.Options{Store: store, Connections: []scim.Connection{{
		Directory:   scim.Directory{ID: "directory", ProvisioningDomainID: "tenant"},
		Credentials: []scim.Credential{{ID: "directory-key", Token: "local-directory-only"}},
	}}})
}
