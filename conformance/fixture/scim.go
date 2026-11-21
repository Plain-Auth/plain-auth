package main

import (
	"context"
	"os"
	"path/filepath"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlstore"
	"github.com/Stonewrit/stonewrit-auth/plugins/scim"
)

func scimFixture(host *auth.Auth, store *sqlstore.Store) (*scim.Handler, error) {
	options := scim.Options{Store: store, Connections: []scim.Connection{{
		Directory:   scim.Directory{ID: "directory", ProvisioningDomainID: "tenant"},
		Credentials: []scim.Credential{{ID: "directory-key", Token: "local-directory-only"}},
	}}}
	if os.Getenv("CONFORMANCE_SCIM_DYNAMIC") == "1" {
		path := filepath.Join(filepath.Dir(os.Args[1]), "scim-revoked")
		options.VerifyBearerToken = func(ctx context.Context, in scim.BearerInput) (*scim.BearerVerification, error) {
			if in.Headers.Get("X-Test-Route") != in.Method+" "+in.Path {
				return nil, nil
			}
			v := scim.BearerVerification{Connection: &scim.Directory{ID: "runtime", ProvisioningDomainID: "domain"}, CredentialID: "issued", Scopes: []string{scim.UsersRead, scim.UsersWrite}, ExpiresAt: time.Now().Add(time.Hour)}
			switch in.Token {
			case "application":
				if _, e := os.Stat(path); e == nil {
					return nil, nil
				} else if !os.IsNotExist(e) {
					return nil, e
				}
			case "declared":
				v.Connection = nil
				v.ConnectionID = "directory"
			case "expired":
				v.ExpiresAt = time.Now().Add(-time.Minute)
			case "read":
				v.Scopes = []string{scim.UsersRead}
			case "ambiguous":
				v.ConnectionID = "directory"
			case "collision":
				v.Connection.ID = "directory"
			case "moved":
				v.Connection.ProvisioningDomainID = "different"
			case "ba_scim_credential_test.invalid":
				// If accidentally passed to the application, this would authenticate.
			case "reserved":
				v.Connection.ID = "ba_scim_connection_local"
			default:
				return nil, nil
			}
			return &v, nil
		}
	}
	return scim.New(host, options)
}
