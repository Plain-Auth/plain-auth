package sqlstore

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// The token endpoint refuses client credentials to a client registered
// without that grant, to a public client and to a client with no
// client-credentials scopes with unauthorized_client, and a grant the
// issuer does not offer with unsupported_grant_type, as another runtime
// does.
func TestOAuthTokenGrantRefusals(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			s, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"oauth-provider"}, schema.Options{})
			must(err)
			defer s.Close()
			const insert = `INSERT INTO "oauthClient" ("id","clientId","clientSecret","tokenEndpointAuthMethod","grantTypes","clientCredentialsScopes","scopes","redirectUris") VALUES (?,?,?,?,?,?,?,?)`
			for _, c := range []struct{ id, secret, method, grants, machineScopes string }{
				{"no-grant", "plain:shared", "client_secret_post", `["authorization_code"]`, `["reports"]`},
				{"public", "", "none", `["client_credentials"]`, `["reports"]`},
				{"no-scopes", "plain:shared", "client_secret_post", `["client_credentials"]`, `[]`},
				{"service", "plain:shared", "client_secret_post", `["client_credentials"]`, `["reports"]`},
			} {
				var secret any
				if c.secret != "" {
					secret = c.secret
				}
				_, err := s.db.ExecContext(ctx, s.bind(insert), c.id, c.id, secret, c.method, c.grants, c.machineScopes, `["reports"]`, `[]`)
				must(err)
			}
			verify := func(_ context.Context, supplied, stored string) (bool, error) { return stored == "plain:"+supplied, nil }
			build := func(grants []string) *auth.Auth {
				p, err := op.New(op.Options{Scopes: []string{"reports"}, GrantTypes: grants, Registration: op.RegistrationOptions{VerifySecret: verify}})
				must(err)
				off := false
				h, err := auth.New(auth.Options{BaseURL: "https://grants.example.test", Secret: strings.Repeat("s", 40), Store: s, Plugins: []auth.Plugin{p}, RateLimit: &off})
				must(err)
				return h
			}
			token := func(h *auth.Auth, form url.Values) (int, string) {
				t.Helper()
				r := httptest.NewRequest("POST", "https://grants.example.test/api/auth/oauth2/token", strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				var e struct{ Error string }
				json.Unmarshal(w.Body.Bytes(), &e)
				return w.Code, e.Error
			}
			all := build(nil)
			for _, id := range []string{"no-grant", "public", "no-scopes"} {
				form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}}
				if id != "public" {
					form.Set("client_secret", "shared")
				}
				if status, code := token(all, form); status != 400 || code != "unauthorized_client" {
					t.Fatal("a client credentials request was not refused with unauthorized_client", id, status, code)
				}
			}
			if status, code := token(all, url.Values{"grant_type": {"client_credentials"}, "client_id": {"service"}, "client_secret": {"shared"}}); status != 200 {
				t.Fatal("an eligible client credentials request was refused", status, code)
			}
			machineOnly := build([]string{"client_credentials"})
			if status, code := token(machineOnly, url.Values{"grant_type": {"authorization_code"}, "client_id": {"service"}, "client_secret": {"shared"}, "code": {"unused"}}); status != 400 || code != "unsupported_grant_type" {
				t.Fatal("a grant the issuer does not offer was not refused with unsupported_grant_type", status, code)
			}
		})
	}
}
