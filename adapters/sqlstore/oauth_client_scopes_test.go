package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestOAuthClientCredentialsScopes(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			open := func() *Store {
				t.Helper()
				s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider", "admin"}, schema.Options{})
				must(err)
				t.Cleanup(func() { s.Close() })
				return s
			}
			s, peer := open(), open()
			write := func(q string, args ...any) {
				t.Helper()
				_, err := peer.db.ExecContext(ctx, peer.bind(q), args...)
				must(err)
			}
			var afterApproval func()
			opts := op.Options{Scopes: []string{"read", "write", "openid", "email", "profile", "offline_access"}, ImmutableClientIDs: []string{"operator-managed"},
				ClientReference: func(_ context.Context, a op.RegistrationAccess) (string, error) {
					if a.User.Name == "owner" {
						return "Team", nil
					}
					return "", nil
				},
				ClientPrivileges: func(_ context.Context, a op.ClientAccess) (bool, error) {
					if a.Headers.Get("X-Deny") == a.Action {
						return false, nil
					}
					if a.Action == "configure-client-credentials-scopes" {
						if a.User.Name != "operator" {
							return false, nil
						}
						if afterApproval != nil {
							afterApproval()
						}
					}
					return true, nil
				},
			}
			plugin, err := op.New(opts)
			must(err)
			const origin = "https://machine.example.test"
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("s", 40), Store: s, EmailAndPassword: true, Plugins: []auth.Plugin{plugin}})
			must(err)
			sdk, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
			must(err)
			account := func(name string) (http.Header, string) {
				t.Helper()
				var result client.EmailResult
				fields := client.SignUpRequest{Name: name, Email: name + "@machine.test", Password: "local machine scope password"}
				headers, err := sdk.DoWithHeaders(ctx, http.MethodPost, "/sign-up/email", fields, &result)
				must(err)
				r := httptest.NewRequest(http.MethodGet, origin, nil)
				for _, c := range (&http.Response{Header: headers}).Cookies() {
					r.AddCookie(c)
				}
				return r.Header, result.User.ID
			}
			owner, ownerID := account("owner")
			operator, operatorID := account("operator")
			create := func(id string, user, ref any, grants, method string) {
				t.Helper()
				write(`INSERT INTO "oauthClient" ("id","clientId","userId","referenceId","grantTypes","tokenEndpointAuthMethod","redirectUris","scopes","clientCredentialsScopes") VALUES (?,?,?,?,?,?,?,?,?)`,
					id, id, user, ref, grants, method, "[]", `["email"]`, `[]`)
			}
			const m2m = `["client_credentials"]`
			create("machine", ownerID, nil, m2m, "client_secret_basic")
			create("tenant", nil, "Team", m2m, "private_key_jwt")
			create("public", ownerID, nil, m2m, "none")
			create("interactive", ownerID, nil, `["authorization_code"]`, "client_secret_post")
			manager, err := op.NewClientManager(h, s, opts)
			must(err)
			opts.ClientPrivileges = nil
			defaultManager, err := op.NewClientManager(h, s, opts)
			must(err)
			denied := func(m *op.ClientManager, headers http.Header, id string, scopes []string, wantStatus int, wantCode string) {
				t.Helper()
				_, err := m.SetClientCredentialsScopes(ctx, headers, id, scopes)
				var problem *auth.OAuthError
				var api *auth.APIError
				if errors.As(err, &problem) && problem.Status == wantStatus && problem.Code == wantCode || errors.As(err, &api) && api.Status == wantStatus && api.Code == wantCode {
					return
				}
				t.Fatalf("expected %d %q on %s, got %v", wantStatus, wantCode, id, err)
			}
			set := func(m *op.ClientManager, actor http.Header, id string, input, want []string) {
				t.Helper()
				granted, err := m.SetClientCredentialsScopes(ctx, actor, id, input)
				must(err)
				if granted == nil || !slices.Equal(granted, want) {
					t.Fatalf("unexpected granted scopes: %v", granted)
				}
				var stored, delegated []byte
				must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT "clientCredentialsScopes","scopes" FROM "oauthClient" WHERE "clientId"=?`), id).Scan(&stored, &delegated))
				var machine, user []string
				must(json.Unmarshal(stored, &machine))
				must(json.Unmarshal(delegated, &user))
				if machine == nil || !slices.Equal(machine, want) || !slices.Equal(user, []string{"email"}) {
					t.Fatalf("wrong stored machine or user scopes: %s %s", stored, delegated)
				}
			}
			read := []string{"read"}
			denied(manager, nil, "machine", read, 401, "")
			denied(manager, owner, "machine", read, 401, "")
			denied(defaultManager, owner, "machine", read, 401, "")
			denied(defaultManager, operator, "tenant", nil, 401, "")
			set(defaultManager, owner, "tenant", nil, []string{})
			block := operator.Clone()
			block.Set("X-Deny", "update")
			denied(manager, block, "machine", read, 401, "")
			denied(manager, operator, "operator-managed", read, 400, "invalid_client")
			denied(manager, operator, "absent", read, 404, "not_found")
			denied(manager, operator, "public", read, 400, "invalid_client_metadata")
			denied(manager, operator, "interactive", read, 400, "invalid_client_metadata")
			denied(manager, operator, "machine", []string{"read", ""}, 400, "VALIDATION_ERROR")
			denied(manager, operator, "machine", []string{"read", " "}, 400, "VALIDATION_ERROR")
			set(manager, operator, "machine", []string{"\uFEFFwrite ", "read", "write"}, []string{"write", "read"})
			for _, invalid := range []string{"openid", "profile", "email", "offline_access", "unconfigured"} {
				denied(manager, operator, "machine", []string{invalid}, 400, "invalid_scope")
			}
			afterApproval = func() { write(`UPDATE "oauthClient" SET "userId"=? WHERE "clientId"='machine'`, operatorID) }
			denied(manager, operator, "machine", read, 401, "")
			afterApproval = func() { write(`UPDATE "oauthClient" SET "tokenEndpointAuthMethod"='none' WHERE "clientId"='machine'`) }
			denied(manager, operator, "machine", read, 400, "invalid_client_metadata")
			afterApproval = nil
			var existing []byte
			must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT "clientCredentialsScopes" FROM "oauthClient" WHERE "clientId"='machine'`)).Scan(&existing))
			var grants []string
			must(json.Unmarshal(existing, &grants))
			if !slices.Equal(grants, []string{"write", "read"}) {
				t.Fatal("a rejected grant change modified the stored ceiling")
			}
			set(defaultManager, operator, "machine", nil, []string{})
			set(manager, operator, "tenant", read, read)
			write(`UPDATE "session" SET "impersonatedBy"='fixture-admin' WHERE "userId"=?`, operatorID)
			denied(manager, operator, "tenant", nil, 403, "OWNER_SESSION_REQUIRED")
			result := httptest.NewRecorder()
			h.ServeHTTP(result, httptest.NewRequest(http.MethodPatch, origin+"/api/auth/admin/oauth2/update-client", nil))
			if result.Code != 404 {
				t.Fatalf("server-only operation reachable over HTTP: %d", result.Code)
			}
		})
	}
}
