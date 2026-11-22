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

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/plugins/apikey"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestOAuthClientDirectory(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			wantError := func(err error, status int, code string) {
				t.Helper()
				var p *auth.APIError
				if !errors.As(err, &p) || p.Status != status || p.Code != code {
					t.Fatalf("want %d %q, got %v", status, code, err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			open := func() *Store {
				t.Helper()
				s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider", "admin", "api-key"}, schema.Options{})
				must(err)
				t.Cleanup(func() { s.Close() })
				return s
			}
			store, peer := open(), open()
			const origin = "https://directory.example.test"
			var rejectReference bool
			p, err := op.New(op.Options{Registration: op.RegistrationOptions{Enabled: true},
				ClientReference: func(_ context.Context, a op.RegistrationAccess) (string, error) {
					if rejectReference {
						return "", errors.New("tenant lookup failed")
					}
					switch a.User.Name {
					case "team-one", "team-two":
						return "Team", nil
					case "case-variant":
						return "team", nil
					}
					return "", nil
				},
			})
			must(err)
			keys, err := apikey.New(apikey.Options{Store: store, EnableSession: true, DisableRateLimit: true})
			must(err)
			off := false
			h, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 40), BaseURL: origin, EmailAndPassword: true, RateLimit: &off, Plugins: []auth.Plugin{p, keys.Plugin()}})
			must(err)
			account := func(name string) (*client.Client, string) {
				t.Helper()
				c, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
				must(err)
				a, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: name, Email: name + "@directory.test", Password: "local directory test password"})
				must(err)
				return c, a.User.ID
			}
			personal, ownerID := account("individual")
			team, _ := account("team-one")
			member, memberID := account("team-two")
			variant, _ := account("case-variant")
			other, otherID := account("visitor")
			exec := func(q string, args ...any) {
				t.Helper()
				_, err := peer.db.ExecContext(ctx, peer.bind(q), args...)
				must(err)
			}
			m := op.RegistrationMetadata{Contacts: []string{"support@example.test"}, RedirectURIs: []string{"https://client.example.test/cb"}}
			owned, err := personal.RegisterOAuthClient(ctx, m)
			must(err)
			shared, err := team.RegisterOAuthClient(ctx, m)
			must(err)
			exec(`UPDATE "oauthClient" SET "metadata"=? WHERE "clientId"=?`, `{"theme":{"accent":"blue"},"client_secret":"forged","clientSecret":"forged","user_id":"forged","grant_types":["forged"],"resources":["forged"],"SCOPE":"extension"}`, owned.ClientID)
			details, err := personal.OAuthClient(ctx, owned.ClientID)
			must(err)
			if details.UserID == nil || *details.UserID != ownerID || details.SecretExpiresAt == nil || *details.SecretExpiresAt != 0 || details.IssuedAt == nil || *details.IssuedAt != owned.IssuedAt || details.Scope == nil || *details.Scope != owned.Scope || !slices.Equal(details.RedirectURIs, m.RedirectURIs) || len(details.Extensions) != 2 || string(details.Extensions["SCOPE"]) != `"extension"` {
				t.Fatal("incomplete owner view or reserved fields exposed")
			}
			raw, err := json.Marshal(details)
			must(err)
			var props map[string]json.RawMessage
			must(json.Unmarshal(raw, &props))
			for _, k := range []string{"client_secret", "clientSecret", "resources", "client_credentials_scopes"} {
				if _, ok := props[k]; ok {
					t.Fatalf("owner read returned %s", k)
				}
			}
			if _, ok := props["theme"]; !ok {
				t.Fatal("SDK lost host metadata")
			}
			show, err := other.PublicOAuthClient(ctx, owned.ClientID)
			must(err)
			if show.ClientID != owned.ClientID || show.RedirectURIs == nil || len(show.RedirectURIs) != 0 || !slices.Equal(show.Contacts, m.Contacts) {
				t.Fatal("public projection exposed a redirect or lost contacts")
			}
			getIDs := func(c *client.Client) []string {
				t.Helper()
				entries, err := c.OAuthClients(ctx)
				must(err)
				if entries == nil {
					t.Fatal("nil client list")
				}
				var ids []string
				for _, entry := range entries {
					ids = append(ids, entry.ClientID)
				}
				return ids
			}
			if !slices.Equal(getIDs(member), []string{shared.ClientID}) || len(getIDs(variant)) != 0 {
				t.Fatal("tenant ownership or case-sensitive list filter failed")
			}
			_, err = variant.OAuthClient(ctx, shared.ClientID)
			wantError(err, 401, "")
			_, err = member.OAuthClient(ctx, owned.ClientID)
			wantError(err, 401, "")
			// A personal owner takes precedence on a mixed record, including when listing a tenant.
			exec(`UPDATE "oauthClient" SET "userId"=? WHERE "clientId"=?`, otherID, shared.ClientID)
			if len(getIDs(member)) != 0 || !slices.Equal(getIDs(other), []string{shared.ClientID}) {
				t.Fatal("tenant list exposed another user's registration")
			}
			_, err = member.OAuthClient(ctx, shared.ClientID)
			wantError(err, 401, "")
			exec(`UPDATE "oauthClient" SET "userId"=NULL, "referenceId"=? WHERE "clientId"=?`, "team", shared.ClientID)
			if !slices.Equal(getIDs(variant), []string{shared.ClientID}) || len(getIDs(member)) != 0 {
				t.Fatal("ownership reassignment was stale")
			}
			_, err = member.OAuthClient(ctx, shared.ClientID)
			wantError(err, 401, "")
			_, err = variant.OAuthClient(ctx, shared.ClientID)
			must(err)
			exec(`UPDATE "oauthClient" SET "disabled"=? WHERE "clientId"=?`, true, shared.ClientID)
			_, err = other.PublicOAuthClient(ctx, shared.ClientID)
			wantError(err, 404, "not_found")
			hidden, err := variant.OAuthClient(ctx, shared.ClientID)
			must(err)
			if hidden.Disabled == nil || !*hidden.Disabled {
				t.Fatal("owner cannot inspect disabled registration")
			}
			rejectReference = true
			_, err = personal.OAuthClient(ctx, owned.ClientID)
			must(err)
			_, err = variant.OAuthClient(ctx, shared.ClientID)
			wantError(err, 500, "INTERNAL_SERVER_ERROR")
			_, err = member.OAuthClients(ctx)
			wantError(err, 500, "INTERNAL_SERVER_ERROR")
			rejectReference = false
			key, err := personal.CreateAPIKey(ctx, client.CreateAPIKeyRequest{Name: "integration"})
			must(err)
			for _, path := range []string{"get-client?client_id=" + owned.ClientID, "get-clients"} {
				r := httptest.NewRequest(http.MethodGet, origin+"/api/auth/oauth2/"+path, nil)
				r.Header.Set("X-API-Key", key.Secret)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != 403 || !strings.Contains(w.Body.String(), "OWNER_SESSION_REQUIRED") {
					t.Fatal("application credential could manage OAuth clients", w.Code)
				}
			}
			exec(`UPDATE "session" SET "impersonatedBy"=? WHERE "userId"=?`, "fixture-admin", memberID)
			_, err = member.OAuthClients(ctx)
			wantError(err, 403, "OWNER_SESSION_REQUIRED")
			_, err = member.OAuthClient(ctx, owned.ClientID)
			wantError(err, 403, "OWNER_SESSION_REQUIRED")
			exec(`DELETE FROM "oauthClient" WHERE "clientId"=?`, owned.ClientID)
			_, err = personal.OAuthClient(ctx, owned.ClientID)
			wantError(err, 404, "not_found")
		})
	}
}
