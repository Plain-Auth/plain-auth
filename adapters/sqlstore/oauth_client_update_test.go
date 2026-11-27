package sqlstore

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// An owner replaces registration fields through /oauth2/update-client: the
// merged registration passes the creation rules, fields an owner cannot
// change are ignored, another owner and trusted clients are refused, and a
// client without the machine grant loses its machine scopes.
func TestOAuthClientUpdate(t *testing.T) {
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
			t.Cleanup(func() { s.Close() })
			p, err := op.New(op.Options{Scopes: []string{"openid", "reports", "extra"}, ImmutableClientIDs: []string{"trusted"}})
			must(err)
			const origin = "https://update.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("u", 40), Store: s, EmailAndPassword: true, Plugins: []auth.Plugin{p}, RateLimit: &off})
			must(err)
			account := func(email string) (*client.Client, string) {
				t.Helper()
				c, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
				must(err)
				signed, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: email, Password: "local update test password"})
				must(err)
				return c, h.SessionCookie(*signed.Token, true).String()
			}
			owner, cookie := account("owner@update.test")
			_, other := account("other@update.test")
			app, err := owner.CreateOAuthClient(ctx, op.RegistrationMetadata{RedirectURIs: []string{"https://app.example.test/cb"}, Scope: "reports",
				GrantTypes: []string{"authorization_code", "client_credentials"}})
			must(err)
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "oauthClient" SET "clientCredentialsScopes"=? WHERE "clientId"=?`), `["reports"]`, app.ClientID)
			must(err)
			post := func(cookie string, body map[string]any) *httptest.ResponseRecorder {
				raw, _ := json.Marshal(body)
				r := httptest.NewRequest("POST", origin+"/api/auth/oauth2/update-client", bytes.NewReader(raw))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", origin)
				if cookie != "" {
					r.Header.Set("Cookie", cookie)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			stored := func(column string) string {
				t.Helper()
				var v *string
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT "`+column+`" FROM "oauthClient" WHERE "clientId"=?`), app.ClientID).Scan(&v))
				if v == nil {
					return ""
				}
				return *v
			}
			for _, tc := range []struct {
				cookie string
				body   map[string]any
				status int
				want   string
			}{
				{cookie, map[string]any{"client_id": app.ClientID, "update": "x"}, 400, `"message":"[body.update] Invalid input: expected object, received string"`},
				{"", map[string]any{"client_id": app.ClientID, "update": map[string]any{}}, 401, ""},
				{other, map[string]any{"client_id": app.ClientID, "update": map[string]any{"client_name": "Stolen"}}, 401, ""},
				{cookie, map[string]any{"client_id": "trusted", "update": map[string]any{"client_name": "X"}}, 400, `"error_description":"trusted clients must be updated manually"`},
				{cookie, map[string]any{"client_id": "absent", "update": map[string]any{"client_name": "X"}}, 404, `"error":"not_found"`},
				{cookie, map[string]any{"client_id": app.ClientID, "update": map[string]any{"scope": "write"}}, 400, `"error_description":"cannot request scope write"`},
				{cookie, map[string]any{"client_id": app.ClientID, "update": map[string]any{"redirect_uris": []string{"http://example.test/cb"}}}, 400, `"error":"invalid_redirect_uri"`},
			} {
				if w := post(tc.cookie, tc.body); w.Code != tc.status || !strings.Contains(w.Body.String(), tc.want) {
					t.Fatal("an update was not refused as expected", tc.body, w.Code, w.Body.String())
				}
			}
			// An allowed update writes the merged fields and ignores the
			// fields an owner cannot change.
			w := post(cookie, map[string]any{"client_id": app.ClientID, "update": map[string]any{
				"client_name": "Reports", "redirect_uris": []string{"https://app.example.test/new"}, "scope": "reports extra",
				"skip_consent": true, "token_endpoint_auth_method": "none", "client_credentials_scopes": []string{"extra"}}})
			var updated map[string]any
			must(json.Unmarshal(w.Body.Bytes(), &updated))
			if w.Code != 200 || updated["client_name"] != "Reports" || updated["scope"] != "reports extra" || updated["client_secret"] != nil {
				t.Fatal("the update was not applied", w.Code, w.Body.String())
			}
			if !sameJSON(stored("redirectUris"), `["https://app.example.test/new"]`) || !sameJSON(stored("scopes"), `["reports","extra"]`) || stored("tokenEndpointAuthMethod") != "client_secret_basic" ||
				!sameJSON(stored("clientCredentialsScopes"), `["reports"]`) || stored("skipConsent") == "1" || stored("skipConsent") == "true" {
				t.Fatal("the stored client did not take only the owner's fields", stored("redirectUris"), stored("scopes"), stored("clientCredentialsScopes"))
			}
			// Dropping the machine grant clears the machine scopes.
			if w := post(cookie, map[string]any{"client_id": app.ClientID, "update": map[string]any{"grant_types": []string{"authorization_code"}}}); w.Code != 200 || !sameJSON(stored("clientCredentialsScopes"), `[]`) {
				t.Fatal("dropping the machine grant kept the machine scopes", w.Code, w.Body.String(), stored("clientCredentialsScopes"))
			}
			// An empty update returns the client unchanged.
			if w := post(cookie, map[string]any{"client_id": app.ClientID, "update": map[string]any{"disabled": true}}); w.Code != 200 || stored("disabled") == "1" || stored("disabled") == "true" {
				t.Fatal("an update of ignored fields changed the client", w.Code, w.Body.String())
			}
		})
	}
}
