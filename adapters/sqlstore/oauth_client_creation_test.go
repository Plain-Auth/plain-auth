package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// A signed-in user creates an application through /oauth2/create-client
// while dynamic registration stays disabled. The issuer's grants and scopes
// bound the request, the registration ceiling and PKCE setting do not
// apply, and fields an owner cannot set are dropped.
func TestOAuthClientCreation(t *testing.T) {
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
			optional := false
			var deny bool
			p, err := op.New(op.Options{Scopes: []string{"openid", "reports", "extra"}, GrantTypes: []string{"authorization_code", "client_credentials"},
				Registration: op.RegistrationOptions{DefaultScopes: []string{"openid"}, AllowedScopes: []string{"openid"}, RequirePKCE: &optional, DefaultApplicationType: "native",
					MayCreate: func(context.Context, op.RegistrationAccess) (bool, error) { return !deny, nil }}})
			must(err)
			const origin = "https://create.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("c", 40), Store: s, EmailAndPassword: true, Plugins: []auth.Plugin{p}, RateLimit: &off})
			must(err)
			owner, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
			must(err)
			m := op.RegistrationMetadata{RedirectURIs: []string{"https://app.example.test/cb"}, Scope: "reports extra"}
			post := func(cookie string, body map[string]any) *httptest.ResponseRecorder {
				raw, _ := json.Marshal(body)
				r := httptest.NewRequest("POST", origin+"/api/auth/oauth2/create-client", bytes.NewReader(raw))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", origin)
				if cookie != "" {
					r.Header.Set("Cookie", cookie)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			if w := post("", map[string]any{"redirect_uris": m.RedirectURIs}); w.Code != 401 || !strings.Contains(w.Body.String(), `"code":"UNAUTHORIZED"`) {
				t.Fatal("an anonymous caller created a client", w.Code, w.Body.String())
			}
			signed, err := owner.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@create.test", Password: "local creation test password"})
			must(err)
			cookie := h.SessionCookie(*signed.Token, true).String()
			if _, err := owner.RegisterOAuthClient(ctx, m); err == nil {
				t.Fatal("dynamic registration was open")
			}
			app, err := owner.CreateOAuthClient(ctx, m)
			must(err)
			if app.ClientID == "" || app.ClientSecret == "" || app.TokenEndpointAuthMethod != "client_secret_basic" || app.ApplicationType != "web" || app.Scope != "reports extra" || app.UserID != signed.User.ID {
				t.Fatal("the created client lost its defaults or scopes", app)
			}
			var scopes, pkce sql.NullString
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "scopes","requirePKCE" FROM "oauthClient" WHERE "clientId"=?`), app.ClientID).Scan(&scopes, &pkce))
			if scopes.String != `["reports","extra"]` || pkce.Valid && pkce.String != "" && pkce.String != "1" && pkce.String != "true" {
				t.Fatal("the stored client took the registration ceiling or PKCE setting", scopes, pkce)
			}
			// Without a scope the client may request every configured scope.
			open, err := owner.CreateOAuthClient(ctx, op.RegistrationMetadata{RedirectURIs: m.RedirectURIs})
			must(err)
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "scopes" FROM "oauthClient" WHERE "clientId"=?`), open.ClientID).Scan(&scopes))
			if scopes.Valid {
				t.Fatal("a client created without a scope stored a scope list", scopes)
			}
			// A machine client may be created; unsupported grants and scopes
			// outside the issuer's are refused; owner-only fields are dropped.
			if machine, err := owner.CreateOAuthClient(ctx, op.RegistrationMetadata{GrantTypes: []string{"client_credentials"}}); err != nil || machine.ClientSecret == "" {
				t.Fatal("a machine client was refused", err)
			}
			var problem *auth.APIError
			if _, err := owner.CreateOAuthClient(ctx, op.RegistrationMetadata{GrantTypes: []string{"refresh_token"}}); !errors.As(err, &problem) || problem.Code != "invalid_client_metadata" || problem.Message != "unsupported grant_type refresh_token" {
				t.Fatal("an unsupported grant was not refused", err)
			}
			if _, err := owner.CreateOAuthClient(ctx, op.RegistrationMetadata{RedirectURIs: m.RedirectURIs, Scope: "write"}); !errors.As(err, &problem) || problem.Code != "invalid_scope" || problem.Message != "cannot request scope write" {
				t.Fatal("a scope outside the issuer's was not refused", err)
			}
			w := post(cookie, map[string]any{"redirect_uris": m.RedirectURIs, "skip_consent": true, "subject_type": "pairwise", "resources": []string{"urn:x"}})
			var dropped struct {
				ClientID string `json:"client_id"`
			}
			must(json.Unmarshal(w.Body.Bytes(), &dropped))
			var skip sql.NullBool
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "skipConsent" FROM "oauthClient" WHERE "clientId"=?`), dropped.ClientID).Scan(&skip))
			if w.Code != 201 || w.Header().Get("Cache-Control") != "no-store" || skip.Bool {
				t.Fatal("owner-only fields were not dropped", w.Code, w.Body.String(), skip)
			}
			deny = true
			if w := post(cookie, map[string]any{"redirect_uris": m.RedirectURIs}); w.Code != 401 || w.Body.Len() != 0 {
				t.Fatal("a refused creation answered with a body", w.Code, w.Body.String())
			}
		})
	}
}
