package sqlstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

// Enterprise OIDC sign-ins run ValidateUserInfo with the SSO provider ID and
// the raw claims, check a returning user again, and return a refusal to the
// error callback with error and error_description.
func TestEnterpriseOIDCUserValidation(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, e := schema.Generate(dialect, []string{"organization", "sso"})
			must(e)
			store, e := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(e)
			defer store.Close()
			idp := newSSOIssuer(t)
			var checks []auth.UserInfoValidation
			refuse := false
			p, e := sso.New(sso.Options{})
			must(e)
			host, e := auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", RateLimit: new(bool), Store: store, Secret: strings.Repeat("k", 32),
				TrustedOrigins: []string{idp.URL}, Plugins: []auth.Plugin{p},
				ValidateUserInfo: func(_ context.Context, v auth.UserInfoValidation) error {
					checks = append(checks, v)
					if refuse {
						return &auth.APIError{Code: "sso_blocked", Message: "Not allowed"}
					}
					return nil
				}})
			must(e)
			now := time.Now().UTC()
			must(store.CreateUser(ctx, auth.User{ID: "owner", Name: "Owner", Email: "owner@example.test", CreatedAt: now, UpdatedAt: now}, "credential", nil))
			pkce := true
			cfg, _ := json.Marshal(sso.Config{Issuer: idp.URL, ClientID: "enterprise-client", ClientSecret: "oidc-secret", AuthorizationEndpoint: idp.URL + "/authorize",
				TokenEndpoint: idp.URL + "/token", JWKSEndpoint: idp.URL + "/keys", TokenEndpointAuthentication: "client_secret_basic", PKCE: &pkce})
			_, e = store.db.ExecContext(ctx, store.bind(`INSERT INTO "ssoProvider" ("id","providerId","issuer","oidcConfig","domain","userId") VALUES (?,?,?,?,?,?)`),
				"record-acme", "acme", idp.URL, string(cfg), "acme.example", "owner")
			must(e)
			call := func(method, path, cookie string, body any) *httptest.ResponseRecorder {
				var buf bytes.Buffer
				if body != nil {
					json.NewEncoder(&buf).Encode(body)
				}
				req := httptest.NewRequest(method, "https://service.test/identity/"+path, &buf)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", "https://service.test")
				if cookie != "" {
					req.Header.Set("Cookie", cookie)
				}
				w := httptest.NewRecorder()
				host.ServeHTTP(w, req)
				return w
			}
			signIn := func() string {
				t.Helper()
				w := call("POST", "sign-in/sso", "", map[string]any{"providerId": "acme", "callbackURL": "/home", "errorCallbackURL": "/retry"})
				var started struct{ URL string }
				must(json.Unmarshal(w.Body.Bytes(), &started))
				u, e := url.Parse(started.URL)
				must(e)
				q := u.Query()
				code := rand.Text()
				idp.mu.Lock()
				idp.codes[code] = ssoCode{q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri"), "employee@acme.example", "employee", "client_secret_basic", ""}
				idp.mu.Unlock()
				cb, e := url.Parse(q.Get("redirect_uri"))
				must(e)
				c := w.Result().Cookies()[0]
				done := call("GET", strings.TrimPrefix(cb.Path, "/identity/")+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), c.Name+"="+c.Value, nil)
				return done.Header().Get("Location")
			}
			refuse = true
			if got := signIn(); got != "https://service.test/retry?error=sso_blocked&error_description=Not+allowed" {
				t.Fatal("a refused enterprise sign-up signed in", got)
			}
			check := checks[len(checks)-1]
			if check.Action != auth.UserInfoCreateUser || check.Method != "sso-oidc" || check.Provider != "acme" || check.Profile["sub"] != "employee" || check.User.Email != "employee@acme.example" {
				t.Fatalf("the enterprise check was %+v", check)
			}
			if _, err := store.FindAccountUser(ctx, "employee@acme.example"); err == nil {
				t.Fatal("a refused enterprise sign-up stored a user")
			}
			refuse = false
			if got := signIn(); got != "https://service.test/home" {
				t.Fatal("an admitted enterprise sign-up failed", got)
			}
			refuse = true
			if got := signIn(); !strings.Contains(got, "error=sso_blocked") {
				t.Fatal("a refused returning enterprise sign-in signed in", got)
			}
			if check := checks[len(checks)-1]; check.Action != auth.UserInfoSignIn || check.User.ID == "" {
				t.Fatalf("the returning enterprise check was %+v", check)
			}
		})
	}
}
