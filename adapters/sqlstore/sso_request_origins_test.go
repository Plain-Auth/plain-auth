package sqlstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

// An enterprise OIDC return checks its stored callbacks with the callback
// request's own trusted origins. A callback that request no longer trusts
// sends the browser to BaseURL, or a failure to the error page, instead of
// failing after the sign-in.
func TestEnterpriseOIDCRequestOrigins(t *testing.T) {
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	ddl, err := schema.Generate("sqlite", []string{"organization", "sso"})
	must(err)
	store, err := OpenWithSchema(ctx, "sqlite", organizationTestDSN(t, "sqlite"), ddl)
	must(err)
	defer store.Close()
	idp := newSSOIssuer(t)
	refuse := false
	p, err := sso.New(sso.Options{})
	must(err)
	host, err := auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", RateLimit: new(bool), Store: store, Secret: strings.Repeat("k", 32),
		TrustedOrigins: []string{idp.URL, "myapp://"}, Plugins: []auth.Plugin{p},
		TrustedOriginsForRequest: func(r *http.Request) ([]string, error) {
			if r.Header.Get("X-Tenant") == "one" {
				return []string{"https://one.example"}, nil
			}
			return nil, nil
		},
		ValidateUserInfo: func(context.Context, auth.UserInfoValidation) error {
			if refuse {
				return &auth.APIError{Code: "sso_blocked", Message: "Not allowed"}
			}
			return nil
		}})
	must(err)
	now := time.Now().UTC()
	must(store.CreateUser(ctx, auth.User{ID: "owner", Name: "Owner", Email: "owner@example.test", CreatedAt: now, UpdatedAt: now}, "credential", nil))
	pkce := true
	cfg, _ := json.Marshal(sso.Config{Issuer: idp.URL, ClientID: "enterprise-client", ClientSecret: "oidc-secret", AuthorizationEndpoint: idp.URL + "/authorize",
		TokenEndpoint: idp.URL + "/token", JWKSEndpoint: idp.URL + "/keys", TokenEndpointAuthentication: "client_secret_basic", PKCE: &pkce})
	_, err = store.db.ExecContext(ctx, store.bind(`INSERT INTO "ssoProvider" ("id","providerId","issuer","oidcConfig","domain","userId") VALUES (?,?,?,?,?,?)`),
		"record-acme", "acme", idp.URL, string(cfg), "acme.example", "owner")
	must(err)
	call := func(method, path, tenant, cookie string, body any) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		if body != nil {
			json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, "https://service.test/identity/"+path, &buf)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://service.test")
		if tenant != "" {
			req.Header.Set("X-Tenant", tenant)
		}
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		w := httptest.NewRecorder()
		host.ServeHTTP(w, req)
		return w
	}
	// The sign-in starts on the tenant's request and returns on another.
	tenantCallbacks := map[string]any{"callbackURL": "https://one.example/home", "errorCallbackURL": "https://one.example/retry"}
	signInTo := func(callbacks map[string]any, returnTenant string) (string, bool) {
		t.Helper()
		body := map[string]any{"providerId": "acme"}
		maps.Copy(body, callbacks)
		w := call("POST", "sign-in/sso", "one", "", body)
		var started struct{ URL string }
		must(json.Unmarshal(w.Body.Bytes(), &started))
		u, err := url.Parse(started.URL)
		must(err)
		q := u.Query()
		code := rand.Text()
		idp.mu.Lock()
		idp.codes[code] = ssoCode{q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri"), "employee@acme.example", "employee", "client_secret_basic", ""}
		idp.mu.Unlock()
		cb, err := url.Parse(q.Get("redirect_uri"))
		must(err)
		c := w.Result().Cookies()[0]
		done := call("GET", strings.TrimPrefix(cb.Path, "/identity/")+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), returnTenant, c.Name+"="+c.Value, nil)
		if done.Code != http.StatusFound {
			t.Fatalf("the enterprise return answered %d: %s", done.Code, done.Body)
		}
		return done.Header().Get("Location"), strings.Contains(strings.Join(done.Header().Values("Set-Cookie"), "\n"), "session_token=")
	}
	signIn := func(returnTenant string) (string, bool) { return signInTo(tenantCallbacks, returnTenant) }
	if got, session := signIn("one"); got != "https://one.example/home" || !session {
		t.Fatal("a trusted enterprise return went to", got, session)
	}
	if got, session := signIn(""); got != "https://service.test" || !session {
		t.Fatal("an untrusted enterprise return went to", got, session)
	}
	refuse = true
	if got, _ := signIn("one"); got != "https://one.example/retry?error=sso_blocked&error_description=Not+allowed" {
		t.Fatal("a trusted enterprise failure went to", got)
	}
	if got, _ := signIn(""); got != "https://service.test/identity/error?error=sso_blocked&error_description=Not+allowed" {
		t.Fatal("an untrusted enterprise failure went to", got)
	}
	// A failure keeps the "//" of an app deep link.
	if got, _ := signInTo(map[string]any{"callbackURL": "myapp://"}, ""); got != "myapp://?error=sso_blocked&error_description=Not+allowed" {
		t.Fatal("an enterprise failure for a deep link went to", got)
	}
}
