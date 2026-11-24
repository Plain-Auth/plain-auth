package sqlstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

// flowCounter records flow writes on the SQL store.
type flowCounter struct {
	*Store
	saves atomic.Int32
}

func (s *flowCounter) SaveOAuthFlow(ctx context.Context, f auth.OAuthFlow, now time.Time) error {
	s.saves.Add(1)
	return s.Store.SaveOAuthFlow(ctx, f, now)
}

// With OAuthStateCookie an enterprise OIDC sign-in keeps its flow sealed in
// sso_state, writes none, and refuses a state cookie from another flow.
func TestEnterpriseOIDCStateCookie(t *testing.T) {
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	ddl, err := schema.Generate("sqlite", []string{"organization", "sso"})
	must(err)
	inner, err := OpenWithSchema(ctx, "sqlite", organizationTestDSN(t, "sqlite"), ddl)
	must(err)
	defer inner.Close()
	store := &flowCounter{Store: inner}
	idp := newSSOIssuer(t)
	p, err := sso.New(sso.Options{})
	must(err)
	host, err := auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", RateLimit: new(bool), Store: store, Secret: strings.Repeat("k", 32),
		TrustedOrigins: []string{idp.URL}, Plugins: []auth.Plugin{p}, OAuthStateStrategy: auth.OAuthStateCookie})
	must(err)
	now := time.Now().UTC()
	must(inner.CreateUser(ctx, auth.User{ID: "owner", Name: "Owner", Email: "owner@example.test", CreatedAt: now, UpdatedAt: now}, "credential", nil))
	pkce := true
	cfg, _ := json.Marshal(sso.Config{Issuer: idp.URL, ClientID: "enterprise-client", ClientSecret: "oidc-secret", AuthorizationEndpoint: idp.URL + "/authorize",
		TokenEndpoint: idp.URL + "/token", JWKSEndpoint: idp.URL + "/keys", TokenEndpointAuthentication: "client_secret_basic", PKCE: &pkce})
	_, err = inner.db.ExecContext(ctx, inner.bind(`INSERT INTO "ssoProvider" ("id","providerId","issuer","oidcConfig","domain","userId") VALUES (?,?,?,?,?,?)`),
		"record-acme", "acme", idp.URL, string(cfg), "acme.example", "owner")
	must(err)
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
	type started struct{ cookie, callback string }
	start := func() started {
		t.Helper()
		w := call("POST", "sign-in/sso", "", map[string]any{"providerId": "acme", "callbackURL": "/home"})
		var out struct{ URL string }
		must(json.Unmarshal(w.Body.Bytes(), &out))
		u, err := url.Parse(out.URL)
		must(err)
		q := u.Query()
		code := rand.Text()
		idp.mu.Lock()
		idp.codes[code] = ssoCode{q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri"), "employee@acme.example", "employee", "client_secret_basic", ""}
		idp.mu.Unlock()
		cb, err := url.Parse(q.Get("redirect_uri"))
		must(err)
		c := w.Result().Cookies()[0]
		if c.Name != "__Secure-authn.sso_state" || !strings.HasPrefix(c.Value, "authn.v1.") {
			t.Fatalf("the state cookie was %s=%s", c.Name, c.Value)
		}
		return started{c.Name + "=" + c.Value, strings.TrimPrefix(cb.Path, "/identity/") + "?" + url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()}
	}
	first, second := start(), start()
	if w := call("GET", second.callback, first.cookie, nil); w.Code != 302 || !strings.HasSuffix(w.Header().Get("Location"), "/identity/error?error=invalid_state") {
		t.Fatal("another flow's state cookie answered", w.Code, w.Header().Get("Location"))
	}
	if w := call("GET", first.callback, first.cookie, nil); w.Code != 302 || w.Header().Get("Location") != "https://service.test/home" {
		t.Fatal("the enterprise sign-in answered", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	if saves := store.saves.Load(); saves != 0 {
		t.Fatalf("%d flows were stored", saves)
	}
}
