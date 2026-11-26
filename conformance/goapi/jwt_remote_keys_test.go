package goapi_test

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
	libjwt "github.com/golang-jwt/jwt/v5"
)

// With a remote key set, the local key route is gone, discovery advertises
// the remote address and the algorithm, and issued tokens verify with the
// exported keys.
func TestJWTRemoteKeySet(t *testing.T) {
	ctx := t.Context()
	store, err := sqlstore.OpenWithOptions(ctx, "sqlite", ":memory:", []string{"jwt", "oauth-provider"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const base = "https://auth.example"
	const remote = "https://cdn.example.test/keys/jwks.json?v=2"
	keys, err := authn.NewJWT(authn.JWTOptions{Algorithm: "ES256", RemoteJWKSURL: remote})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := oauthprovider.New(oauthprovider.Options{GrantTypes: []string{"authorization_code"}, Scopes: []string{"openid", "email"}, Authorization: oauthprovider.BrowserAuthorizationOptions{LoginPage: "/login", ConsentPage: "/consent"}})
	if err != nil {
		t.Fatal(err)
	}
	off := false
	a, err := authn.New(authn.Options{Store: store, BaseURL: base, Secret: strings.Repeat("r", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []authn.Plugin{keys, provider}})
	if err != nil {
		t.Fatal(err)
	}
	serve := func(method, path, body string, status int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, base+path, strings.NewReader(body))
		r.Header.Set("Origin", base)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s %s: HTTP %d, want %d: %s", method, path, w.Code, status, w.Body)
		}
		return w
	}
	serve("GET", "/api/auth/jwks", "", 404)
	if a.PublicJWKSURL() != remote || len(a.WellKnownPaths()) == 0 {
		t.Fatal("the key-set URL is not the remote one", a.PublicJWKSURL())
	}
	for _, path := range a.WellKnownPaths() {
		var doc struct {
			JWKSURI string `json:"jwks_uri"`
		}
		if err := json.Unmarshal(serve("GET", path, "", 200).Body.Bytes(), &doc); err != nil || doc.JWKSURI != remote {
			t.Fatalf("discovery at %s does not advertise the remote key set", path)
		}
	}
	if doc, err := oauthprovider.GetOpenIDConfig(a); err != nil || doc.JWKSURI != remote || !slices.Equal(doc.IDTokenSigningAlgorithms, []string{"ES256"}) {
		t.Fatal("OpenID discovery does not advertise the remote key set and its algorithm", doc, err)
	}
	signed := serve("POST", "/api/auth/sign-up/email", `{"email":"remote@example.test","password":"remote-key-password","name":"Remote"}`, 200)
	var account authn.AuthResult
	if err := json.Unmarshal(signed.Body.Bytes(), &account); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", base+"/api/auth/token", nil)
	r.AddCookie(a.SessionCookie(account.Token, true))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	var issued struct{ Token string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &issued) != nil {
		t.Fatal("token issuance failed", w.Code, w.Body)
	}
	set, err := a.PublicJWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := libjwt.Parse(issued.Token, func(tok *libjwt.Token) (any, error) {
		for _, k := range set.Keys {
			if k.KeyID == tok.Header["kid"] {
				return k.Key, nil
			}
		}
		return nil, errors.New("unknown key")
	}, libjwt.WithValidMethods([]string{"ES256"}), libjwt.WithIssuer(base), libjwt.WithAudience(base)); err != nil {
		t.Fatal("token does not verify with the exported key set", err)
	}
}
