package mcp_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/plugins/mcp"
	"github.com/Plain-Org/plain-auth/schema"
)

const origin = "https://mcp.example.test"

// instance builds an auth instance with the jwt plugin on SQLite.
func instance(t *testing.T, jwt auth.JWTOptions, opts auth.Options) (*auth.Auth, *sqlstore.Store) {
	t.Helper()
	store, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"jwt"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	keys, err := auth.NewJWT(jwt)
	if err != nil {
		t.Fatal(err)
	}
	opts.BaseURL, opts.Secret, opts.Store, opts.Plugins = origin, strings.Repeat("m", 32), store, []auth.Plugin{keys}
	a, err := auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return a, store
}

// accessToken signs an access token the way the provider does.
func accessToken(t *testing.T, a *auth.Auth, audience string, claims map[string]any) string {
	t.Helper()
	now := time.Now()
	base := map[string]any{"azp": "client-1", "scope": "mcp:read"}
	for k, v := range claims {
		if v == nil {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	token, err := a.SignJWT(t.Context(), "user-5", auth.JWTSignOptions{Type: "at+jwt", Issuer: a.OAuthIssuer(), Audience: []string{audience}, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Claims: base})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// RequireAuth defaults its resource to the instance's public URL, base path
// included, and its issuer to the one the instance signs with, reads keys
// in process even with /jwks disabled, requires azp, applies required and
// challenge scopes, and accepts an explicit resource and JWKS URL.
func TestRequireAuth(t *testing.T) {
	a, store := instance(t, auth.JWTOptions{Issuer: "https://issuer.example.test"}, auth.Options{DisabledPaths: []string{"/jwks"}})
	resource := a.PublicURL()
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := mcp.AccessTokenClaims(r.Context())
		json.NewEncoder(w).Encode(claims)
	})
	guard := func(opts mcp.AuthOptions) http.Handler {
		t.Helper()
		h, err := mcp.RequireAuth(a, store, echo, opts)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	call := func(h http.Handler, authorization string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", resource, nil)
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	h := guard(mcp.AuthOptions{})
	if w := call(h, "Bearer "+accessToken(t, a, resource, nil)); w.Code != 200 || !strings.Contains(w.Body.String(), `"sub":"user-5"`) {
		t.Fatal("a provider token was refused with the defaults", w.Code, w.Body.String())
	}
	if w := call(h, ""); w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/api/auth"`) {
		t.Fatal("the default resource metadata was wrong", w.Code, w.Header())
	}
	// A session JWT without azp is refused.
	if w := call(h, "Bearer "+accessToken(t, a, resource, map[string]any{"azp": nil})); w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatal("a token without azp was accepted", w.Code, w.Header())
	}
	// Scopes.
	scoped := guard(mcp.AuthOptions{RequiredScopes: []string{"mcp:write"}})
	if w := call(scoped, "Bearer "+accessToken(t, a, resource, nil)); w.Code != 403 {
		t.Fatal("a missing required scope was accepted", w.Code)
	}
	if w := call(scoped, ""); !strings.Contains(w.Header().Get("WWW-Authenticate"), `scope="mcp:write"`) {
		t.Fatal("the hint did not default to the required scopes", w.Header())
	}
	if w := call(guard(mcp.AuthOptions{ChallengeScopes: []string{"mcp:read"}}), ""); !strings.Contains(w.Header().Get("WWW-Authenticate"), `scope="mcp:read"`) {
		t.Fatal("the challenge hint was not used", w.Header())
	}
	// An explicit resource.
	const explicit = origin + "/mcp"
	if w := call(guard(mcp.AuthOptions{Resource: explicit}), "Bearer "+accessToken(t, a, explicit, nil)); w.Code != 200 {
		t.Fatal("an explicit resource was refused", w.Code, w.Header())
	}
	// Refused configurations.
	for name, opts := range map[string]mcp.AuthOptions{
		"urn":             {Resource: "urn:example:mcp"},
		"query":           {Resource: origin + "/mcp?x=1"},
		"challenge scope": {ChallengeScopes: []string{"bad scope"}},
	} {
		if _, err := mcp.RequireAuth(a, store, echo, opts); err == nil {
			t.Error("a bad configuration was accepted", name)
		}
	}
	// An explicit JWKS URL is fetched over HTTP.
	var hits atomic.Int32
	jwks := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		set, _ := a.PublicJWKS(r.Context())
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(jwks.Close)
	fetched := guard(mcp.AuthOptions{JWKSURL: jwks.URL, Transport: jwks.Client().Transport})
	if w := call(fetched, "Bearer "+accessToken(t, a, resource, nil)); w.Code != 200 || hits.Load() != 1 {
		t.Fatal("an explicit JWKS URL was not fetched", w.Code, hits.Load())
	}
}
