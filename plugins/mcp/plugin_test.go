package mcp_test

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/plugins/mcp"
	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// The MCP plugin runs the OAuth provider with the resource declared and
// given to registered clients, and serves its protected resource metadata
// at the well-known root and at the resource's path: the provider's issuer,
// header bearer tokens, the DPoP algorithms and requirement, and the scopes
// without the authorization server's own. Other methods get 405, HEAD the
// headers alone, and an invalid resource is refused.
func TestMCPPlugin(t *testing.T) {
	ctx := t.Context()
	store, err := sqlstore.OpenWithOptions(ctx, "sqlite", ":memory:", []string{"jwt", "oauth-provider"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	const resource = "https://api.example.test/mcp"
	opts := oauthprovider.Options{Scopes: []string{"openid", "profile", "mcp:read", "mcp:write", "offline_access"},
		Authorization: oauthprovider.BrowserAuthorizationOptions{LoginPage: "/login", ConsentPage: "/consent"},
		Resources: []oauthprovider.ResourceDefinition{{Identifier: "urn:other"},
			{Identifier: resource, Policy: oauthprovider.ResourcePatch{DPoPBoundAccessTokensRequired: oauthprovider.Set(true)}}}}
	opts.DPoP.SigningAlgorithms = []string{"ES256"}
	opts.Registration.DefaultResources = []string{"urn:other"}
	original := opts
	plugin, err := mcp.New(mcp.Options{Options: opts, Resource: resource})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opts, original) || len(opts.Resources) != 2 || len(opts.Registration.DefaultResources) != 1 {
		t.Fatal("the caller's options were changed")
	}
	keys, err := auth.NewJWT(auth.JWTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.New(auth.Options{Store: store, BaseURL: "https://auth.example.test", Secret: strings.Repeat("p", 32), Plugins: []auth.Plugin{keys, plugin}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"resource": resource, "authorization_servers": []any{"https://auth.example.test/api/auth"}, "bearer_methods_supported": []any{"header"},
		"dpop_signing_alg_values_supported": []any{"ES256"}, "dpop_bound_access_tokens_required": true, "scopes_supported": []any{"mcp:read", "mcp:write"}}
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest("GET", "https://auth.example.test"+path, nil))
		var got map[string]any
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || !reflect.DeepEqual(got, want) || w.Header().Get("Cache-Control") == "" {
			t.Fatal("the protected resource metadata was wrong", path, w.Code, w.Body.String(), w.Header())
		}
		w = httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest("HEAD", "https://auth.example.test"+path, nil))
		if w.Code != 200 || w.Body.Len() != 0 {
			t.Fatal("HEAD was wrong", path, w.Code, w.Body.String())
		}
		w = httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest("POST", "https://auth.example.test"+path, nil))
		if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
			t.Fatal("another method was not refused", path, w.Code, w.Header())
		}
	}
	// The provider's own discovery is still served.
	if _, ok := a.WellKnownJSON("/.well-known/oauth-authorization-server/api/auth"); !ok {
		t.Fatal("the provider's metadata was not served", a.WellKnownPaths())
	}
	if !slices.Contains(a.WellKnownPaths(), "/.well-known/oauth-protected-resource/mcp") {
		t.Fatal("the resource path was not served", a.WellKnownPaths())
	}
	// An undeclared resource is declared and becomes a default resource,
	// which the provider accepts only once it is declared.
	plain := oauthprovider.Options{Scopes: []string{"mcp:read"}, Authorization: oauthprovider.BrowserAuthorizationOptions{LoginPage: "/login", ConsentPage: "/consent"}}
	if _, err := mcp.New(mcp.Options{Options: plain, Resource: resource}); err != nil {
		t.Fatal("an undeclared resource was not declared", err)
	}
	for _, bad := range []string{"urn:example:mcp", "http://api.example.test/mcp", resource + "?x=1"} {
		if _, err := mcp.New(mcp.Options{Options: opts, Resource: bad}); err == nil {
			t.Error("a bad resource was accepted", bad)
		}
	}
}

// With open registration, a client registered without resources is linked
// to the MCP resource, which the provider declares and seeds.
func TestMCPRegistrationLinksResource(t *testing.T) {
	ctx := t.Context()
	store, err := sqlstore.OpenWithOptions(ctx, "sqlite", ":memory:", []string{"oauth-provider"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	const resource = "https://api.example.test/mcp"
	opts := oauthprovider.Options{Scopes: []string{"mcp:read"}, Authorization: oauthprovider.BrowserAuthorizationOptions{LoginPage: "/login", ConsentPage: "/consent"}}
	opts.Registration.Enabled, opts.Registration.AllowUnauthenticated, opts.Registration.DefaultApplicationType = true, true, "infer"
	plugin, err := mcp.New(mcp.Options{Options: opts, Resource: resource})
	if err != nil {
		t.Fatal(err)
	}
	off := false
	a, err := auth.New(auth.Options{Store: store, BaseURL: "https://auth.example.test", Secret: strings.Repeat("r", 32), Plugins: []auth.Plugin{plugin}, RateLimit: &off})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"redirect_uris":["http://127.0.0.1:3000/callback"],"token_endpoint_auth_method":"none","client_name":"MCP client"}`
	r := httptest.NewRequest("POST", "https://auth.example.test/api/auth/oauth2/register", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	var registered oauthprovider.RegisteredClient
	if w.Code != 200 && w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &registered) != nil {
		t.Fatal("open registration failed", w.Code, w.Body.String())
	}
	if !slices.Equal(registered.Resources, []string{resource}) || registered.ApplicationType != "native" {
		t.Fatal("the registered client was not linked to the MCP resource", registered.Resources, registered.ApplicationType)
	}
}
