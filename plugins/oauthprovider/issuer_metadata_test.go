package oauthprovider_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestIssuerDiscoveryConfiguration(t *testing.T) {
	for _, opts := range []op.IssuerMetadataOptions{
		{Scopes: []string{"unconfigured"}},
		{TokenAuthMethods: []string{}},
		{TokenAuthMethods: []string{"client_secret_basic", "client_secret_basic"}},
		{TokenAuthMethods: []string{"unsupported"}},
	} {
		if _, err := op.New(op.Options{Scopes: []string{"read"}, Metadata: opts}); err == nil {
			t.Error("accepted invalid advertised configuration", opts)
		}
	}
	if _, err := op.New(op.Options{GrantTypes: []string{"client_credentials"}, Metadata: op.IssuerMetadataOptions{TokenAuthMethods: []string{"none"}}}); err == nil {
		t.Fatal("advertised unauthenticated machine clients")
	}
}

func TestMetadataResponse(t *testing.T) {
	input := map[string]string{"service": "reports"}
	for _, tc := range []struct {
		headers http.Header
		cache   string
	}{
		{nil, "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400"},
		{http.Header{"cache-control": {"private"}, "Content-Type": {"text/plain"}, "X-Version": {"1", "2"}}, "private"},
		{http.Header{"Cache-Control": {""}}, ""},
	} {
		input["service"] = "reports"
		response, err := op.NewMetadataResponse(input, tc.headers)
		if err != nil {
			t.Fatal(err)
		}
		input["service"] = "changed"
		if values := tc.headers["X-Version"]; len(values) > 0 {
			values[0] = "changed"
		}
		w := httptest.NewRecorder()
		response.ServeHTTP(w, httptest.NewRequest("GET", "/publisher", nil))
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != tc.cache ||
			w.Body.String() != `{"service":"reports"}` || (tc.cache == "private" && !slices.Equal(w.Header().Values("X-Version"), []string{"1", "2"})) {
			t.Fatalf("unexpected response %d %v %s", w.Code, w.Header(), w.Body.String())
		}
	}
	if _, err := op.NewMetadataResponse(make(chan int), nil); err == nil {
		t.Fatal("accepted a value that cannot be serialized")
	}
}

func TestIssuerDiscoveryMounts(t *testing.T) {
	s, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"oauth-provider", "jwt"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	base := "https://accounts.example.test"
	const wellKnown = "/.well-known/oauth-authorization-server"
	const mount = "/auth"
	scopes := []string{"read", "openid", "write"}
	headers := http.Header{"Cache-Control": {"private, max-age=5"}, "X-Discovery": {"auth"}}
	meta := op.IssuerMetadataOptions{Scopes: scopes, Headers: headers}
	p, err := op.New(op.Options{GrantTypes: []string{"client_credentials"}, Scopes: scopes, Registration: op.RegistrationOptions{Enabled: true}, Metadata: meta})
	if err != nil {
		t.Fatal(err)
	}
	scopes[0], headers["X-Discovery"][0] = "changed", "changed"
	build := func(plugin auth.Plugin, store auth.Store, jwtIssuer string, disabled []string) (*auth.Auth, error) {
		t.Helper()
		plugins := []auth.Plugin{plugin}
		if jwtIssuer != "" {
			signing, err := auth.NewJWT(auth.JWTOptions{JWKSPath: "/keys", Issuer: jwtIssuer})
			if err != nil {
				t.Fatal(err)
			}
			plugins = append(plugins, signing)
		}
		return auth.New(auth.Options{BaseURL: base, BasePath: mount, Secret: strings.Repeat("a", 48), Store: store, Plugins: plugins, DisabledPaths: disabled})
	}
	for _, tc := range []struct {
		issuer string
		paths  []string
	}{
		{"", []string{wellKnown + mount, mount + wellKnown}},
		{"https://issuer.example.test", []string{wellKnown}},
		{"https://issuer.example.test/", []string{wellKnown}},
		{"https://issuer.example.test/ten%2Fant/v2/", []string{wellKnown + "/ten%2Fant/v2", "/ten%2Fant/v2" + wellKnown}},
		{"http://localhost:9999/dev", []string{wellKnown + "/dev", "/dev" + wellKnown}},
		// The published issuer drops a query, a fragment and one trailing
		// slash, as another runtime publishes it.
		{"https://issuer.example.test/tenant/?invalid=issuer#part", []string{wellKnown + "/tenant", "/tenant" + wellKnown}},
	} {
		a, err := build(p, s, tc.issuer, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(a.WellKnownPaths(), tc.paths) {
			t.Fatalf("issuer %q published paths %v", tc.issuer, a.WellKnownPaths())
		}
		doc, err := op.GetAuthorizationServerConfig(a)
		if tc.issuer != "" && a.OAuthIssuer() != strings.TrimSuffix(strings.Split(strings.Split(tc.issuer, "?")[0], "#")[0], "/") {
			t.Fatal("the issuer was not published without its query, fragment and trailing slash", tc.issuer, a.OAuthIssuer())
		}
		if err != nil || doc.Issuer != a.OAuthIssuer() || doc.TokenEndpoint != base+mount+"/oauth2/token" ||
			!slices.Equal(doc.ScopesSupported, []string{"read", "write"}) || doc.RegistrationEndpoint == "" {
			t.Fatal("unexpected issuer metadata", doc, err)
		}
		if (tc.issuer != "") != (doc.JWKSURI == base+mount+"/keys") {
			t.Fatal("unexpected signing key URL", doc.JWKSURI)
		}
		mux := http.NewServeMux()
		for _, path := range a.WellKnownPaths() {
			mux.Handle(path, a)
		}
		mux.Handle(mount+"/", a)
		for _, path := range tc.paths {
			raw, ok := a.WellKnownJSON(path)
			if !ok {
				t.Fatal(path)
			}
			doc.ScopesSupported[0], raw[0] = "changed", '!'
			r := httptest.NewRequest(http.MethodGet, "https://untrusted.example.test"+path+"?ignored=1", nil)
			r.Header.Set("Forwarded", "host=untrusted.example.test;proto=http")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != 200 || w.Header().Get("X-Discovery") != "auth" || w.Header().Get("Cache-Control") != "private, max-age=5" || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") ||
				w.Header().Get("Access-Control-Allow-Origin") != "" || strings.Contains(w.Body.String(), "changed") ||
				strings.Contains(w.Body.String(), "untrusted") || w.Body.Bytes()[0] != '{' {
				t.Fatalf("GET %s: %d %v %s", path, w.Code, w.Header(), w.Body.String())
			}
			extraSlash := httptest.NewRecorder()
			a.ServeHTTP(extraSlash, httptest.NewRequest(http.MethodGet, path+"/", nil))
			if extraSlash.Code != 404 {
				t.Fatalf("unexpected alias at %s/", path)
			}
		}
	}
	a, err := build(p, s, base+mount, []string{"/keys", "/oauth2/register", "/oauth2/introspect", "/oauth2/revoke", wellKnown})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := op.GetAuthorizationServerConfig(a)
	if err != nil || len(a.WellKnownPaths()) != 1 || doc.JWKSURI != "" || doc.RegistrationEndpoint != "" ||
		doc.IntrospectionEndpoint != "" || doc.RevocationEndpoint != "" || len(doc.IntrospectionEndpointAuthMethods) != 0 || len(doc.RevocationEndpointAuthMethods) != 0 {
		t.Fatal("advertised a disabled route", doc, err)
	}
	type machineOnly struct {
		auth.Store
		op.ConsentStore
		op.MachineTokenStore
	}
	basic := machineOnly{s, s, s}
	plain, err := op.New(op.Options{})
	if err != nil {
		t.Fatal(err)
	}
	type consentOnly struct {
		auth.Store
		op.ConsentStore
	}
	readOnly, err := build(plain, consentOnly{s, s}, "", nil)
	if err != nil || len(readOnly.WellKnownPaths()) != 0 {
		t.Fatal("published a machine issuer without an issuance store", err)
	}
	a, err = build(plain, basic, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	doc, err = op.GetAuthorizationServerConfig(a)
	if err != nil || doc.ScopesSupported == nil || len(doc.ScopesSupported) != 0 || !slices.Equal(doc.TokenEndpointAuthMethods, []string{"client_secret_basic", "client_secret_post"}) ||
		doc.IntrospectionEndpoint != "" || doc.RevocationEndpoint != "" || len(doc.TokenEndpointAuthSigningAlgorithms) != 0 || len(doc.DPoPSigningAlgorithms) != 0 {
		t.Fatal("advertised unavailable store features", doc, err)
	}
	explicitJWT, err := op.New(op.Options{Metadata: op.IssuerMetadataOptions{TokenAuthMethods: []string{"private_key_jwt"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := build(explicitJWT, basic, "", nil); err == nil {
		t.Fatal("accepted an unavailable explicitly advertised method")
	}
	restricted, err := op.New(op.Options{DPoP: op.DPoPOptions{SigningAlgorithms: []string{}},
		Metadata: op.IssuerMetadataOptions{TokenAuthMethods: []string{"client_secret_post"}, Scopes: []string{}}})
	if err != nil {
		t.Fatal(err)
	}
	a, err = build(restricted, s, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	doc, err = op.GetAuthorizationServerConfig(a)
	if err != nil || doc.DPoPSigningAlgorithms == nil || len(doc.DPoPSigningAlgorithms) != 0 ||
		!slices.Equal(doc.TokenEndpointAuthMethods, []string{"client_secret_post"}) || !slices.Contains(doc.TokenEndpointAuthSigningAlgorithms, "RS256") {
		t.Fatal("unexpected explicit capability lists", doc, err)
	}
	disabled, err := op.New(op.Options{Metadata: op.IssuerMetadataOptions{Disabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	noGrants, err := op.New(op.Options{GrantTypes: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		plugin   auth.Plugin
		issuer   string
		disabled []string
	}{
		{disabled, "", nil}, {noGrants, "", nil}, {p, "http://untrusted.example.test", nil},
		{p, "", []string{"/oauth2/token"}},
	} {
		a, err := build(tc.plugin, s, tc.issuer, tc.disabled)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := op.GetAuthorizationServerConfig(a); !errors.Is(err, auth.ErrNotFound) || len(a.WellKnownPaths()) != 0 {
			t.Fatal("unexpected discovery document", err)
		}
	}
}

// Each mounted discovery document is JSON with the default cache rule when
// Metadata.Headers sets none, for the authorization server and OpenID
// documents alike.
func TestDiscoveryDefaultHeaders(t *testing.T) {
	s, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"oauth-provider", "jwt"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	p, err := op.New(op.Options{})
	if err != nil {
		t.Fatal(err)
	}
	sign, err := auth.NewJWT(auth.JWTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.New(auth.Options{BaseURL: "https://accounts.example.test", Secret: strings.Repeat("a", 48), Store: s, Plugins: []auth.Plugin{p, sign}})
	if err != nil {
		t.Fatal(err)
	}
	paths := a.WellKnownPaths()
	for _, want := range []string{"/.well-known/oauth-authorization-server/api/auth", "/.well-known/openid-configuration"} {
		if !slices.ContainsFunc(paths, func(p string) bool { return strings.HasPrefix(p, want) || strings.HasSuffix(p, want) }) {
			t.Fatal("a discovery document was not mounted", want, paths)
		}
	}
	for _, path := range paths {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") || w.Header().Get("Cache-Control") != "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400" {
			t.Fatal("a discovery document lacks its JSON type or default cache rule", path, w.Code, w.Header())
		}
	}
	// Metadata.Headers replaces the defaults on the OpenID document too.
	custom, err := op.New(op.Options{Metadata: op.IssuerMetadataOptions{Headers: http.Header{"Cache-Control": {"no-store"}, "X-Discovery": {"openid"}}}})
	if err != nil {
		t.Fatal(err)
	}
	a, err = auth.New(auth.Options{BaseURL: "https://accounts.example.test", Secret: strings.Repeat("a", 48), Store: s, Plugins: []auth.Plugin{custom, sign}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration/api/auth", nil))
	if w.Code == 404 {
		w = httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/.well-known/openid-configuration", nil))
	}
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Discovery") != "openid" {
		t.Fatal("the OpenID document did not take the configured headers", w.Code, w.Header(), a.WellKnownPaths())
	}
}
