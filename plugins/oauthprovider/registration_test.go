package oauthprovider

import (
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

func TestRegistrationRedirectPolicy(t *testing.T) {
	r := RegistrationOptions{AllowHTTPRedirect: func(u *url.URL) bool { return u.Hostname() == "dev.example.test" }}
	for _, tc := range []struct {
		app, uri string
		ok       bool
	}{
		{"web", "https://example.test/return?site=1", true}, {"web", "https://[::1]/cb", false},
		{"web", "https://ｌｏｃａｌｈｏｓｔ/cb", false}, {"web", "http://dev.example.test:8080/cb", true},
		{"native", "com.example.photos:/oauth/return", true}, {"native", "editor://workspace/cb", true},
		{"native", "editor://workspace", false}, {"native", "editor:/cb", false}, {"native", "file://workspace/cb", false},
		{"native", "https://app.example/cb", true}, {"native", "http://[::1]:48215/cb", true},
		{"native", "http://localhost:80/cb", true}, {"native", "http://127.0.0.2/cb", false},
		{"native", "http://localhost./cb", false}, {"native", "http://preview.localhost/cb", false},
		{"native", "https://example.test/cb#", false}, {"web", "https://example.test:70000/cb", false},
		// Credentials are refused even when the host is approved, and
		// loopback and custom-scheme callbacks belong to native clients.
		{"web", "http://user@dev.example.test/cb", false}, {"native", "http://user:pw@dev.example.test/cb", false},
		{"web", "http://127.0.0.1:8787/callback", false}, {"native", "http://127.0.0.1:8787/callback", true},
		{"web", "com.example.app:/callback", false}, {"native", "com.example.app:/callback", true},
		{"web", "myapp://example.app/callback", false}, {"native", "myapp://example.app/callback", true},
		{"web", "http://localhost:3000/cb", false},
		// Shortened loopback forms, HTTPS loopback and plain HTTP hosts
		// are refused for both kinds, and so is a script URL.
		{"native", "http://127.1/callback", false}, {"web", "https://127.1/cb", false},
		{"native", "https://127.0.0.1/cb", false}, {"native", "http://example.com/callback", false},
		{"web", "http://example.com/callback", false}, {"native", "javascript:alert(1)", false},
		{"web", "javascript://example.com/%0Aalert(1)", false},
	} {
		if err := r.validateRedirect(tc.uri, tc.app); (err == nil) != tc.ok {
			t.Errorf("%s %s: %v", tc.app, tc.uri, err)
		}
	}
	// Native clients refuse unsafe schemes, malformed reverse-domain
	// schemes, non-loopback HTTP hosts and HTTPS loopback.
	for _, uri := range []string{
		"file:///callback", "ftp://example.com/callback", "mailto:oauth@example.com", "ws://host/callback",
		"wss://host/callback", "myapp:/callback", "com.example.app:callback", "com.example.app:///callback",
		"com..example.app:/callback", "com.example..app:/callback", "com.example.-app:/callback", "com.example.app-:/callback",
		"https://localhost/callback", "https://localhost./callback", "https://localhost../callback", "http://localhost../callback",
		"http://192.168.1.2/callback", "http://tenant.localhost/callback", "http://127.42.7.9:49152/callback",
		"https://user:password@example.com/callback", "https://example.com/callback#fragment",
	} {
		if r.validateRedirect(uri, "native") == nil {
			t.Error("native redirect accepted", uri)
		}
	}
	for _, uri := range []string{
		"http://localhost:54921/callback", "http://127.0.0.1:54921/callback", "http://[::1]:61234/callback",
		"com.example.app:/callback", "com.example.app://host/callback", "https://app.example.com/callback",
	} {
		if err := r.validateRedirect(uri, "native"); err != nil {
			t.Error("native redirect refused", uri, err)
		}
	}
	// An approved web host may use HTTP, but never with credentials.
	local := RegistrationOptions{AllowHTTPRedirect: func(u *url.URL) bool { return u.Hostname() == "localhost" }}
	if err := local.validateRedirect("http://localhost:3000/cb", "web"); err != nil {
		t.Fatal("an approved HTTP web callback was refused", err)
	}
	if err := local.validateRedirect("http://user@localhost:3000/cb", "web"); err == nil {
		t.Fatal("an approved HTTP web callback with credentials was accepted")
	}
}

// A registration secret lifetime is zero or a positive whole number of
// seconds.
func TestRegistrationSecretLifetime(t *testing.T) {
	for _, lifetime := range []time.Duration{-time.Second, 1500 * time.Millisecond} {
		if _, err := New(Options{Registration: RegistrationOptions{Enabled: true, SecretLifetime: lifetime}}); err == nil {
			t.Error("an invalid secret lifetime was accepted", lifetime)
		}
	}
	if _, err := New(Options{Registration: RegistrationOptions{Enabled: true, SecretLifetime: time.Hour}}); err != nil {
		t.Fatal(err)
	}
}

// The authorize-time HTTPS policy accepts every scheme but http, http on a
// loopback host for a client that is not web or when the host approves it,
// and never http with credentials.
func TestRedirectTransportPolicy(t *testing.T) {
	r := RegistrationOptions{AllowHTTPRedirect: func(u *url.URL) bool { return u.Hostname() == "intranet.example" }}
	for _, tc := range []struct {
		uri  string
		web  bool
		want bool
	}{
		{"https://app.example/cb", true, true}, {"https://localhost/cb", true, true}, {"https://127.0.0.1/cb", false, true},
		{"myapp:callback", true, true}, {"com.example.app:/cb", false, true},
		{"http://localhost:3000/cb", false, true}, {"http://tenant.localhost/cb", false, true}, {"http://127.0.0.2:9/cb", false, true},
		{"http://localhost:3000/cb", true, false}, {"http://192.168.1.2/cb", false, false}, {"http://example.com/cb", true, false},
		{"http://intranet.example/cb", true, true}, {"http://intranet.example/cb", false, true},
		{"http://user@intranet.example/cb", true, false}, {"relative/cb", false, false}, {"", false, false},
	} {
		if got := r.redirectTransportAllowed(tc.uri, tc.web); got != tc.want {
			t.Errorf("transport of %q (web %v) = %v", tc.uri, tc.web, got)
		}
	}
}

func TestRegistrationPublicKeys(t *testing.T) {
	for _, tc := range []struct {
		kty, curve string
		algs       []string
		params     map[string]any
	}{
		{"EC", "P-256", []string{"ES256"}, map[string]any{"x": "x", "y": "y"}},
		{"EC", "P-384", []string{"ES384"}, map[string]any{"x": "x", "y": "y"}},
		{"EC", "P-521", []string{"ES512"}, map[string]any{"x": "x", "y": "y"}},
		{"OKP", "Ed25519", []string{"EdDSA"}, map[string]any{"x": "x"}},
		{"RSA", "", []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}, map[string]any{"n": "n", "e": "AQAB"}},
	} {
		key := tc.params
		key["kty"] = tc.kty
		if tc.curve != "" {
			key["crv"] = tc.curve
		}
		check := func(valid bool) {
			t.Helper()
			raw, err := json.Marshal(map[string]any{"keys": []any{key}})
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidatePublicClientJWKS(raw); (err == nil) != valid {
				t.Fatalf("key type %s curve %s: %v", tc.kty, tc.curve, err)
			}
		}
		check(true)
		for _, alg := range tc.algs {
			key["alg"] = alg
			check(true)
		}
		for _, alg := range []any{"HS256", "none", nil, false} {
			key["alg"] = alg
			check(false)
		}
		delete(key, "alg")
		for _, field := range []string{"k", "d", "p", "q", "dp", "dq", "qi", "oth"} {
			key[field] = nil
			check(false)
			delete(key, field)
		}
	}
	// Each refusal names its reason, as another runtime's validation result
	// does.
	const (
		set    = "jwks must be an RFC 7517 JWK Set object with a non-empty keys array"
		public = "jwks must contain only public asymmetric keys"
		params = "jwks keys must be supported public JWKs with required key parameters"
		alg    = "jwks key alg must be supported for private_key_jwt and compatible with its key type and signing curve"
	)
	for raw, want := range map[string]string{`{}`: set, `[]`: set, `{"keys":[]}`: set, `{"keys":[null]}`: params, `{"keys":[{"kty":"oct"}]}`: public,
		`{"keys":[{"kty":"RSA","n":"n","e":"AQAB","d":"d"}]}`: public, `{"keys":[{"kty":"RSA","n":"n"}]}`: params, `{"keys":[{"kty":"OKP","crv":"X25519","x":"x"}]}`: params,
		`{"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y","alg":"ES384"}]}`: alg} {
		var e *auth.OAuthError
		if err := ValidatePublicClientJWKS(json.RawMessage(raw)); !errors.As(err, &e) || e.Code != "invalid_client_metadata" || e.Description != want {
			t.Fatal("an invalid public key set was not refused with its reason", raw, err)
		}
	}
}

func TestRegistrationMetadataPolicy(t *testing.T) {
	host, err := auth.New(auth.Options{Store: memory.New(), BaseURL: "https://issuer.example.test", Secret: "a-test-secret-for-registering-clients", TrustedOrigins: []string{"https://keys.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	options := Options{GrantTypes: []string{"client_credentials"}, PairwiseSecret: "a-long-test-secret-for-pairwise-claims", Registration: RegistrationOptions{DefaultApplicationType: "web", AllowedScopes: []string{"email", "reports"}}}
	m := RegistrationMetadata{GrantTypes: []string{"authorization_code", "client_credentials", "other"}, ResponseTypes: []string{"code"}}
	if err := options.prepareMetadata(host, &m, true); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.GrantTypes, []string{"client_credentials"}) || m.ResponseTypes != nil || m.RedirectURIs == nil {
		t.Fatal("response types no longer match negotiated grants")
	}
	options.GrantTypes = []string{"authorization_code"}
	for _, pair := range []struct {
		uris  []string
		valid bool
	}{
		{[]string{"https://EXAMPLE.test/a", "https://example.test:443/b"}, true},
		{[]string{"https://example.test/a", "https://other.test/b"}, false},
		{[]string{"app://example.test/cb"}, false},
	} {
		m := RegistrationMetadata{RedirectURIs: pair.uris, ApplicationType: "native", SubjectType: "pairwise"}
		if err := options.prepareMetadata(host, &m, true); (err == nil) != pair.valid {
			t.Errorf("pairwise %v: %v", pair.uris, err)
		}
	}
	for _, tc := range []struct {
		field, uri string
		valid      bool
	}{
		{"jwks_uri", "https://keys.example.test/keys", true}, {"jwks_uri", "https://other.example.test/keys", false},
		{"backchannel_logout_uri", "https://client.example.test/logout", true},
		{"backchannel_logout_uri", "https://example.test/logout#", false}, {"backchannel_logout_uri", "http://example.test/logout", false},
		{"backchannel_logout_uri", "https://user@example.test/logout", false}, {"backchannel_logout_uri", "https://metadata.google.internal/logout", false},
		{"backchannel_logout_uri", "https://[::1]/logout", false}, {"backchannel_logout_uri", "https://192.0.2.1/logout", false},
		{"backchannel_logout_uri", "https://[2002::1]/logout", false}, {"backchannel_logout_uri", "https://example.test:80808/logout", false},
	} {
		if err := validateServerURI(tc.field, tc.uri, host); (err == nil) != tc.valid {
			t.Errorf("%s %s: %v", tc.field, tc.uri, err)
		}
	}
	for _, tc := range []struct {
		key   string
		value any
		code  string
	}{
		{"skip_consent", false, "invalid_client_metadata"}, {"software_statement", true, "invalid_software_statement"}, {"redirect_uris", nil, "invalid_redirect_uri"},
		{"contacts", []any{nil}, "invalid_client_metadata"}, {"resources", []any{"relative"}, "invalid_target"},
	} {
		_, err := readRegistration(map[string]any{tc.key: tc.value})
		var problem *auth.OAuthError
		if !errors.As(err, &problem) || problem.Code != tc.code {
			t.Errorf("%s got %v", tc.key, err)
		}
	}
}
