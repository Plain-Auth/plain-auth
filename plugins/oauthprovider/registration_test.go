package oauthprovider

import (
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
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
	} {
		if err := r.validateRedirect(tc.uri, tc.app); (err == nil) != tc.ok {
			t.Errorf("%s %s: %v", tc.app, tc.uri, err)
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
	for _, raw := range []string{`{}`, `[]`, `{"keys":[]}`, `{"keys":[null]}`, `{"keys":[{"kty":"oct"}]}`, `{"keys":[{"kty":"RSA","n":"n"}]}`, `{"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y","alg":"ES384"}]}`, `{"keys":[{"kty":"OKP","crv":"X25519","x":"x"}]}`} {
		if ValidatePublicClientJWKS(json.RawMessage(raw)) == nil {
			t.Fatal("accepted invalid public key set", raw)
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
