package sso

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/memory"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDiscoveryOriginAndBoundedTransport(t *testing.T) {
	issuer := "https://login.example.test/tenant"
	host, err := auth.New(auth.Options{Store: memory.New(), BaseURL: "https://accounts.test", Secret: strings.Repeat("k", 40), TrustedOrigins: []string{"https://*.example.test", "https://login.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	raw := `{"issuer":"https://login.example.test/tenant","authorization_endpoint":"/authorize","token_endpoint":"token","jwks_uri":"/keys","token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"]}`
	requests := 0
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		deadline, set := r.Context().Deadline()
		if !set || time.Until(deadline) > 10*time.Second {
			t.Fatal("unbounded discovery fetch")
		}
		if r.URL.String() != issuer+"/.well-known/openid-configuration" {
			t.Fatal(r.URL)
		}
		return &http.Response{Request: r, StatusCode: 200, Body: io.NopCloser(strings.NewReader(raw)), Header: http.Header{}}, nil
	})}
	code := func(err error, want string, status int) {
		t.Helper()
		var e *auth.APIError
		if !errors.As(err, &e) || e.Code != want || e.Status != status {
			t.Fatalf("%v, want %d %s", err, status, want)
		}
	}
	if _, err = host.CallbackURL("https://other.example.test/return"); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Issuer: "https://other.example.test/tenant"}
	code(hydrate(t.Context(), host, client, &cfg, false), "discovery_untrusted_origin", 400)
	if requests != 0 {
		t.Fatal("contacted browser-only origin")
	}
	for _, endpoint := range []string{"https://100.64.0.1/keys", "https://[2001:db8::1]/keys", "https://metadata.goog/keys"} {
		code(checkEndpoint(host, endpoint), "discovery_private_host", 400)
	}
	cfg = Config{Issuer: issuer}
	if err = hydrate(t.Context(), host, client, &cfg, false); err != nil {
		t.Fatal(err)
	}
	if cfg.TokenEndpoint != issuer+"/token" || cfg.JWKSEndpoint != issuer+"/keys" || cfg.AuthorizationEndpoint != issuer+"/authorize" || cfg.TokenEndpointAuthentication != "client_secret_basic" {
		t.Fatal(cfg)
	}
	for _, body := range []struct{ value, code string }{
		{"null", "discovery_incomplete"}, {`{broken`, "discovery_invalid_json"},
		{strings.Replace(raw, "https://login.example.test/tenant", "https://other.example.test/tenant", 1), "issuer_mismatch"},
		{strings.Replace(raw, "/keys", "http://127.0.0.1/keys", 1), "discovery_private_host"},
		{strings.Repeat(" ", (1<<20)+1), "discovery_invalid_json"},
	} {
		saved := raw
		raw = body.value
		cfg = Config{Issuer: issuer}
		code(hydrate(t.Context(), host, client, &cfg, false), body.code, 400)
		raw = saved
	}
	client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	client.Timeout = 5 * time.Millisecond
	cfg = Config{Issuer: issuer}
	code(hydrate(context.Background(), host, client, &cfg, false), "discovery_timeout", 502)
	if _, err := domains("Example.org,EXAMPLE.org, BüCHER.example"); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"*.example.com", "https://example.com", "user@example.com", "abc..example.com"} {
		if _, err := domains(input); err == nil {
			t.Fatal(input)
		}
	}
}
