package sso

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
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
	code(hydrate(t.Context(), host.ExplicitlyTrustedOrigin, client, &cfg, false), "discovery_untrusted_origin", 400)
	if requests != 0 {
		t.Fatal("contacted browser-only origin")
	}
	for _, endpoint := range []string{"https://100.64.0.1/keys", "https://[2001:db8::1]/keys", "https://metadata.goog/keys"} {
		code(checkEndpoint(host.ExplicitlyTrustedOrigin, endpoint), "discovery_private_host", 400)
	}
	cfg = Config{Issuer: issuer}
	if err = hydrate(t.Context(), host.ExplicitlyTrustedOrigin, client, &cfg, false); err != nil {
		t.Fatal(err)
	}
	if cfg.TokenEndpoint != issuer+"/token" || cfg.JWKSEndpoint != issuer+"/keys" || cfg.AuthorizationEndpoint != issuer+"/authorize" || cfg.TokenEndpointAuthentication != "client_secret_basic" {
		t.Fatal(cfg)
	}
	for _, body := range []struct{ value, code string }{
		{"null", "discovery_invalid_json"}, {`{broken`, "discovery_invalid_json"},
		{strings.Replace(raw, "https://login.example.test/tenant", "https://other.example.test/tenant", 1), "issuer_mismatch"},
		{strings.Replace(raw, "/keys", "http://127.0.0.1/keys", 1), "discovery_untrusted_origin"},
		{strings.Repeat(" ", (1<<20)+1), "discovery_invalid_json"},
	} {
		saved := raw
		raw = body.value
		cfg = Config{Issuer: issuer}
		code(hydrate(t.Context(), host.ExplicitlyTrustedOrigin, client, &cfg, false), body.code, 400)
		raw = saved
	}
	client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	client.Timeout = 5 * time.Millisecond
	cfg = Config{Issuer: issuer}
	code(hydrate(context.Background(), host.ExplicitlyTrustedOrigin, client, &cfg, false), "discovery_timeout", 502)
	if _, err := domains("Example.org,EXAMPLE.org, BüCHER.example"); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"*.example.com", "https://example.com", "user@example.com", "abc..example.com"} {
		if _, err := domains(input); err == nil {
			t.Fatal(input)
		}
	}
}

// discoveryHost trusts only the provider origin login.example.test.
func discoveryHost(t *testing.T) *auth.Auth {
	t.Helper()
	host, err := auth.New(auth.Options{Store: memory.New(), BaseURL: "https://accounts.test", Secret: strings.Repeat("k", 40), TrustedOrigins: []string{"https://login.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	return host
}

// Discovery answers each failure with the documented status and code, and a
// malformed URL is refused without contacting the provider.
func TestDiscoveryErrorCodes(t *testing.T) {
	host := discoveryHost(t)
	const issuer = "https://login.example.test/tenant"
	doc := `{"issuer":"https://login.example.test/tenant","authorization_endpoint":"/authorize","token_endpoint":"/token","jwks_uri":"/keys"}`
	requests, served := 0, ""
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		status, body := 200, doc
		if served != "" {
			body = served
		}
		switch r.URL.Path {
		case "/tenant/missing":
			status = 404
		case "/tenant/failing":
			status = 500
		case "/tenant/gone":
			status = 410
		case "/tenant/slow":
			status = 408
		case "/tenant/empty":
			body = ""
		case "/tenant/created":
			status = 201
		case "/tenant/no-content":
			status, body = 204, ""
		case "/tenant/partial":
			body = strings.Replace(doc, `,"jwks_uri":"/keys"`, "", 1)
		case "/tenant/slash":
			body = strings.Replace(doc, issuer+`"`, issuer+`/"`, 1)
		case "/tenant/elsewhere":
			body = strings.Replace(doc, `"/token"`, `"https://elsewhere.example.test/token"`, 1)
		case "/tenant/unreachable":
			return nil, errors.New("connection refused")
		case "/tenant/ftp-token":
			body = strings.Replace(doc, `"/token"`, `"ftp://login.example.test/token"`, 1)
		}
		return &http.Response{Request: r, StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})}
	reply := func(err error) (int, string) {
		var e *auth.APIError
		if errors.As(err, &e) {
			return e.Status, e.Code
		}
		return 0, ""
	}
	fetch := func(path string) error {
		cfg := Config{Issuer: issuer, DiscoveryEndpoint: issuer + path}
		return hydrate(t.Context(), host.ExplicitlyTrustedOrigin, client, &cfg, false)
	}
	if status, code := reply(fetch("/missing")); status != 400 || code != "discovery_not_found" {
		t.Fatal("a 404 discovery document did not answer 400 discovery_not_found", status, code)
	}
	if status, code := reply(fetch("/failing")); status != 502 || code != "discovery_unexpected_error" {
		t.Fatal("a 500 discovery response did not answer 502 discovery_unexpected_error", status, code)
	}
	if status, code := reply(fetch("/gone")); status != 502 || code != "discovery_unexpected_error" {
		t.Fatal("a 410 discovery response did not answer 502 discovery_unexpected_error", status, code)
	}
	if status, code := reply(fetch("/unreachable")); status != 502 || code != "discovery_unexpected_error" {
		t.Fatal("a transport failure did not answer 502 discovery_unexpected_error", status, code)
	}
	if status, code := reply(fetch("/slow")); status != 502 || code != "discovery_timeout" {
		t.Fatal("a 408 discovery response did not answer 502 discovery_timeout", status, code)
	}
	if status, code := reply(fetch("/empty")); status != 400 || code != "discovery_invalid_json" {
		t.Fatal("an empty discovery document did not answer 400 discovery_invalid_json", status, code)
	}
	if status, code := reply(fetch("/partial")); status != 400 || code != "discovery_incomplete" {
		t.Fatal("a discovery document without jwks_uri did not answer 400 discovery_incomplete", status, code)
	}
	// Any 2xx carries the document, and the messages name what is wrong.
	if err := fetch("/created"); err != nil {
		t.Fatal("a 201 discovery document was refused", err)
	}
	if status, code := reply(fetch("/no-content")); status != 400 || code != "discovery_invalid_json" {
		t.Fatal("an empty 204 discovery answer did not answer 400 discovery_invalid_json", status, code)
	}
	if err := fetch("/partial"); err.Error() != "OIDC discovery document is missing required fields: Discovery document is missing required fields: jwks_uri" {
		t.Fatal("an incomplete discovery document did not name its missing fields", err)
	}
	if err := fetch("/slash"); err.Error() != `OIDC issuer mismatch: Discovered issuer "https://login.example.test/tenant/" does not match configured issuer "https://login.example.test/tenant"` {
		t.Fatal("an issuer mismatch did not name both issuers", err)
	}
	if status, code := reply(fetch("/slash")); status != 400 || code != "issuer_mismatch" {
		t.Fatal("an issuer differing by a trailing slash did not answer 400 issuer_mismatch", status, code)
	}
	if status, code := reply(fetch("/elsewhere")); status != 400 || code != "discovery_untrusted_origin" {
		t.Fatal("a discovered token endpoint on an untrusted origin did not answer 400 discovery_untrusted_origin", status, code)
	}
	if status, code := reply(fetch("/ftp-token")); status != 400 || code != "discovery_invalid_url" {
		t.Fatal("a discovered ftp token endpoint did not answer 400 discovery_invalid_url", status, code)
	}
	// Every discovered URL, stored or not, must sit on a trusted origin, and
	// the refusal names the field and the URL.
	for _, field := range []string{"token_endpoint", "authorization_endpoint", "jwks_uri", "userinfo_endpoint", "revocation_endpoint", "end_session_endpoint", "introspection_endpoint"} {
		served = strings.Replace(doc, "}", `,"`+field+`":"https://elsewhere.example.test/`+field+`"}`, 1)
		var e *auth.APIError
		if err := fetch("/served"); !errors.As(err, &e) || e.Status != 400 || e.Code != "discovery_untrusted_origin" || e.Message != `Untrusted OIDC discovery URL: The `+field+` "https://elsewhere.example.test/`+field+`" is not trusted by your trusted origins configuration.` {
			t.Fatal("a discovered URL on an untrusted origin was not refused with discovery_untrusted_origin", field, err)
		}
	}
	served = strings.Replace(doc, "}", `,"revocation_endpoint":"ftp://login.example.test/revoke"}`, 1)
	if status, code := reply(fetch("/served")); status != 400 || code != "discovery_invalid_url" {
		t.Fatal("a discovered ftp revocation endpoint did not answer 400 discovery_invalid_url", status, code)
	}
	// A document missing a required field is refused even when oidcConfig
	// supplies that endpoint.
	for _, field := range []string{`"issuer":"https://login.example.test/tenant",`, `"authorization_endpoint":"/authorize",`, `,"token_endpoint":"/token"`, `,"jwks_uri":"/keys"`} {
		served = strings.Replace(doc, field, "", 1)
		cfg := Config{Issuer: issuer, DiscoveryEndpoint: issuer + "/served", AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", JWKSEndpoint: issuer + "/keys"}
		if status, code := reply(hydrate(t.Context(), host.ExplicitlyTrustedOrigin, client, &cfg, false)); served == doc || status != 400 || code != "discovery_incomplete" {
			t.Fatal("a discovery document missing a required field did not answer 400 discovery_incomplete", field, status, code)
		}
	}
	served = ""
	fetched := requests
	for _, cfg := range []Config{
		{Issuer: "ftp://login.example.test/tenant"},
		{Issuer: "not-a-url"},
		{Issuer: issuer, DiscoveryEndpoint: "https://login.example.test/%zz"},
		{Issuer: issuer, DiscoveryEndpoint: "https://admin@login.example.test/tenant/.well-known/openid-configuration"},
	} {
		if status, code := reply(hydrate(t.Context(), host.ExplicitlyTrustedOrigin, client, &cfg, false)); status != 400 || code != "discovery_invalid_url" {
			t.Fatal("a malformed issuer or discovery URL did not answer 400 discovery_invalid_url", cfg.Issuer, cfg.DiscoveryEndpoint, status, code)
		}
	}
	// A configured endpoint on a private host is refused before any request.
	for _, cfg := range []Config{
		{Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: "http://169.254.169.254/latest/meta-data/", JWKSEndpoint: issuer + "/keys"},
		{Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", JWKSEndpoint: issuer + "/keys", UserInfoEndpoint: "https://10.0.0.5/userinfo"},
		{Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", JWKSEndpoint: "http://localhost:6379/"},
	} {
		if status, code := reply(hydrate(t.Context(), host.ExplicitlyTrustedOrigin, client, &cfg, true)); status != 400 || code != "discovery_private_host" {
			t.Fatal("a private oidcConfig endpoint did not answer 400 discovery_private_host", cfg, status, code)
		}
	}
	manual := Config{Issuer: issuer, AuthorizationEndpoint: "not-a-url", TokenEndpoint: issuer + "/token", JWKSEndpoint: issuer + "/keys"}
	if status, code := reply(hydrate(t.Context(), host.ExplicitlyTrustedOrigin, client, &manual, true)); status != 400 || code != "discovery_invalid_url" {
		t.Fatal("a malformed configured endpoint did not answer 400 discovery_invalid_url", status, code)
	}
	if requests != fetched {
		t.Fatal("discovery contacted the provider for a malformed URL")
	}
}

// Discovery stores an advertised UserInfo endpoint, relative to the issuer
// or absolute on a trusted origin, unless oidcConfig already sets one.
func TestDiscoveryHydratesUserInfoEndpoint(t *testing.T) {
	host := discoveryHost(t)
	const issuer = "https://login.example.test/tenant"
	userinfo := ""
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"issuer":"` + issuer + `","authorization_endpoint":"/authorize","token_endpoint":"/token","jwks_uri":"/keys"` + userinfo + `}`
		return &http.Response{Request: r, StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})}
	userinfo = `,"userinfo_endpoint":"/userinfo"`
	cfg := Config{Issuer: issuer}
	if err := hydrate(t.Context(), host.ExplicitlyTrustedOrigin, client, &cfg, false); err != nil || cfg.UserInfoEndpoint != issuer+"/userinfo" {
		t.Fatal("discovery did not store the issuer-relative userinfo_endpoint", cfg.UserInfoEndpoint, err)
	}
	userinfo = `,"userinfo_endpoint":"https://login.example.test/profile/me"`
	cfg = Config{Issuer: issuer}
	if err := hydrate(t.Context(), host.ExplicitlyTrustedOrigin, client, &cfg, false); err != nil || cfg.UserInfoEndpoint != "https://login.example.test/profile/me" {
		t.Fatal("discovery did not store an absolute userinfo_endpoint", cfg.UserInfoEndpoint, err)
	}
	cfg = Config{Issuer: issuer, UserInfoEndpoint: "https://login.example.test/claims"}
	if err := hydrate(t.Context(), host.ExplicitlyTrustedOrigin, client, &cfg, false); err != nil || cfg.UserInfoEndpoint != "https://login.example.test/claims" {
		t.Fatal("discovery replaced a configured UserInfo endpoint", cfg.UserInfoEndpoint, err)
	}
	userinfo = ""
	cfg = Config{Issuer: issuer}
	if err := hydrate(t.Context(), host.ExplicitlyTrustedOrigin, client, &cfg, false); err != nil || cfg.UserInfoEndpoint != "" {
		t.Fatal("discovery invented a UserInfo endpoint the document does not advertise", cfg.UserInfoEndpoint, err)
	}
	userinfo = `,"userinfo_endpoint":"https://10.0.0.5/userinfo"`
	cfg = Config{Issuer: issuer}
	var e *auth.APIError
	if err := hydrate(t.Context(), host.ExplicitlyTrustedOrigin, client, &cfg, false); !errors.As(err, &e) || e.Status != 400 || e.Code != "discovery_untrusted_origin" || cfg.UserInfoEndpoint != "" {
		t.Fatal("discovery stored a private userinfo_endpoint", err)
	}
}

// Sign-in discovers the endpoints a stored configuration leaves out.
func TestNeedsRuntimeDiscovery(t *testing.T) {
	if !needsRuntimeDiscovery(nil) {
		t.Fatal("a missing configuration did not need discovery")
	}
	full := Config{AuthorizationEndpoint: "https://login.example.test/authorize", TokenEndpoint: "https://login.example.test/token", JWKSEndpoint: "https://login.example.test/keys"}
	if needsRuntimeDiscovery(&full) {
		t.Fatal("a complete configuration needed runtime discovery")
	}
	for _, blank := range []func(*Config){func(c *Config) { c.AuthorizationEndpoint = "" }, func(c *Config) { c.TokenEndpoint = "" }, func(c *Config) { c.JWKSEndpoint = "" }} {
		c := full
		blank(&c)
		if !needsRuntimeDiscovery(&c) {
			t.Fatal("a configuration missing an endpoint did not need discovery", c)
		}
	}
}

// Discovery computes the document URL from the issuer, records it, keeps
// configured endpoints and picks the token endpoint authentication method.
func TestDiscoveryHydratedConfiguration(t *testing.T) {
	host := discoveryHost(t)
	const issuer = "https://login.example.test/tenant"
	methods, fetched := "", ""
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		fetched = r.URL.String()
		doc := `{"issuer":"` + issuer + `","authorization_endpoint":"/authorize","token_endpoint":"/token","jwks_uri":"/keys"` + methods + `}`
		return &http.Response{Request: r, StatusCode: 200, Body: io.NopCloser(strings.NewReader(doc)), Header: http.Header{}}, nil
	})}
	hydrated := func(cfg Config) Config {
		t.Helper()
		if err := hydrate(t.Context(), host.ExplicitlyTrustedOrigin, client, &cfg, false); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	cfg := hydrated(Config{Issuer: issuer})
	if fetched != issuer+"/.well-known/openid-configuration" || cfg.DiscoveryEndpoint != issuer+"/.well-known/openid-configuration" {
		t.Fatal("the discovery URL was not computed and recorded from the issuer", fetched, cfg.DiscoveryEndpoint)
	}
	// A configured authorization endpoint is kept while the others fill in.
	cfg = hydrated(Config{Issuer: issuer, AuthorizationEndpoint: issuer + "/custom-authorize"})
	if cfg.AuthorizationEndpoint != issuer+"/custom-authorize" || cfg.TokenEndpoint != issuer+"/token" || cfg.JWKSEndpoint != issuer+"/keys" {
		t.Fatal("a configured endpoint was replaced by the discovered one", cfg)
	}
	for _, c := range []struct{ advertised, configured, want string }{
		{"", "", "client_secret_basic"},
		{`,"token_endpoint_auth_methods_supported":["tls_client_auth"]`, "", "client_secret_basic"},
		{`,"token_endpoint_auth_methods_supported":["client_secret_post"]`, "", "client_secret_post"},
		{`,"token_endpoint_auth_methods_supported":["private_key_jwt"]`, "", "private_key_jwt"},
		{`,"token_endpoint_auth_methods_supported":["client_secret_basic"]`, "client_secret_post", "client_secret_post"},
		{`,"token_endpoint_auth_methods_supported":["client_secret_post"]`, "client_secret_basic", "client_secret_basic"},
	} {
		methods = c.advertised
		if got := hydrated(Config{Issuer: issuer, TokenEndpointAuthentication: c.configured}).TokenEndpointAuthentication; got != c.want {
			t.Fatal("discovery chose the wrong token endpoint authentication", c.advertised, c.configured, got)
		}
	}
}

// An untrusted discovery URL is written as another runtime's URL parser
// writes it.
func TestUntrustedDiscoveryURL(t *testing.T) {
	for raw, want := range map[string]string{"https://IDP.Example.test:443": "https://idp.example.test/", "HTTP://idp.test:80/x": "http://idp.test/x", "https://idp.test:8443/a?b=c": "https://idp.test:8443/a?b=c", "https://[2001:DB8::1]:443/": "https://[2001:db8::1]/", "https://idp.test/a/./b/../c?d=e": "https://idp.test/a/c?d=e", "https://idp.test/token?": "https://idp.test/token?", "https://idp.test/a/%2E%2e/b": "https://idp.test/b", "https://idp.test/a/.%2e/b/%2e/c": "https://idp.test/b/c"} {
		if got := whatwgURL(raw); got != want {
			t.Fatal("an untrusted URL was not normalized", raw, got, want)
		}
	}
}

// The callback reports a discovery failure with the raw message, as another
// runtime does, without the registration prefix.
func TestCallbackDiscoveryMessage(t *testing.T) {
	for _, c := range []struct{ code, message, want string }{
		{"discovery_incomplete", "OIDC discovery document is missing required fields: Discovery document is missing required fields: jwks_uri", "Discovery document is missing required fields: jwks_uri"},
		{"issuer_mismatch", `OIDC issuer mismatch: Discovered issuer "a" does not match configured issuer "b"`, `Discovered issuer "a" does not match configured issuer "b"`},
		{"discovery_not_found", "OIDC discovery endpoint not found. The issuer may not support OIDC discovery, or the URL is incorrect. Discovery endpoint not found", "Discovery endpoint not found"},
		{"discovery_timeout", "OIDC discovery timed out: Discovery request timed out", "Discovery request timed out"},
		{"discovery_invalid_json", "OIDC discovery returned invalid data: Discovery endpoint returned invalid JSON", "Discovery endpoint returned invalid JSON"},
		{"discovery_unexpected_error", "OIDC discovery failed: Unexpected discovery error: Internal Server Error", "Unexpected discovery error: Internal Server Error"},
		{"discovery_untrusted_origin", `Untrusted OIDC discovery URL: The main discovery endpoint "https://idp.test/" is not trusted by your trusted origins configuration.`, `The main discovery endpoint "https://idp.test/" is not trusted by your trusted origins configuration.`},
	} {
		if got := callbackDiscoveryMessage(&auth.APIError{Code: c.code, Message: c.message}); got != c.want {
			t.Fatal("the callback discovery message differs from the raw one", c.code, got)
		}
	}
}

// Discovery derives the document URL from the issuer, keeps every endpoint
// and client authentication method the configuration sets, and picks a
// method from the advertised list in another runtime's order.
func TestDiscoveryHydrationKeepsConfiguredValues(t *testing.T) {
	const issuer = "https://login.example.test/tenant"
	host, err := auth.New(auth.Options{Store: memory.New(), BaseURL: "https://accounts.test", Secret: strings.Repeat("k", 40), TrustedOrigins: []string{"https://login.example.test", "https://keys.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	methods := `"token_endpoint_auth_methods_supported":["client_secret_basic"],`
	var fetched string
	docIssuer := issuer + "/"
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		fetched = r.URL.String()
		doc := `{"issuer":"` + docIssuer + `","authorization_endpoint":"/authorize","token_endpoint":"/token","jwks_uri":"/keys",` + methods + `"x-vendor":{"anything":[1,2]}}`
		return &http.Response{Request: r, StatusCode: 200, Body: io.NopCloser(strings.NewReader(doc)), Header: http.Header{}}, nil
	})}
	hydrated := func(cfg Config) Config {
		t.Helper()
		if err := hydrate(t.Context(), host.ExplicitlyTrustedOrigin, client, &cfg, false); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	// A trailing slash on the issuer still names one well-known document,
	// and the hydrated configuration records it.
	cfg := hydrated(Config{Issuer: issuer + "/"})
	if fetched != issuer+"/.well-known/openid-configuration" || cfg.DiscoveryEndpoint != issuer+"/.well-known/openid-configuration" {
		t.Fatal("the discovery URL was not derived from the issuer", fetched, cfg.DiscoveryEndpoint)
	}
	docIssuer = issuer
	// Configured endpoints and method win over the document.
	cfg = hydrated(Config{Issuer: issuer, AuthorizationEndpoint: issuer + "/custom-authorize", TokenEndpoint: "https://keys.example.test/token", JWKSEndpoint: "https://keys.example.test/keys", TokenEndpointAuthentication: "client_secret_post"})
	if cfg.AuthorizationEndpoint != issuer+"/custom-authorize" || cfg.TokenEndpoint != "https://keys.example.test/token" || cfg.JWKSEndpoint != "https://keys.example.test/keys" || cfg.TokenEndpointAuthentication != "client_secret_post" {
		t.Fatal("discovery replaced configured values", cfg)
	}
	if cfg = hydrated(Config{Issuer: issuer, AuthorizationEndpoint: issuer + "/custom-authorize"}); cfg.AuthorizationEndpoint != issuer+"/custom-authorize" || cfg.TokenEndpoint != issuer+"/token" || cfg.JWKSEndpoint != issuer+"/keys" {
		t.Fatal("discovery did not fill only the missing endpoints", cfg)
	}
	methods = `"token_endpoint_auth_methods_supported":["client_secret_post"],`
	if cfg = hydrated(Config{Issuer: issuer, TokenEndpointAuthentication: "client_secret_basic"}); cfg.TokenEndpointAuthentication != "client_secret_basic" {
		t.Fatal("discovery replaced a configured client authentication method", cfg.TokenEndpointAuthentication)
	}
	// Discovered endpoints are resolved against the issuer's path and
	// written as another runtime's URL parser writes them.
	saved := docIssuer
	docIssuer = issuer + "/"
	client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		doc := `{"issuer":"` + docIssuer + `","authorization_endpoint":"//authorize","token_endpoint":"https://LOGIN.example.test:443/oauth/../token","jwks_uri":"keys/"}`
		return &http.Response{Request: r, StatusCode: 200, Body: io.NopCloser(strings.NewReader(doc)), Header: http.Header{}}, nil
	})
	if cfg = hydrated(Config{Issuer: issuer + "/"}); cfg.AuthorizationEndpoint != issuer+"/authorize" || cfg.TokenEndpoint != "https://login.example.test/token" || cfg.JWKSEndpoint != issuer+"/keys/" {
		t.Fatal("discovered endpoints were not resolved and normalized as another runtime does", cfg.AuthorizationEndpoint, cfg.TokenEndpoint, cfg.JWKSEndpoint)
	}
	docIssuer = saved
	client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		fetched = r.URL.String()
		doc := `{"issuer":"` + docIssuer + `","authorization_endpoint":"/authorize","token_endpoint":"/token","jwks_uri":"/keys",` + methods + `"x-vendor":{"anything":[1,2]}}`
		return &http.Response{Request: r, StatusCode: 200, Body: io.NopCloser(strings.NewReader(doc)), Header: http.Header{}}, nil
	})
	// An unset method takes the first advertised one in the order
	// client_secret_basic, client_secret_post, private_key_jwt; none or only
	// unknown ones mean client_secret_basic.
	for list, want := range map[string]string{
		``: "client_secret_basic", `"token_endpoint_auth_methods_supported":[],`: "client_secret_basic",
		`"token_endpoint_auth_methods_supported":["client_secret_post"],`:                   "client_secret_post",
		`"token_endpoint_auth_methods_supported":["private_key_jwt"],`:                      "private_key_jwt",
		`"token_endpoint_auth_methods_supported":["private_key_jwt","client_secret_post"],`: "client_secret_post",
		`"token_endpoint_auth_methods_supported":["tls_client_auth"],`:                      "client_secret_basic",
	} {
		methods = list
		if cfg = hydrated(Config{Issuer: issuer}); cfg.TokenEndpointAuthentication != want {
			t.Fatal("discovery chose the wrong client authentication method", list, cfg.TokenEndpointAuthentication, want)
		}
	}
}
