package oauthprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"testing"
	"time"
)

func TestMachineTokenConfiguration(t *testing.T) {
	for _, opts := range []TokenOptions{
		{MachineLifetime: -time.Second},
		{MachineLifetime: time.Millisecond},
		{ScopeLifetimes: map[string]time.Duration{"read": 0}},
		{ScopeLifetimes: map[string]time.Duration{"read": time.Second + time.Millisecond}},
	} {
		if _, err := New(Options{Tokens: opts}); err == nil {
			t.Fatal("accepted invalid token lifetime")
		}
	}
	options := TokenOptions{}
	if err := options.defaults(); err != nil {
		t.Fatal(err)
	}
	if options.MachineLifetime != time.Hour || options.RateLimit.Window != time.Minute || options.RateLimit.Max != 20 {
		t.Fatal("incorrect machine token defaults")
	}
	p, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range p.Endpoints {
		if endpoint.Path != "/oauth2/token" {
			continue
		}
		if endpoint.Method != http.MethodPost || !endpoint.RawBody {
			t.Fatal("token route must accept a raw POST body")
		}
		var operation struct {
			RequestBody struct {
				Content map[string]json.RawMessage `json:"content"`
			} `json:"requestBody"`
			Responses map[string]json.RawMessage `json:"responses"`
		}
		if err := json.Unmarshal(endpoint.OpenAPI, &operation); err != nil {
			t.Fatal(err)
		}
		if len(operation.RequestBody.Content) != 1 || operation.RequestBody.Content[tokenFormType] == nil || operation.Responses["200"] == nil {
			t.Fatal("incorrect token endpoint documentation")
		}
		return
	}
	t.Fatal("token endpoint missing when dynamic registration is disabled")
}

func TestIntrospectionEndpoint(t *testing.T) {
	testTokenActionEndpoint(t, "/oauth2/introspect", 100)
}

func TestRevocationEndpoint(t *testing.T) {
	testTokenActionEndpoint(t, "/oauth2/revoke", 30)
}

func testTokenActionEndpoint(t *testing.T, path string, max int) {
	t.Helper()
	p, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, ep := range p.Endpoints {
		if ep.Path != path {
			continue
		}
		if ep.Method != http.MethodPost || !ep.RawBody || ep.RateLimit == nil || ep.RateLimit.Max != max || ep.RateLimit.Window != time.Minute {
			t.Fatalf("%s: incorrect method, body or default limit", path)
		}
		var operation struct {
			RequestBody struct {
				Content map[string]json.RawMessage
			}
			Responses map[string]json.RawMessage
		}
		if err := json.Unmarshal(ep.OpenAPI, &operation); err != nil {
			t.Fatal(err)
		}
		if len(operation.RequestBody.Content) != 1 || operation.RequestBody.Content[tokenFormType] == nil || operation.Responses["200"] == nil {
			t.Fatal(path, "form or response missing from OpenAPI")
		}
		return
	}
	t.Fatal(path, "endpoint missing")
}

// Unset lifetimes take another runtime's defaults: an hour for access
// tokens, thirty days for refresh tokens and ten minutes for codes.
func TestTokenLifetimeDefaults(t *testing.T) {
	var tokens TokenOptions
	if err := tokens.defaults(); err != nil {
		t.Fatal(err)
	}
	var browser BrowserAuthorizationOptions
	if err := browser.defaults(); err != nil {
		t.Fatal(err)
	}
	if tokens.AccessLifetime != time.Hour || tokens.MachineLifetime != time.Hour || tokens.RefreshLifetime != 30*24*time.Hour || tokens.IDTokenLifetime != 10*time.Hour || browser.CodeLifetime != 10*time.Minute {
		t.Fatal("an unset lifetime did not take its default", tokens.AccessLifetime, tokens.MachineLifetime, tokens.RefreshLifetime, tokens.IDTokenLifetime, browser.CodeLifetime)
	}
}

// Default credentials are 32 ASCII letters, a configured generator replaces
// them, and each token kind is stored as its SHA-256 base64url digest or
// through its own hash function only.
func TestTokenGenerationAndStorage(t *testing.T) {
	ctx := t.Context()
	letters := regexp.MustCompile(`^[A-Za-z]{32}$`)
	id, err := randomClientCredential()
	if err != nil || !letters.MatchString(id) {
		t.Fatal("a default client credential is not 32 letters", id, err)
	}
	var tokens TokenOptions
	if err := tokens.defaults(); err != nil {
		t.Fatal(err)
	}
	issued, stored, err := tokens.newOpaqueToken(ctx)
	if err != nil || !letters.MatchString(issued) || stored != tokenDigest(issued) {
		t.Fatal("a default opaque access token is not 32 letters stored as its digest", issued, stored, err)
	}
	wire, digest, err := tokens.issueRefreshToken(ctx, "session")
	if err != nil || !letters.MatchString(wire) || digest != tokenDigest(wire) {
		t.Fatal("a default refresh token is not 32 letters stored as its digest", wire, digest, err)
	}
	if code, err := tokens.storedAuthorizationCode(ctx, "code"); err != nil || code != tokenDigest("code") {
		t.Fatal("an authorization code is not stored as its digest", code, err)
	}
	calls := map[string]int{}
	hash := func(kind string) func(context.Context, string) (string, error) {
		return func(_ context.Context, raw string) (string, error) { calls[kind]++; return kind + ":" + raw, nil }
	}
	custom := TokenOptions{HashOpaqueToken: hash("access"), HashRefreshToken: hash("refresh"), HashAuthorizationCode: hash("code"),
		GenerateOpaqueToken: func(context.Context) (string, error) { return "opaque-value", nil }, GenerateRefreshToken: func(context.Context) (string, error) { return "refresh-value", nil }}
	if err := custom.defaults(); err != nil {
		t.Fatal(err)
	}
	if issued, stored, err := custom.newOpaqueToken(ctx); err != nil || issued != "opaque-value" || stored != "access:opaque-value" {
		t.Fatal("a configured access token generator or hash was not used", issued, stored, err)
	}
	if wire, digest, err := custom.issueRefreshToken(ctx, "session"); err != nil || wire != "refresh-value" || digest != "refresh:refresh-value" {
		t.Fatal("a configured refresh token generator or hash was not used", wire, digest, err)
	}
	if code, err := custom.storedAuthorizationCode(ctx, "code"); err != nil || code != "code:code" {
		t.Fatal("a configured code hash was not used", code, err)
	}
	if calls["access"] != 1 || calls["refresh"] != 1 || calls["code"] != 1 {
		t.Fatal("a hash function ran for another token kind", calls)
	}
}
