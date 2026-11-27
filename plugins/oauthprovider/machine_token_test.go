package oauthprovider

import (
	"encoding/json"
	"net/http"
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
