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
	p, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, ep := range p.Endpoints {
		if ep.Path != "/oauth2/introspect" {
			continue
		}
		if ep.Method != http.MethodPost || !ep.RawBody || ep.RateLimit == nil || ep.RateLimit.Max != 100 || ep.RateLimit.Window != time.Minute {
			t.Fatal("incorrect introspection method, body or default limit")
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
			t.Fatal("introspection form or response missing from OpenAPI")
		}
		return
	}
	t.Fatal("introspection endpoint missing")
}
