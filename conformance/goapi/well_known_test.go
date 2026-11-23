package goapi_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
)

func TestWellKnownRegistration(t *testing.T) {
	const path = "/auth/.well-known/example"
	original := json.RawMessage(`{"issuer":"test"}`)
	headers := http.Header{"X-Published": {"yes"}}
	plugin := func(id, path string, b json.RawMessage) auth.Plugin {
		return auth.Plugin{ID: id, WellKnown: func(*auth.Auth, auth.Store) (map[string]auth.WellKnownDocument, error) {
			return map[string]auth.WellKnownDocument{path: {Body: b, Headers: headers}}, nil
		}}
	}
	newHost := func(plugins ...auth.Plugin) (*auth.Auth, error) {
		return auth.New(auth.Options{BaseURL: "https://auth.example.test", BasePath: "/auth", Secret: strings.Repeat("s", 40), Store: memory.New(), Plugins: plugins})
	}
	fromPlugin := errors.New("issuer unavailable")
	_, err := newHost(auth.Plugin{ID: "failure", WellKnown: func(*auth.Auth, auth.Store) (map[string]auth.WellKnownDocument, error) { return nil, fromPlugin }})
	if !errors.Is(err, fromPlugin) {
		t.Fatal(err)
	}
	registered := plugin("one", path, original)
	for _, pair := range [][]auth.Plugin{
		{registered, plugin("two", path, original)},
		{plugin("bad", "/auth/.well-known/%2e%2e/logout", original)},
		{plugin("bad", "/ordinary", original)},
		{plugin("bad", path+"?q", original)},
		{plugin("bad", path, nil)}, {plugin("bad", path, json.RawMessage("null"))},
		{registered, {ID: "post", Endpoints: []auth.Endpoint{{Method: "POST", Path: "/.well-known/example",
			Handler: func(auth.EndpointContext) (any, error) { return nil, nil },
		}}}},
	} {
		if _, err := newHost(pair...); err == nil {
			t.Fatalf("accepted invalid registration for %s", pair[0].ID)
		}
	}
	a, err := newHost(registered)
	if err != nil {
		t.Fatal(err)
	}
	original[0], headers["X-Published"][0] = '!', "changed"
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	if w.Code != 200 || w.Body.String() != `{"issuer":"test"}` || w.Header().Get("X-Published") != "yes" {
		t.Fatal(w.Code, w.Header(), w.Body.String())
	}
}
