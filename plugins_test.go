package plainauth_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	authn "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/sqlite"
)

func TestPluginRegistrationAndDispatch(t *testing.T) {
	calls := 0
	handle := func(ctx authn.EndpointContext) (any, error) {
		calls++
		ctx.ResponseHeader.Set("X-Fixture", "received")
		if ctx.Body["value"] != "sample" || ctx.Auth == nil {
			t.Fatal("missing plugin context")
		}
		return ctx.Body, nil
	}
	ep := authn.Endpoint{Method: "POST", Path: "/fixture", Handler: handle}
	auth := newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example", Plugins: []authn.Plugin{{ID: "example", Endpoints: []authn.Endpoint{ep}}}})
	h := http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
	serve(t, auth, "GET", "/api/auth/fixture", "", nil, 404)
	res := serve(t, auth, "POST", "/api/auth/fixture", `{"value":"sample"}`, h, 200)
	if res.Header.Get("X-Fixture") != "received" {
		t.Fatal("missing plugin header")
	}
	h.Set("Cookie", "theme=light")
	h.Set("Origin", "https://other.example")
	serve(t, auth, "POST", "/api/auth/fixture", `{"value":"sample"}`, h, 403)
	h.Set("Origin", "https://auth.example")
	serve(t, auth, "POST", "/api/auth/fixture", `{"callbackURL":"https://other.example"}`, h, 403)
	if calls != 1 {
		t.Fatalf("expected one plugin dispatch, got %d", calls)
	}

	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, plugins := range [][]authn.Plugin{
		{{ID: "duplicate"}, {ID: "duplicate"}},
		{{ID: "first", Endpoints: []authn.Endpoint{ep}}, {ID: "second", Endpoints: []authn.Endpoint{ep}}},
		{{ID: "collision", Endpoints: []authn.Endpoint{{Method: "GET", Path: "/ok", Handler: handle}}}},
		{{ID: "invalid", Endpoints: []authn.Endpoint{{Method: "POST", Path: "invalid", Handler: handle}}}},
	} {
		_, err := authn.New(authn.Options{Store: store, BaseURL: "http://auth.example", Secret: "unit-test-secret-0123456789-abcdefghijk", Plugins: plugins})
		if err == nil {
			t.Fatalf("expected invalid registration: %+v", plugins)
		}
	}
}

func TestPluginStatusOnlyError(t *testing.T) {
	plain := &authn.APIError{Status: http.StatusBadRequest}
	if plain.Error() != "" {
		t.Fatalf("plain APIError changed its native message: %q", plain.Error())
	}
	empty := fmt.Errorf("role update: %w", authn.StatusOnlyError(http.StatusBadRequest))
	pointer := authn.StatusOnlyError(http.StatusForbidden)
	var api *authn.APIError
	if !errors.As(empty, &api) || api.Status != http.StatusBadRequest || api.Message != http.StatusText(http.StatusBadRequest) {
		t.Fatalf("status-only error lost its native APIError: %#v", api)
	}
	for _, test := range []struct {
		name, body string
		status     int
		err        error
	}{
		{"plain", "{\"message\":\"\"}\n", 400, plain},
		{"status-only", "", 400, empty},
		{"status-only-pointer", "", 403, &pointer},
		{"invalid-status", "", 500, authn.StatusOnlyError(0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			ep := authn.Endpoint{Method: http.MethodGet, Path: "/fixture", Handler: func(authn.EndpointContext) (any, error) { return nil, test.err }}
			a := newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example", Plugins: []authn.Plugin{{ID: "fixture", Endpoints: []authn.Endpoint{ep}}}})
			r := httptest.NewRequest(http.MethodGet, "https://auth.example/api/auth/fixture", nil)
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			if w.Code != test.status || w.Body.String() != test.body {
				t.Fatalf("wire status and body: %d %q", w.Code, w.Body.String())
			}
		})
	}
}
