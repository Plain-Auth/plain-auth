package betterauth_test

import (
	"net/http"
	"testing"

	betterauth "github.com/nabuhadba/go-better-auth"
	"github.com/nabuhadba/go-better-auth/adapters/sqlite"
)

func TestPluginRegistrationAndDispatch(t *testing.T) {
	calls := 0
	handle := func(ctx betterauth.EndpointContext) (any, error) {
		calls++
		ctx.ResponseHeader.Set("X-Fixture", "received")
		if ctx.Body["value"] != "sample" || ctx.Auth == nil {
			t.Fatal("missing plugin context")
		}
		return ctx.Body, nil
	}
	ep := betterauth.Endpoint{Method: "POST", Path: "/fixture", Handler: handle}
	auth := newHTTPAuth(t, betterauth.Options{BaseURL: "https://auth.example", Plugins: []betterauth.Plugin{{ID: "example", Endpoints: []betterauth.Endpoint{ep}}}})
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
	for _, plugins := range [][]betterauth.Plugin{
		{{ID: "duplicate"}, {ID: "duplicate"}},
		{{ID: "first", Endpoints: []betterauth.Endpoint{ep}}, {ID: "second", Endpoints: []betterauth.Endpoint{ep}}},
		{{ID: "collision", Endpoints: []betterauth.Endpoint{{Method: "GET", Path: "/ok", Handler: handle}}}},
		{{ID: "invalid", Endpoints: []betterauth.Endpoint{{Method: "POST", Path: "invalid", Handler: handle}}}},
	} {
		_, err := betterauth.New(betterauth.Options{Store: store, BaseURL: "http://auth.example", Secret: "unit-test-secret-0123456789-abcdefghijk", Plugins: plugins})
		if err == nil {
			t.Fatalf("expected invalid registration: %+v", plugins)
		}
	}
}
