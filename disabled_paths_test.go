package plainauth_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/plugins/openapi"
)

func TestDisabledHTTPPaths(t *testing.T) {
	for _, mount := range []string{"/identity", "/"} {
		t.Run(mount, func(t *testing.T) {
			paths := []string{"/get-session", "/signup-status/", "/sign-up/email", "/callback/work"}
			calls, probes := 0, 0
			p := auth.Plugin{ID: "host",
				CredentialSessions: &auth.CredentialSessionResolver{SelectRequest: func(*http.Request) (auth.CredentialVerifier, error) { probes++; return nil, nil }},
				OnRequest:          func(auth.RequestContext) error { calls++; return nil },
				Endpoints:          []auth.Endpoint{{Method: "GET", Path: "/signup-status", Handler: func(auth.EndpointContext) (any, error) { return true, nil }}},
			}
			api := newHTTPAuth(t, auth.Options{BaseURL: "https://auth.example", BasePath: mount, DisabledPaths: paths, DeferSessionRefresh: true, Plugins: []auth.Plugin{p}})
			paths[0] = "/ok"
			root := strings.TrimRight(mount, "/")
			for _, tc := range []struct{ method, path string }{{"GET", "/get-session"}, {"POST", "/get-session"}, {"GET", "/get-session/?view=public"}, {"POST", "/sign-up/email"}, {"GET", "/signup-status"}, {"GET", "/callback/work"}} {
				res := httptest.NewRecorder()
				req := httptest.NewRequest(tc.method, "https://auth.example"+root+tc.path, nil)
				if !api.HTTPPathDisabled(req) {
					t.Fatal("missing disabled path", tc)
				}
				api.ServeHTTP(res, req)
				if res.Code != 404 || len(res.Result().Cookies()) != 0 || calls != 0 || probes != 0 {
					t.Fatal("disabled route reached a request hook or issued cookies", tc, res.Code, calls)
				}
			}
			res := httptest.NewRecorder()
			api.ServeHTTP(res, httptest.NewRequest("GET", "https://auth.example"+root+"/ok", nil))
			if res.Code != 200 || calls != 1 || probes != 1 {
				t.Fatal("neighboring live route unavailable", res.Code, calls)
			}
			doc, err := openapi.Generate(api)
			if err != nil {
				t.Fatal(err)
			}
			table := doc["paths"].(map[string]any)
			for _, path := range []string{"/get-session", "/sign-up/email", "/signup-status"} {
				if _, found := table[path]; found {
					t.Fatal("disabled operation was published", path)
				}
			}
			if _, found := table["/sign-in/email"]; !found {
				t.Fatal("enabled sign-in operation disappeared from OpenAPI")
			}
			_, err = api.SignUpEmail(t.Context(), auth.SignUpInput{Name: "User", Email: "local@example.test", Password: "test-password"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal("mount policy disabled native registration", err)
			}
		})
	}
}

func TestDisabledPathConfiguration(t *testing.T) {
	for _, p := range []string{"", "relative", "https://auth.example/sign-up/email", "/login?provider=a", "/callback/:id", "/organization/*", "/ok#section"} {
		_, err := auth.New(auth.Options{BaseURL: "https://auth.example", Secret: strings.Repeat("s", 32), Store: memory.New(), DisabledPaths: []string{p}})
		if err == nil {
			t.Fatalf("accepted a nonliteral HTTP route %q", p)
		}
	}
}
