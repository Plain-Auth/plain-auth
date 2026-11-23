package goapi_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/sqlite"
)

// Run plugin middleware by path pattern, let OnRequest continue, interrupt or
// edit a request, and let OnResponse change every response before it is written.
func TestPluginMiddlewareRequestsAndResponses(t *testing.T) {
	var mu sync.Mutex
	var events []string
	record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
	seen := func() string { mu.Lock(); defer mu.Unlock(); s := strings.Join(events, ","); events = nil; return s }
	middleware := func(name, path string) authn.Middleware {
		return authn.Middleware{Path: path, Run: func(c *authn.HookContext) error {
			record(name + ":" + path)
			switch c.Request.URL.Query().Get(name) {
			case "reject":
				return &authn.APIError{Status: 403, Code: "BLOCKED_BY_MIDDLEWARE", Message: "Blocked"}
			case "page":
				c.Respond(authn.HTMLPage("<p>maintenance</p>"))
			}
			return nil
		}}
	}
	on := true
	auth := newHTTPAuth(t, authn.Options{
		BaseURL: "https://auth.example", RateLimit: &on,
		RateLimitRules: map[string]*authn.RateLimitRule{"/tenant": {Max: 3, Window: time.Minute}},
		Hooks: authn.EndpointHooks{Before: []authn.EndpointHook{{Run: func(c *authn.HookContext) error {
			record("before")
			return nil
		}}}},
		Plugins: []authn.Plugin{
			{
				ID:         "first",
				Middleware: []authn.Middleware{middleware("exact", "/tenant"), middleware("all", "/**")},
				Endpoints: []authn.Endpoint{{Method: "GET", Path: "/tenant", Handler: func(c authn.EndpointContext) (any, error) {
					return map[string]any{"tenant": c.Request.Header.Get("X-Tenant")}, nil
				}}},
				OnRequest: func(c authn.RequestContext) error {
					switch c.Request.URL.Query().Get("request") {
					case "interrupt":
						// Interrupt the request with an error response.
						return &authn.APIError{Status: 503, Code: "MAINTENANCE", Message: "Down for maintenance"}
					case "edit":
						// Modify the request the endpoint reads.
						c.Request.Header.Set("X-Tenant", "acme")
					}
					return nil
				},
				OnResponse: func(c *authn.ResponseContext) {
					record("response-first:" + c.Path + ":" + http.StatusText(c.Status))
					c.Header.Set("X-Served-By", "first")
					if c.Request.URL.Query().Get("response") == "replace" {
						c.Status, c.Body = http.StatusAccepted, []byte(`{"replaced":true}`)
					}
				},
			},
			{
				ID:         "second",
				Middleware: []authn.Middleware{middleware("one", "/:segment"), middleware("reset", "/reset-password/*")},
				OnResponse: func(c *authn.ResponseContext) {
					record("response-second:" + c.Header.Get("X-Served-By"))
				},
			},
		},
	})
	call := func(method, target string, status int) (*http.Response, string) {
		t.Helper()
		r := httptest.NewRequest(method, "https://auth.example/api/auth"+target, nil)
		host := r
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		if host.Header.Get("X-Tenant") != "" {
			t.Fatal("an OnRequest edit reached the host's request")
		}
		res := w.Result()
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != status {
			t.Fatalf("%s %s returned %d, want %d: %s", method, target, res.StatusCode, status, body)
		}
		return res, strings.TrimSpace(string(body))
	}

	// Middleware runs broadest pattern first, then the endpoint hooks.
	_, body := call("GET", "/tenant", 200)
	if got := seen(); got != "all:/**,one:/:segment,exact:/tenant,before,response-first:/tenant:OK,response-second:first" || body != `{"tenant":""}` {
		t.Fatal("unexpected middleware order", got, body)
	}
	// A pattern matches only its own segments.
	call("GET", "/reset-password/reset-token-1?callbackURL=/done", 302)
	if got := seen(); got != "all:/**,reset:/reset-password/*,before,response-first:/reset-password/reset-token-1:Found,response-second:first" {
		t.Fatal("unexpected middleware matches", got)
	}

	// Middleware rejects a request or answers it with its own page.
	if _, body = call("GET", "/tenant?exact=reject", 403); !strings.Contains(body, "BLOCKED_BY_MIDDLEWARE") {
		t.Fatal("the middleware did not reject the request", body)
	}
	res, body := call("GET", "/ok?all=page", 200)
	if got := seen(); body != "<p>maintenance</p>" || res.Header.Get("Content-Type") != "text/html; charset=utf-8" || got != "all:/**,one:/:segment,exact:/tenant,response-first:/tenant:Forbidden,response-second:first,all:/**,response-first:/ok:OK,response-second:first" {
		t.Fatal("the middleware did not answer the request", body, got)
	}

	// OnRequest continues, edits a copy of the request, or interrupts it without OnResponse.
	if _, body = call("GET", "/tenant?request=edit", 200); body != `{"tenant":"acme"}` {
		t.Fatal("the OnRequest edit did not reach the endpoint", body)
	}
	seen()
	if _, body = call("GET", "/tenant?request=interrupt", 503); !strings.Contains(body, "MAINTENANCE") || seen() != "" {
		t.Fatal("OnRequest did not interrupt the request before middleware and OnResponse", body)
	}

	// OnResponse sees and changes every response, including errors, unknown routes and rate limits.
	res, body = call("GET", "/tenant?response=replace", 202)
	if body != `{"replaced":true}` || res.Header.Get("X-Served-By") != "first" {
		t.Fatal("OnResponse did not replace the response", body)
	}
	seen()
	call("GET", "/missing", 404)
	call("POST", "/sign-in/email", 400)
	if got := seen(); got != "response-first:/missing:Not Found,response-second:first,all:/**,before,response-first:/sign-in/email:Bad Request,response-second:first" {
		t.Fatal("OnResponse skipped an error response", got)
	}
	call("GET", "/tenant", 429)
	if got := seen(); got != "response-first:/tenant:Too Many Requests,response-second:first" {
		t.Fatal("OnResponse skipped a rate-limited response", got)
	}

	// Middleware needs a rooted path, ** only at the end, and Run.
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	run := func(*authn.HookContext) error { return nil }
	for _, bad := range []authn.Middleware{{Path: "/a/**/b", Run: run}, {Path: "sign-in", Run: run}, {Path: "/ok"}} {
		if _, err := authn.New(authn.Options{Store: store, BaseURL: "https://auth.example", Secret: strings.Repeat("s", 32), Plugins: []authn.Plugin{{ID: "bad", Middleware: []authn.Middleware{bad}}}}); err == nil {
			t.Fatal("invalid middleware was accepted", bad.Path)
		}
	}
}
