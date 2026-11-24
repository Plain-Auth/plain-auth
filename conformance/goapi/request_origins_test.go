package goapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

// TrustedOriginsForRequest adds origins for one request. Origin checks,
// callbacks, plugin redirects and the OAuth return all see them, the host
// function runs once per request, and a failure never trusts anything.
func TestTrustedOriginsForRequest(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			target, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
			target.RawQuery = url.Values{"code": {"code"}, "state": {r.URL.Query().Get("state")}}.Encode()
			http.Redirect(w, r, target.String(), http.StatusFound)
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","expires_in":3600}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer provider.Close()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	app := httptest.NewUnstartedServer(nil)
	base := "http://" + app.Listener.Addr().String()
	var calls atomic.Int32
	tenants := map[string][]string{
		"one":  {"", "https://one.example"},
		"wild": {"https://*.two.example"},
		"bad":  {"javascript://one.example"},
	}
	node, err := auth.New(auth.Options{
		Store: store, Secret: strings.Repeat("s", 32), BaseURL: base, EmailAndPassword: true, RateLimit: new(bool),
		TrustedOrigins: []string{"https://static.example"},
		TrustedOriginsForRequest: func(r *http.Request) ([]string, error) {
			calls.Add(1)
			if r.Body != http.NoBody || r.ContentLength != 0 {
				t.Error("the host function received the request body")
			}
			switch r.Header.Get("X-Tenant") {
			case "fail":
				return nil, errors.New("tenant lookup failed")
			case "unknown":
				return nil, &auth.APIError{Status: 404, Code: "UNKNOWN_TENANT", Message: "Unknown tenant"}
			case "no-status":
				return nil, &auth.APIError{Code: "UNKNOWN_TENANT", Message: "Unknown tenant"}
			case "typed-nil":
				var missing *auth.APIError
				return nil, missing
			case "oauth":
				return nil, &auth.OAuthError{Status: 400, Code: "invalid_request", Description: "tenant detail"}
			}
			return tenants[r.Header.Get("X-Tenant")], nil
		},
		SocialProviders: map[string]auth.OAuthProvider{"local": {
			Config: oauth2.Config{ClientID: "local-client", ClientSecret: "secret",
				Endpoint: oauth2.Endpoint{AuthURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token"}},
			Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) {
				return auth.OAuthProfile{Subject: "subject", Email: "social@example.org", EmailVerified: true, Name: "Social"}, nil
			},
		}},
		Plugins: []auth.Plugin{{ID: "tenant-redirect", Endpoints: []auth.Endpoint{{Method: "GET", Path: "/tenant/redirect",
			Handler: func(c auth.EndpointContext) (any, error) { return c.Redirect(c.Request.URL.Query().Get("to")) }}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	app.Config.Handler = node
	app.Start()
	defer app.Close()

	send := func(method, path, tenant, origin, body string) (*http.Response, string) {
		t.Helper()
		r := httptest.NewRequest(method, base+"/api/auth"+path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if tenant != "" {
			r.Header.Set("X-Tenant", tenant)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		node.ServeHTTP(w, r)
		data, _ := io.ReadAll(w.Result().Body)
		return w.Result(), string(data)
	}
	expect := func(res *http.Response, body string, status int, code string) {
		t.Helper()
		var problem struct{ Code string }
		_ = json.Unmarshal([]byte(body), &problem)
		if res.StatusCode != status || problem.Code != code {
			t.Fatalf("got %d %s, want %d %s", res.StatusCode, body, status, code)
		}
	}
	signUp := func(email, callback string) string {
		return `{"name":"Person","email":"` + email + `","password":"a tenant test password","callbackURL":"` + callback + `"}`
	}

	// Callbacks: the tenant's origin is trusted on its own requests only,
	// alongside the static origins.
	res, body := send("POST", "/sign-up/email", "one", "", signUp("one@example.org", "https://one.example/welcome"))
	expect(res, body, 200, "")
	res, body = send("POST", "/sign-up/email", "", "", signUp("two@example.org", "https://one.example/welcome"))
	expect(res, body, 403, "INVALID_CALLBACK_URL")
	res, body = send("POST", "/sign-up/email", "one", "", signUp("two@example.org", "https://static.example/welcome"))
	expect(res, body, 200, "")
	res, body = send("POST", "/sign-up/email", "wild", "", signUp("three@example.org", "https://eu.two.example/welcome"))
	expect(res, body, 200, "")

	// The origin check and the callback use the same set, resolved once.
	credentials := `{"email":"one@example.org","password":"a tenant test password"}`
	calls.Store(0)
	res, body = send("POST", "/sign-in/email", "one", "https://one.example", `{"email":"one@example.org","password":"a tenant test password","callbackURL":"https://one.example/home"}`)
	expect(res, body, 200, "")
	if !strings.Contains(body, `"url":"https://one.example/home"`) {
		t.Fatal("the sign-in did not return the tenant callback:", body)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("the host function ran %d times for one request", got)
	}
	res, body = send("POST", "/sign-in/email", "wild", "https://one.example", credentials)
	expect(res, body, 403, "INVALID_ORIGIN")
	res, body = send("POST", "/sign-in/email", "", "https://static.example", credentials)
	expect(res, body, 200, "")

	// A host APIError is the response; another failure or an invalid
	// pattern fails the request without detail.
	res, body = send("POST", "/sign-in/email", "unknown", "https://static.example", credentials)
	expect(res, body, 404, "UNKNOWN_TENANT")
	for _, tenant := range []string{"fail", "bad", "no-status", "typed-nil", "oauth"} {
		res, body = send("POST", "/sign-in/email", tenant, "https://static.example", credentials)
		expect(res, body, 500, "INTERNAL_SERVER_ERROR")
		if res.Header.Get("Cache-Control") != "no-store" || strings.Contains(body, "tenant") || strings.Contains(body, "javascript") {
			t.Fatalf("a failed lookup leaked detail or was cacheable: %v %s", res.Header, body)
		}
	}

	// Plugin endpoints resolve callbacks through EndpointContext.
	res, _ = send("GET", "/tenant/redirect?to=https://one.example/billing", "one", "", "")
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "https://one.example/billing" {
		t.Fatalf("plugin redirect: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	res, body = send("GET", "/tenant/redirect?to=https://one.example/billing", "", "", "")
	expect(res, body, 403, "INVALID_CALLBACK_URL")

	// Direct Go calls have no request, so they trust the static origins only.
	if _, err := node.CallbackURL("https://one.example/billing"); err == nil {
		t.Fatal("Auth.CallbackURL trusted a per-request origin")
	}
	_, err = node.SignUpEmail(t.Context(), auth.SignUpInput{Name: "Direct", Email: "direct@example.org", Password: "a tenant test password"},
		auth.RequestMeta{CallbackURL: "https://one.example/welcome"})
	var problem *auth.APIError
	if !errors.As(err, &problem) || problem.Code != "INVALID_CALLBACK_URL" {
		t.Fatal("a direct sign-up trusted a per-request origin:", err)
	}

	// The OAuth return re-checks its target with the callback request's set.
	social := func(callbackTenant string) string {
		t.Helper()
		jar, _ := cookiejar.New(nil)
		tenant := &tenantHeader{}
		tenant.set("one")
		browser := &http.Client{Jar: jar, Transport: tenant, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, _ := http.NewRequest("POST", base+"/api/auth/sign-in/social", bytes.NewReader([]byte(`{"provider":"local","callbackURL":"https://one.example/home"}`)))
		req.Header.Set("Content-Type", "application/json")
		res, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var start struct{ URL string }
		_ = json.NewDecoder(res.Body).Decode(&start)
		res.Body.Close()
		if res.StatusCode != 200 || start.URL == "" {
			t.Fatalf("social sign-in start: %d", res.StatusCode)
		}
		res, err = browser.Get(start.URL)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		tenant.set(callbackTenant)
		res, err = browser.Get(res.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusFound {
			t.Fatalf("OAuth callback: %d", res.StatusCode)
		}
		return res.Header.Get("Location")
	}
	if got := social("one"); got != "https://one.example/home" {
		t.Fatalf("OAuth return went to %q", got)
	}
	if got := social(""); got != base {
		t.Fatalf("an OAuth return the callback request no longer trusts went to %q", got)
	}
}
