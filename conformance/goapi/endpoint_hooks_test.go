package goapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

// Run before and after hooks around HTTP endpoints: reject, rewrite and answer
// requests, read and replace outcomes, and order user and plugin hooks.
func TestEndpointHooks(t *testing.T) {
	var mu sync.Mutex
	var events []string
	record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
	seen := func() string { mu.Lock(); defer mu.Unlock(); s := strings.Join(events, ","); events = nil; return s }
	path := func(paths ...string) func(*authn.HookContext) bool {
		return func(c *authn.HookContext) bool { return slices.Contains(paths, c.Path) }
	}
	var host *http.Request
	off := false
	auth := newHTTPAuth(t, authn.Options{
		BaseURL: "https://auth.example", RateLimit: &off, Logger: slog.New(slog.DiscardHandler),
		DisabledPaths: []string{"/sign-out"},
		SocialProviders: map[string]authn.OAuthProvider{"local": {
			Config: oauth2.Config{ClientID: "local-client", Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example/authorize", TokenURL: "https://idp.example/token"}},
			Resolve: func(context.Context, *oauth2.Token, string) (authn.OAuthProfile, error) {
				return authn.OAuthProfile{}, errors.New("unused")
			},
		}},
		Hooks: authn.EndpointHooks{
			Before: []authn.EndpointHook{
				{Run: func(c *authn.HookContext) error {
					record("user-before:" + c.Path)
					if c.Path != "/sign-up/email" {
						return nil
					}
					// Enforce an email domain.
					email, _ := c.Body["email"].(string)
					if !strings.HasSuffix(email, "@example.com") {
						return &authn.APIError{Status: 400, Code: "BAD_REQUEST", Message: "Email must end with @example.com"}
					}
					// Modify the request the endpoint reads.
					c.Body["name"] = "John Doe"
					c.Request.Header.Set("X-Hooked", "yes")
					if host != nil && host.Header.Get("X-Hooked") != "" {
						t.Error("a hook edit reached the host's request")
					}
					return nil
				}},
				{Match: path("/ok"), Run: func(c *authn.HookContext) error {
					switch c.Request.URL.Query().Get("answer") {
					case "json":
						c.Respond(map[string]any{"message": "Hello World"})
					case "redirect":
						c.Respond(authn.Redirect("/sign-up/name"))
					case "fail":
						return errors.New("database unavailable")
					case "panic":
						panic("hook bug")
					}
					return nil
				}},
				{Match: path("/sign-in/email"), Run: func(c *authn.HookContext) error {
					switch c.Request.URL.Query().Get("rewrite") {
					case "invalid":
						c.Body["email"] = 7
					case "callback":
						c.Body["callbackURL"] = "https://attacker.example/landing"
					}
					c.ResponseHeader.Set("X-Before", "set")
					return nil
				}},
				{Match: path("/list-sessions"), Run: func(c *authn.HookContext) error {
					session, err := c.Session()
					if err != nil || session == nil {
						return &authn.APIError{Status: 401, Code: "HOOK_NEEDS_SESSION", Message: "Sign in first"}
					}
					record("session:" + session.User.Email)
					return nil
				}},
				{Match: path("/reset-password/:token"), Run: func(c *authn.HookContext) error {
					record("token:" + c.Params["token"])
					return nil
				}},
				{Match: path("/sign-in/social", "/callback/:id"), Run: func(c *authn.HookContext) error {
					record("social:" + c.Path + ":" + c.Params["id"] + ":" + func() string { s, _ := c.Body["provider"].(string); return s }())
					return nil
				}},
			},
			After: []authn.EndpointHook{
				// One hook can handle several endpoints by branching on Path.
				{Run: func(c *authn.HookContext) error {
					switch {
					case strings.HasPrefix(c.Path, "/sign-up"):
						record("user-after:signed-up")
					case c.Path == "/sign-in/email":
						var problem *authn.APIError
						if errors.As(c.Err, &problem) {
							record("user-after:error:" + problem.Code)
							if c.Request.URL.Query().Get("replace") == "error" {
								return &authn.APIError{Status: 403, Code: "SIGN_IN_PAUSED", Message: "Sign-in is paused"}
							}
							if c.Request.URL.Query().Get("replace") == "result" {
								c.Result, c.Err = map[string]any{"recovered": true}, nil
							}
							return nil
						}
						record("user-after:signed-in:" + c.ResponseHeader.Get("X-Before") + ":" + boolString(strings.Contains(strings.Join(c.ResponseHeader.Values("Set-Cookie"), ";"), "session_token")))
					case c.Path == "/ok":
						record("user-after:ok")
					case c.Path == "/sign-in/social":
						result, _ := c.Result.(map[string]any)
						url, _ := result["url"].(string)
						record("user-after:social:" + boolString(strings.HasPrefix(url, "https://idp.example/authorize")))
					case c.Path == "/callback/:id":
						target, _ := c.Result.(authn.Redirect)
						record("user-after:callback:" + strings.TrimPrefix(string(target), "https://auth.example"))
					}
					return nil
				}},
			},
		},
		Plugins: []authn.Plugin{
			{ID: "audit", Hooks: authn.EndpointHooks{
				Before: []authn.EndpointHook{{Match: path("/sign-up/email", "/sign-in/email"), Run: func(c *authn.HookContext) error {
					record("audit-before:" + c.Request.Header.Get("X-Hooked"))
					return nil
				}}},
				After: []authn.EndpointHook{{Match: path("/sign-in/email"), Run: func(c *authn.HookContext) error {
					var problem *authn.APIError
					if errors.As(c.Err, &problem) {
						record("audit-after:" + problem.Code)
					}
					return nil
				}}},
			}},
			{ID: "metrics", Hooks: authn.EndpointHooks{
				Before: []authn.EndpointHook{{Match: path("/sign-in/email"), Run: func(*authn.HookContext) error { record("metrics-before"); return nil }}},
			}},
		},
	})
	h := http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
	var cookies []*http.Cookie
	call := func(method, target, body string, status int) map[string]any {
		t.Helper()
		r := httptest.NewRequest(method, "https://auth.example/api/auth"+target, strings.NewReader(body))
		r.Header = h.Clone()
		host = r
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		host = nil
		cookies = w.Result().Cookies()
		if w.Code != status {
			t.Fatalf("%s %s returned %d, want %d: %s", method, target, w.Code, status, w.Body)
		}
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if w.Code == 302 {
			out = map[string]any{"location": w.Header().Get("Location")}
		}
		return out
	}

	// A before hook rejects a sign-up outside the allowed domain; nothing is created.
	out := call("POST", "/sign-up/email", `{"email":"ada@other.test","password":"correct horse battery","name":"Ada"}`, 400)
	if out["message"] != "Email must end with @example.com" || seen() != "user-before:/sign-up/email" {
		t.Fatal("the domain restriction did not reject the sign-up", out)
	}
	call("POST", "/sign-in/email", `{"email":"ada@other.test","password":"correct horse battery"}`, 401)
	if got := seen(); got != "user-before:/sign-in/email,audit-before:,metrics-before,user-after:error:INVALID_EMAIL_OR_PASSWORD,audit-after:INVALID_EMAIL_OR_PASSWORD" {
		t.Fatal("unexpected hook order", got)
	}

	// A before hook rewrites the body and headers the endpoint reads.
	out = call("POST", "/sign-up/email", `{"email":"ada@example.com","password":"correct horse battery","name":"Ada"}`, 200)
	if user, _ := out["user"].(map[string]any); user["name"] != "John Doe" {
		t.Fatal("the rewritten name was not stored", out)
	}
	if got := seen(); got != "user-before:/sign-up/email,audit-before:yes,user-after:signed-up" {
		t.Fatal("unexpected sign-up hooks", got)
	}

	// After hooks see the response headers set so far, including the session cookie.
	call("POST", "/sign-in/email", `{"email":"ada@example.com","password":"correct horse battery"}`, 200)
	if got := seen(); got != "user-before:/sign-in/email,audit-before:,metrics-before,user-after:signed-in:set:true" {
		t.Fatal("unexpected sign-in hooks", got)
	}

	// A hook reads the caller's session.
	out = call("GET", "/list-sessions", "", 401)
	if out["code"] != "HOOK_NEEDS_SESSION" {
		t.Fatal("a hook without a session did not reject the request", out)
	}
	call("POST", "/sign-in/email", `{"email":"ada@example.com","password":"correct horse battery"}`, 200)
	for _, cookie := range cookies {
		h.Add("Cookie", cookie.Name+"="+cookie.Value)
	}
	call("GET", "/list-sessions", "", 200)
	h.Del("Cookie")
	if got := seen(); !strings.HasSuffix(got, "user-before:/list-sessions,session:ada@example.com") {
		t.Fatal("a hook did not read the caller's session", got)
	}

	// An after hook replaces an error with another error or with a result.
	out = call("POST", "/sign-in/email?replace=error", `{"email":"ada@example.com","password":"wrong password here"}`, 403)
	if out["code"] != "SIGN_IN_PAUSED" || !strings.HasSuffix(seen(), "user-after:error:INVALID_EMAIL_OR_PASSWORD,audit-after:SIGN_IN_PAUSED") {
		t.Fatal("a later after hook did not see the replaced error", out)
	}
	out = call("POST", "/sign-in/email?replace=result", `{"email":"ada@example.com","password":"wrong password here"}`, 200)
	if out["recovered"] != true {
		t.Fatal("an after hook did not replace the error with a result", out)
	}
	seen()

	// Rewritten input is checked like caller input.
	out = call("POST", "/sign-in/email?rewrite=invalid", `{"email":"ada@example.com","password":"correct horse battery"}`, 400)
	if out["code"] != "VALIDATION_ERROR" {
		t.Fatal("an invalid rewrite was not rejected", out)
	}
	call("POST", "/sign-in/email?rewrite=callback", `{"email":"ada@example.com","password":"correct horse battery"}`, 403)
	seen()

	// Before hooks answer with JSON or a redirect, and the endpoint and after hooks are skipped.
	if out = call("GET", "/ok?answer=json", "", 200); out["message"] != "Hello World" {
		t.Fatal("the JSON answer was not written", out)
	}
	if out = call("GET", "/ok?answer=redirect", "", 302); out["location"] != "/sign-up/name" {
		t.Fatal("the redirect answer was not written", out)
	}
	if got := seen(); got != "user-before:/ok,user-before:/ok" {
		t.Fatal("an answered request ran its after hooks", got)
	}
	if out = call("GET", "/ok", "", 200); out["ok"] != true || seen() != "user-before:/ok,user-after:ok" {
		t.Fatal("an unanswered request did not reach the endpoint", out)
	}

	// Internal hook errors and panics end the request with a generic 500.
	for _, answer := range []string{"fail", "panic"} {
		if out = call("GET", "/ok?answer="+answer, "", 500); out["code"] != "INTERNAL_SERVER_ERROR" {
			t.Fatal("an internal hook failure leaked", answer, out)
		}
	}
	seen()

	// Path is the route template and Params holds its values.
	call("GET", "/reset-password/reset-token-1?callbackURL=/done", "", 302)
	if got := seen(); !strings.Contains(got, "token:reset-token-1") {
		t.Fatal("the route parameter was not passed", got)
	}

	// Social sign-in routes run the same hooks.
	call("POST", "/sign-in/social", `{"provider":"local","callbackURL":"/done"}`, 200)
	if got := seen(); got != "user-before:/sign-in/social,social:/sign-in/social::local,user-after:social:true" {
		t.Fatal("unexpected social start hooks", got)
	}
	call("GET", "/callback/local?state=missing&code=x", "", 302)
	if got := seen(); got != "user-before:/callback/:id,social:/callback/:id:local:,user-after:callback:/api/auth/error?error=state_mismatch" {
		t.Fatal("unexpected social callback hooks", got)
	}

	// Requests rejected before dispatch run no hooks.
	call("GET", "/missing", "", 404)
	call("POST", "/sign-out", "{}", 404)
	h.Set("Origin", "https://attacker.example")
	call("POST", "/sign-in/email", `{"email":"ada@example.com","password":"correct horse battery"}`, 403)
	h.Set("Origin", "https://auth.example")
	h.Set("Content-Type", "text/plain")
	call("POST", "/sign-in/email", `{}`, 415)
	h.Set("Content-Type", "application/json")
	if got := seen(); got != "" {
		t.Fatal("a rejected request ran hooks", got)
	}

	// A hook needs Run.
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := authn.New(authn.Options{Store: store, BaseURL: "https://auth.example", Secret: strings.Repeat("s", 32), Hooks: authn.EndpointHooks{Before: []authn.EndpointHook{{}}}}); err == nil {
		t.Fatal("a hook without Run was accepted")
	}
	if _, err := authn.New(authn.Options{Store: store, BaseURL: "https://auth.example", Secret: strings.Repeat("s", 32), Plugins: []authn.Plugin{{ID: "broken", Hooks: authn.EndpointHooks{After: []authn.EndpointHook{{}}}}}}); err == nil {
		t.Fatal("a plugin hook without Run was accepted")
	}
}

// The rate limit rejects a request before its hooks run.
func TestEndpointHooksSkipRateLimitedRequests(t *testing.T) {
	calls := 0
	on := true
	auth := newHTTPAuth(t, authn.Options{
		BaseURL: "https://auth.example", RateLimit: &on,
		RateLimitRules: map[string]*authn.RateLimitRule{"/ok": {Max: 1, Window: time.Minute}},
		Hooks:          authn.EndpointHooks{Before: []authn.EndpointHook{{Run: func(*authn.HookContext) error { calls++; return nil }}}},
	})
	serve(t, auth, "GET", "/api/auth/ok", "", nil, 200)
	res := serve(t, auth, "GET", "/api/auth/ok", "", nil, 429)
	_, _ = io.Copy(io.Discard, res.Body)
	if calls != 1 {
		t.Fatalf("hooks ran %d times, want 1", calls)
	}
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// Read the session a response issues, delete it, set and read signed cookies,
// and hash passwords with the instance's hasher from hooks.
func TestEndpointHookSessionsAndCookies(t *testing.T) {
	var mu sync.Mutex
	var events []string
	record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
	seen := func() string { mu.Lock(); defer mu.Unlock(); s := strings.Join(events, ","); events = nil; return s }
	off := false
	var hashed string
	auth := newHTTPAuth(t, authn.Options{
		BaseURL: "https://auth.example", RateLimit: &off,
		PasswordHash: func(_ context.Context, password string) (string, error) { return "custom:" + password, nil },
		PasswordVerify: func(_ context.Context, encoded, password string) (bool, error) {
			return encoded == "custom:"+password, nil
		},
		Hooks: authn.EndpointHooks{
			Before: []authn.EndpointHook{{Match: func(c *authn.HookContext) bool { return c.Path == "/ok" }, Run: func(c *authn.HookContext) error {
				switch c.Request.URL.Query().Get("cookie") {
				case "set":
					c.SetCookie(c.Auth.SignedCookie("theme", "dark", 3600))
				case "read":
					value, ok := c.Auth.SignedCookieValue(c.Request, "theme")
					record("theme:" + value + ":" + boolString(ok))
				}
				// Hash and verify with the instance's configured hasher.
				if c.Request.URL.Query().Get("hash") != "" {
					var err error
					if hashed, err = c.Auth.HashPassword(c.Request.Context(), "correct horse"); err != nil {
						return err
					}
					good, err := c.Auth.VerifyPasswordHash(c.Request.Context(), hashed, "correct horse")
					if err != nil {
						return err
					}
					bad, _ := c.Auth.VerifyPasswordHash(c.Request.Context(), hashed, "wrong horse")
					record("hash:" + hashed + ":" + boolString(good) + ":" + boolString(bad))
				}
				return nil
			}}},
			After: []authn.EndpointHook{
				{Run: func(c *authn.HookContext) error {
					if c.Path == "/sign-in/email" && c.Err == nil && c.Request.URL.Query().Get("deny") != "" {
						// Turn a successful sign-in into an error without issuing the session.
						c.DeleteSessionCookie()
						return &authn.APIError{Status: 403, Code: "SIGN_IN_DENIED", Message: "Sign-in is not allowed"}
					}
					return nil
				}},
				{Run: func(c *authn.HookContext) error {
					// Notify when a new user signs up.
					session, err := c.NewSession()
					if err != nil {
						return err
					}
					if session == nil {
						record(c.Path + ":none")
						return nil
					}
					record(c.Path + ":" + session.User.Name + ":" + boolString(session.Session.Token != ""))
					return nil
				}},
			},
		},
	})
	h := http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
	call := func(method, target, body string, status int) *http.Response {
		t.Helper()
		return serve(t, auth, method, "/api/auth"+target, body, h, status)
	}
	sessionCookie := auth.Cookie("session_token", "", 0).Name
	if sessionCookie != "__Secure-authn.session_token" {
		t.Fatal("unexpected session cookie name", sessionCookie)
	}
	issued := func(res *http.Response) *http.Cookie {
		for _, c := range res.Cookies() {
			if c.Name == sessionCookie {
				return c
			}
		}
		return nil
	}

	// Sign-up and sign-in issue a session that after hooks can read.
	res := call("POST", "/sign-up/email", `{"email":"ada@example.com","password":"correct horse battery","name":"Ada"}`, 200)
	if got := seen(); got != "/sign-up/email:Ada:true" || issued(res) == nil {
		t.Fatal("the new user's session was not visible", got)
	}
	call("POST", "/sign-in/email", `{"email":"ada@example.com","password":"wrong password here"}`, 401)
	res = call("POST", "/sign-in/email", `{"email":"ada@example.com","password":"correct horse battery"}`, 200)
	if got := seen(); got != "/sign-in/email:none,/sign-in/email:Ada:true" {
		t.Fatal("unexpected new sessions", got)
	}

	// Signing out issues no session.
	session := issued(res)
	h.Set("Cookie", session.Name+"="+session.Value)
	call("POST", "/sign-out", "{}", 200)
	h.Del("Cookie")
	if got := seen(); got != "/sign-out:none" {
		t.Fatal("sign-out reported a new session", got)
	}

	// An after hook that denies a sign-in deletes the session cookie it would issue.
	res = call("POST", "/sign-in/email?deny=1", `{"email":"ada@example.com","password":"correct horse battery"}`, 403)
	if c := issued(res); c == nil || c.MaxAge >= 0 || c.Value != "" {
		t.Fatal("a denied sign-in issued a session cookie", res.Header.Values("Set-Cookie"))
	}
	if got := seen(); got != "/sign-in/email:none" {
		t.Fatal("a deleted session was still reported", got)
	}

	// A hook sets a signed cookie and reads it back; a tampered value is rejected.
	res = call("GET", "/ok?cookie=set", "", 200)
	var theme *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "__Secure-authn.theme" {
			theme = c
		}
	}
	if theme == nil || !theme.HttpOnly || !theme.Secure || theme.Path != "/" || theme.MaxAge != 3600 {
		t.Fatal("the signed cookie lacks the instance attributes", res.Header.Values("Set-Cookie"))
	}
	h.Set("Cookie", theme.Name+"="+theme.Value)
	call("GET", "/ok?cookie=read", "", 200)
	h.Set("Cookie", theme.Name+"="+strings.Replace(theme.Value, "dark", "lite", 1))
	call("GET", "/ok?cookie=read", "", 200)
	h.Del("Cookie")
	if got := seen(); got != "/ok:none,theme:dark:true,/ok:none,theme::false,/ok:none" {
		t.Fatal("unexpected signed cookie reads", got)
	}

	// Hooks hash and verify passwords with the configured hasher.
	call("GET", "/ok?hash=1", "", 200)
	if got := seen(); got != "hash:custom:correct horse:true:false,/ok:none" || hashed != "custom:correct horse" {
		t.Fatal("the instance hasher was not used", got)
	}
}
