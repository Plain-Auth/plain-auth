package goapi_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// Rename individual cookies and change their attributes, and refuse
// configurations a browser would reject.
func TestCookieOptions(t *testing.T) {
	off, no := false, false
	opts := authn.Options{
		BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		DefaultCookieAttributes: authn.CookieAttributes{SameSite: http.SameSiteNoneMode, Partitioned: true},
		Cookies: map[string]authn.CookieOptions{
			"session_token": {Name: "app_session", Attributes: authn.CookieAttributes{Path: "/api"}},
			"dont_remember": {Name: "app_forget", Attributes: authn.CookieAttributes{HttpOnly: &no}},
		},
	}
	auth, err := authn.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	send := func(path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://auth.example/api/auth"+path, strings.NewReader(body))
		r.Header = http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		return w
	}
	find := func(w *httptest.ResponseRecorder, name string) *http.Cookie {
		for _, c := range w.Result().Cookies() {
			if c.Name == name {
				return c
			}
		}
		t.Fatal("missing cookie", name, w.Header().Values("Set-Cookie"))
		return nil
	}
	w := send("/sign-up/email", `{"email":"ada@example.com","password":"correct horse battery","name":"Ada","rememberMe":false}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	// The session cookie takes its custom name, keeps the __Secure- prefix and merges the attributes.
	session := find(w, "__Secure-app_session")
	if session.Path != "/api" || session.SameSite != http.SameSiteNoneMode || !session.Partitioned || !session.HttpOnly || !session.Secure {
		t.Fatal("the session cookie lacks its attributes", session)
	}
	forget := find(w, "__Secure-app_forget")
	if forget.HttpOnly || forget.Path != "/" {
		t.Fatal("the remember marker lacks its attributes", forget)
	}
	// The renamed cookie authenticates, and signing out expires it under its new name.
	r := httptest.NewRequest("GET", "https://auth.example/api/auth/get-session", nil)
	r.AddCookie(session)
	got := httptest.NewRecorder()
	auth.ServeHTTP(got, r)
	if !strings.Contains(got.Body.String(), "ada@example.com") {
		t.Fatal("the renamed session cookie did not authenticate", got.Body)
	}
	out := send("/sign-out", `{}`, session, forget)
	if c := find(out, "__Secure-app_session"); c.MaxAge >= 0 {
		t.Fatal("sign-out did not expire the renamed session cookie", c)
	}

	// Configurations a browser would reject, or that would hide a cookie from
	// the auth endpoints, are refused with a reason.
	for _, tc := range []struct {
		name, want string
		bad        func(*authn.Options)
	}{
		{"SameSite=None without Secure", "SameSite=None", func(o *authn.Options) {
			o.BaseURL, o.DefaultCookieAttributes = "http://auth.example", authn.CookieAttributes{SameSite: http.SameSiteNoneMode}
		}},
		{"Partitioned without Secure", "partitioned", func(o *authn.Options) {
			o.BaseURL, o.DefaultCookieAttributes = "http://auth.example", authn.CookieAttributes{Partitioned: true}
		}},
		{"__Host- with a domain", "__Host-", func(o *authn.Options) {
			o.Cookies = map[string]authn.CookieOptions{"session_token": {Name: "__Host-app", Attributes: authn.CookieAttributes{Domain: "auth.example"}}}
		}},
		{"__Host- with a path", "__Host-", func(o *authn.Options) {
			o.Cookies = map[string]authn.CookieOptions{"session_token": {Name: "__Host-app", Attributes: authn.CookieAttributes{Path: "/api"}}}
		}},
		{"an invalid name", "invalid", func(o *authn.Options) {
			o.Cookies = map[string]authn.CookieOptions{"session_token": {Name: "app session"}}
		}},
		{"a path that misses the auth endpoints", "covers /api/auth", func(o *authn.Options) {
			o.DefaultCookieAttributes = authn.CookieAttributes{Path: "/app"}
		}},
		{"a domain outside the base host", "domain", func(o *authn.Options) {
			o.Cookies = map[string]authn.CookieOptions{"two_factor": {Attributes: authn.CookieAttributes{Domain: "other.example"}}}
		}},
		{"two cookies with one name", "share the name", func(o *authn.Options) {
			o.Cookies = map[string]authn.CookieOptions{"dont_remember": {Name: "app_session"}, "session_token": {Name: "app_session"}}
		}},
		{"attributes that follow session_token", "session_token attributes", func(o *authn.Options) {
			o.Cookies = map[string]authn.CookieOptions{"admin_session": {Attributes: authn.CookieAttributes{Path: "/api"}}}
		}},
	} {
		next := opts
		next.Store = memory.New()
		tc.bad(&next)
		_, err := authn.New(next)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error about %q", tc.name, err, tc.want)
		}
	}
}
