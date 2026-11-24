package goapi_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// Serve paths with trailing slashes, and turn off the CSRF and redirect
// checks only when asked.
func TestRequestSwitches(t *testing.T) {
	newAuth := func(edit func(*authn.Options)) *authn.Auth {
		t.Helper()
		off := false
		opts := authn.Options{BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off}
		edit(&opts)
		a, err := authn.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	status := func(a *authn.Auth, method, path, body string, header http.Header) int {
		r := httptest.NewRequest(method, "https://auth.example/api/auth"+path, strings.NewReader(body))
		r.Header = header
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w.Code
	}
	json := http.Header{"Content-Type": {"application/json"}}

	// Trailing slashes are ignored only with SkipTrailingSlashes.
	plain := newAuth(func(*authn.Options) {})
	slashes := newAuth(func(o *authn.Options) { o.SkipTrailingSlashes = true })
	if status(plain, "GET", "/ok/", "", nil) != 404 || status(slashes, "GET", "/ok/", "", nil) != 200 || status(slashes, "GET", "/ok//", "", nil) != 200 {
		t.Fatal("trailing slashes were not handled as configured")
	}

	// A cookie-bearing request from an untrusted origin is refused unless CSRF checks are off.
	forged := http.Header{"Content-Type": {"application/json"}, "Origin": {"https://attacker.example"}, "Cookie": {"theme=dark"}}
	signIn := `{"email":"nobody@example.com","password":"correct horse battery"}`
	csrf := newAuth(func(o *authn.Options) { o.DisableCSRFCheck = true })
	if status(plain, "POST", "/sign-in/email", signIn, forged) != 403 || status(csrf, "POST", "/sign-in/email", signIn, forged) != 401 {
		t.Fatal("the CSRF check was not applied as configured")
	}

	// An untrusted callback is refused unless the origin check is off; request origins are still checked.
	open := newAuth(func(o *authn.Options) { o.DisableOriginCheck = true })
	signUp := `{"email":"ada@example.com","password":"correct horse battery","name":"Ada","callbackURL":"https://elsewhere.example/welcome"}`
	if status(plain, "POST", "/sign-up/email", signUp, json) != 403 || status(open, "POST", "/sign-up/email", signUp, json) != 200 {
		t.Fatal("the callback check was not applied as configured")
	}
	if status(open, "POST", "/sign-in/email", signIn, forged) != 403 {
		t.Fatal("turning off the callback check turned off the CSRF check")
	}
	// Control characters are refused even without the origin check.
	if status(open, "POST", "/sign-up/email", `{"email":"lin@example.com","password":"correct horse battery","name":"Lin","callbackURL":"/welcome\r\nX: y"}`, json) != 403 {
		t.Fatal("a callback with control characters was accepted")
	}
}
