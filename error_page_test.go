package plainauth

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthErrorPresentation(t *testing.T) {
	cleanConfigEnv(t)
	opts := Options{BaseURL: "https://app.test", Secret: strings.Repeat("a", 32), Store: &refreshFixture{}}
	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/auth/error?error=login_failed&error_description=Alice+%26+Bob", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Alice &amp; Bob") || !strings.Contains(w.Body.String(), "login_failed") {
		t.Fatal(w.Code, w.Body)
	}
	opts.ErrorRedirectURL = "/auth-problem?source=signin"
	a, err = New(opts)
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	a.ServeHTTP(w, r)
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != 302 || loc.Path != "/auth-problem" || loc.Query().Get("error") != "login_failed" || loc.Query().Get("source") != "signin" {
		t.Fatal(loc, err)
	}
}
