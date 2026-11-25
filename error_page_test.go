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
	if err != nil || w.Code != 302 || loc.Path != "/auth-problem" || loc.Query().Get("error") != "login_failed" || loc.Query().Get("source") != "signin" || loc.Query().Get("error_description") != "Alice & Bob" {
		t.Fatal(loc, err)
	}
}

// The default page shows an unknown or malformed code as UNKNOWN and
// escapes the description, and in production it redirects to the site's
// root unless ErrorRedirectURL says otherwise.
func TestAuthErrorPageInput(t *testing.T) {
	cleanConfigEnv(t)
	a, err := New(Options{BaseURL: "https://app.test", Secret: strings.Repeat("a", 32), Store: &refreshFixture{}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("GET", "/api/auth/error?error=%3Cscript%3E&error_description=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil))
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "<p>UNKNOWN</p>") || strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal(w.Code, body)
	}
	t.Setenv("AUTH_ENV", "production")
	a, err = New(Options{BaseURL: "https://app.test", Secret: strings.Repeat("a", 32), Store: &refreshFixture{}})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("GET", "/api/auth/error?error=login_failed", nil))
	if loc, _ := url.Parse(w.Header().Get("Location")); w.Code != 302 || loc.Path != "/" || loc.Query().Get("error") != "login_failed" {
		t.Fatal("production answered", w.Code, w.Header().Get("Location"))
	}
}
