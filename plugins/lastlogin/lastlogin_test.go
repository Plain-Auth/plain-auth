package lastlogin_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/plugins/lastlogin"
)

func TestLastLoginCookieAndConsent(t *testing.T) {
	p := lastlogin.New(lastlogin.Options{CookieName: "app.login-method", MaxAge: 2 * time.Hour, Allow: func(r *http.Request, method string) bool { return r.Header.Get("X-Test-Consent") == "yes" }})
	a, err := auth.New(auth.Options{Store: memory.New(), Secret: strings.Repeat("s", 32), BaseURL: "https://app.example", EmailAndPassword: true, Plugins: []auth.Plugin{p}})
	if err != nil {
		t.Fatal(err)
	}
	for i, route := range []string{"/sign-up/email", "/sign-in/email"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/auth"+route, strings.NewReader(`{"email":"ada@example.test","name":"Ada","password":"test-password"}`))
		r.Header.Set("Content-Type", "application/json")
		if i == 1 {
			r.Header.Set("X-Test-Consent", "yes")
		}
		a.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		var method *http.Cookie
		for _, c := range w.Result().Cookies() {
			if c.Name == "app.login-method" {
				method = c
			}
		}
		if i == 0 && method != nil {
			t.Fatal("cookie recorded without consent")
		}
		if i == 1 && (method == nil || method.Value != "email" || method.MaxAge != 7200 || method.HttpOnly || !method.Secure) {
			t.Fatalf("incorrect method cookie: %v", method)
		}
	}
}

func TestDefaultCookieUsesHostNamespace(t *testing.T) {
	for _, tc := range []struct{ origin, prefix, name string }{
		{"http://app.example", "", "authn.last_used_login_method"},
		{"https://app.example", "staff", "__Secure-staff.last_used_login_method"},
	} {
		a, err := auth.New(auth.Options{BaseURL: tc.origin, Secret: strings.Repeat("s", 32), Store: memory.New(), EmailAndPassword: true, CookiePrefix: tc.prefix, Plugins: []auth.Plugin{lastlogin.New(lastlogin.Options{})}})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", tc.origin+"/api/auth/sign-up/email", strings.NewReader(`{"email":"user@example.test","name":"User","password":"test-password"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", tc.origin)
		res := httptest.NewRecorder()
		a.ServeHTTP(res, req)
		if res.Code != 200 {
			t.Fatal(res.Code, res.Body)
		}
		found := false
		for _, c := range res.Result().Cookies() {
			if c.Name == tc.name && c.Value == "email" && c.Secure == strings.HasPrefix(tc.origin, "https://") {
				found = true
			}
		}
		if !found {
			t.Fatal("missing namespaced login-method cookie", tc.name)
		}
	}
}

func TestReservedLoginPreferenceName(t *testing.T) {
	for _, tc := range []struct {
		name       string
		secure     bool
		wantDomain string
		want       bool
	}{
		{"__Host-preference", true, "", true},
		{"__Secure-preference", true, "example.com", true},
		{"__host-preference", false, "", false},
		{"__secure-preference", false, "", false},
	} {
		w := httptest.NewRecorder()
		p := lastlogin.New(lastlogin.Options{CookieName: tc.name})
		p.OnSessionCookie(auth.SessionCookieEvent{Request: httptest.NewRequest("POST", "/", nil), Route: "/sign-in/email", Header: w.Header(), Cookie: http.Cookie{Name: "session_token", Domain: "example.com", Path: "/", HttpOnly: true, Secure: tc.secure}})
		list := w.Result().Cookies()
		if !tc.want {
			if len(list) != 0 {
				t.Fatal("issued a reserved preference without Secure")
			}
			continue
		}
		if len(list) != 1 || list[0].Name != tc.name || list[0].HttpOnly || !list[0].Secure || list[0].Domain != tc.wantDomain || list[0].Path != "/" {
			t.Fatal("invalid preference security attributes", list)
		}
	}
}
