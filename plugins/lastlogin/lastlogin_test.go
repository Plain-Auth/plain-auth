package lastlogin_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/plugins/lastlogin"
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
	for _, tc := range []struct{ origin, prefix, session, name string }{
		{"http://app.example", "", "", "authn.last_used_login_method"},
		{"https://app.example", "staff", "", "__Secure-staff.last_used_login_method"},
		// A renamed session cookie leaves the preference in the namespace.
		{"https://app.example", "", "sid", "__Secure-authn.last_used_login_method"},
	} {
		a, err := auth.New(auth.Options{BaseURL: tc.origin, Secret: strings.Repeat("s", 32), Store: memory.New(), EmailAndPassword: true, CookiePrefix: tc.prefix, Plugins: []auth.Plugin{lastlogin.New(lastlogin.Options{})},
			Cookies: map[string]auth.CookieOptions{"session_token": {Name: tc.session}}})
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
		p.OnSessionCookie(auth.SessionCookieEvent{Request: httptest.NewRequest("POST", "/", nil), Route: "/sign-in/email", Header: w.Header(), Cookie: http.Cookie{Name: "session_token", Domain: "example.com", Path: "/api", HttpOnly: true, Secure: tc.secure}})
		list := w.Result().Cookies()
		if !tc.want {
			if len(list) != 0 {
				t.Fatal("issued a reserved preference without Secure")
			}
			continue
		}
		if len(list) != 1 || list[0].Name != tc.name || list[0].HttpOnly || !list[0].Secure || list[0].Domain != tc.wantDomain || list[0].Path != "/" {
			// The preference keeps Path=/ so every page can read and clear it.
			t.Fatal("invalid preference security attributes", list)
		}
	}
}

// With the auth API on another site than the app, the preference copies
// SameSite=None, Secure and Partitioned from the session cookie, whether they
// apply to every cookie or only to the session cookie, and keeps Path=/.
func TestPreferenceFollowsCrossSiteSessionCookie(t *testing.T) {
	const api, app = "https://api.example.test", "https://app.example.org"
	for _, tc := range []struct {
		name string
		opts auth.Options
	}{
		{"every cookie", auth.Options{DefaultCookieAttributes: auth.CookieAttributes{SameSite: http.SameSiteNoneMode, Partitioned: true}}},
		{"session cookie only", auth.Options{Cookies: map[string]auth.CookieOptions{"session_token": {Attributes: auth.CookieAttributes{SameSite: http.SameSiteNoneMode, Partitioned: true, Path: "/api"}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := tc.opts
			o.BaseURL, o.Store, o.Secret, o.EmailAndPassword = api, memory.New(), strings.Repeat("s", 32), true
			o.TrustedOrigins, o.Plugins = []string{app}, []auth.Plugin{lastlogin.New(lastlogin.Options{})}
			a, err := auth.New(o)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", api+"/api/auth/sign-up/email", strings.NewReader(`{"email":"ada@example.test","name":"Ada","password":"test-password"}`))
			r.Header.Set("Origin", app)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			var session, preference *http.Cookie
			for _, c := range w.Result().Cookies() {
				switch c.Name {
				case "__Secure-authn.session_token":
					session = c
				case "__Secure-authn.last_used_login_method":
					preference = c
				}
			}
			if w.Code != 200 || session == nil || session.SameSite != http.SameSiteNoneMode || !session.Secure || !session.Partitioned {
				t.Fatal("the session cookie is not cross-site:", w.Code, session)
			}
			if preference == nil || preference.Value != "email" || preference.SameSite != session.SameSite || preference.Secure != session.Secure || preference.Partitioned != session.Partitioned || preference.Domain != session.Domain || preference.HttpOnly || preference.Path != "/" {
				t.Fatal("the preference did not copy the cross-site session attributes", preference)
			}
		})
	}
}
