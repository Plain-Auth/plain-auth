package plainauth

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestBetterCallCookieFixture(t *testing.T) {
	auth := &Auth{opts: Options{BaseURL: "https://auth.example", Secret: "unit-test-cookie-key-0123456789012345"}}
	const token = "t8SzxPp9zv5Wpph7jEn1ccTeeUKfYHaq"
	// Generated using signCookieValue from the reference release's better-call dependency.
	const encoded = "t8SzxPp9zv5Wpph7jEn1ccTeeUKfYHaq.Hzy%2B8onTtmBALFAHhBSuyLUQ3pnCiZJKne7FolTX%2Fv0%3D"
	if c := auth.sessionCookie(token, false); c.Value != encoded {
		t.Fatalf("Go cookie signature differs from the pinned JavaScript fixture: %s", c.Value)
	}
	h := http.Header{"Cookie": {auth.cookieName() + "=" + encoded}}
	if got := auth.cookieToken(h); got != token {
		t.Fatalf("could not read the reference cookie: %q", got)
	}
}

func TestCookiePrefixSeparatesAuthInstances(t *testing.T) {
	cleanConfigEnv(t)
	opts := Options{Store: &refreshFixture{}, Secret: strings.Repeat("s", 32), BaseURL: "https://app.example", CookiePrefix: "company"}
	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	opts.CookiePrefix = "staff"
	b, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	cookie := a.SessionCookie("user-token", true)
	req.AddCookie(cookie)
	if cookie.Name != "__Secure-company.session_token" || a.cookieToken(req.Header) != "user-token" || b.cookieToken(req.Header) != "" {
		t.Fatal("cookie namespaces mixed")
	}
	if name := a.oauthCookie("oauth_state", "example", 600).Name; name != "__Secure-company.oauth_state" {
		t.Fatal(name)
	}
}

func TestCrossDomainCookiePolicy(t *testing.T) {
	cleanConfigEnv(t)
	for _, tc := range []struct {
		host, domain, want string
	}{
		{"auth.example.com", "", "auth.example.com"},
		{"AUTH.EXAMPLE.COM:8443", ".EXAMPLE.com", "example.com"},
		{"auth.bücher.de", "bücher.de", "xn--bcher-kva.de"},
		{"auth.team.github.io", "team.github.io", "team.github.io"},
		{"auth.example.com", "ample.com", ""},
		{"notexample.com", "example.com", ""},
		{"app.example.com", "other.example.com", ""},
		{"login.co.uk", "co.uk", ""},
		{"tenant.github.io", "github.io", ""},
		{"auth.example.com", "..example.com", ""},
		{"auth.example.com", "example.com.", ""},
		{"auth.example.com", "*.example.com", ""},
		{"auth.example.com", "example.com:443", ""},
		{"auth.example.com", "https://example.com", ""},
		{"auth.example.com", " example.com", ""},
		{"auth.example.com", "example.com/path", ""},
		{"127.0.0.1:8443", "", ""},
		{"[::1]:8443", "", ""},
		{"localhost", "", ""},
	} {
		t.Run(tc.host+"/"+tc.domain, func(t *testing.T) {
			scope := &CrossSubDomainCookiesOptions{tc.domain}
			opts := Options{Store: &refreshFixture{}, Secret: strings.Repeat("x", 32), BaseURL: "https://" + tc.host, CrossSubDomainCookies: scope}
			a, err := New(opts)
			if tc.want == "" {
				if err == nil {
					t.Fatal("accepted an invalid cookie scope")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			scope.Domain = "changed.example"
			for _, c := range []*http.Cookie{a.sessionCookie("a", true), a.oauthCookie("oauth_state", "b", 60), a.factorCookie("c", 90), a.trustedDeviceCookie("u", "g", 60), a.clearSessionCookie()} {
				if c.Domain != tc.want || !c.Secure || !c.HttpOnly || c.Path != "/" || c.SameSite != http.SameSiteLaxMode || !strings.HasPrefix(c.Name, "__Secure-") {
					t.Fatal("unexpected shared cookie", c)
				}
			}
			nonce := a.oneTapCookie("nonce", 90)
			if nonce.Domain != "" || !nonce.Secure || nonce.Path != "/" || nonce.SameSite != http.SameSiteStrictMode || !strings.HasPrefix(nonce.Name, "__Host-") {
				t.Fatal("host-only nonce scope changed", nonce)
			}
		})
	}
}

func TestCookieSecurityOverridesAndReservedNames(t *testing.T) {
	cleanConfigEnv(t)
	yes, no := true, false
	for _, tc := range []struct {
		base, namespace       string
		override              *bool
		shared, valid, secure bool
		name                  string
	}{
		{"https://auth.example.com", "app", nil, false, true, true, "__Secure-app"},
		{"http://auth.example.com", "app", nil, false, true, false, "app"},
		{"http://auth.example.com", "app", &yes, true, true, true, "__Secure-app"},
		{"https://auth.example.com", "app", &no, true, true, false, "app"},
		{"https://auth.example.com", "__Secure-app", nil, true, true, true, "__Secure-app"},
		{"https://auth.example.com", "__Host-app", nil, false, true, true, "__Host-app"},
		{"https://auth.example.com", "__Host-app", nil, true, false, false, ""},
		{"https://auth.example.com", "__hOsT-app", &no, false, false, false, ""},
		{"http://auth.example.com", "__secure-app", nil, false, false, false, ""},
	} {
		opts := Options{Store: &refreshFixture{}, Secret: strings.Repeat("s", 32), BaseURL: tc.base, CookiePrefix: tc.namespace, UseSecureCookies: tc.override}
		if tc.shared {
			opts.CrossSubDomainCookies = &CrossSubDomainCookiesOptions{Domain: "example.com"}
		}
		a, err := New(opts)
		if !tc.valid {
			if err == nil {
				t.Fatal("accepted incompatible cookie prefix", tc.namespace)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		c := a.SessionCookie("credential", false)
		if c.Name != tc.name+".session_token" || c.Secure != tc.secure || (c.Domain != "") != tc.shared {
			t.Fatal("unexpected cookie security options", c)
		}
	}
}

func TestCookieScopeLogoutChunks(t *testing.T) {
	cleanConfigEnv(t)
	a, err := New(Options{Store: &refreshFixture{}, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example.com", CrossSubDomainCookies: &CrossSubDomainCookiesOptions{Domain: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://auth.example.com/api/auth/sign-out", nil)
	for _, name := range []string{"session_token", "dont_remember", "session_data.0", "session_data.1", "session_data.other"} {
		r.AddCookie(&http.Cookie{Name: a.prefixedCookieName(name), Value: "old"})
	}
	w := httptest.NewRecorder()
	a.expireSessionCookies(w, r)
	expired := make(map[string]map[string]bool)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge >= 0 || !c.Secure || !c.HttpOnly || c.Path != "/" {
			t.Fatal("invalid deletion", c)
		}
		if expired[c.Name] == nil {
			expired[c.Name] = make(map[string]bool)
		}
		expired[c.Name][c.Domain] = true
	}
	for _, name := range []string{"session_token", "dont_remember", "session_data.0", "session_data.1"} {
		if scopes := expired[a.prefixedCookieName(name)]; !scopes[""] || !scopes["example.com"] {
			t.Fatal("missing deletion scope", name, scopes)
		}
	}
	if len(expired[a.prefixedCookieName("session_data.other")]) != 0 {
		t.Fatal("unrelated cookie was cleared")
	}
}

func TestDisabledCacheScopeCleanup(t *testing.T) {
	cleanConfigEnv(t)
	a, err := New(Options{Store: &refreshFixture{}, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example.com",
		CookiePrefix: "tenant", CrossSubDomainCookies: &CrossSubDomainCookiesOptions{Domain: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/api/auth/get-session", nil)
	name := a.prefixedCookieName("session_data") + ".0"
	for _, item := range []string{name, name, "authn.session_data.0", name + "01"} {
		r.AddCookie(&http.Cookie{Name: item, Value: "old"})
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "null" {
		t.Fatal("cache cookie authenticated an anonymous request")
	}
	var scopes []string
	for _, c := range w.Result().Cookies() {
		if c.Name != name || c.Value != "" || !c.Secure || !c.HttpOnly || c.Path != "/" || c.MaxAge >= 0 {
			t.Fatal("unexpected expiration", c.Name)
		}
		scopes = append(scopes, c.Domain)
	}
	if !reflect.DeepEqual(scopes, []string{"", "example.com"}) {
		t.Fatal("cache was not cleared once on each cookie scope", scopes)
	}
}
