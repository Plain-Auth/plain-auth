package plainauth_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/plugins/lastlogin"
	"golang.org/x/net/publicsuffix"
)

func TestSharedCookieLoginAndLogoutAcrossHosts(t *testing.T) {
	const issuer = "https://auth.example.com"
	const sibling = "https://app.example.com"
	store := memory.New()
	opts := plainauth.Options{Store: store, BaseURL: issuer, Secret: strings.Repeat("x", 32), EmailAndPassword: true, Plugins: []plainauth.Plugin{lastlogin.New(lastlogin.Options{})}}
	create := func() *plainauth.Auth {
		t.Helper()
		a, err := plainauth.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		t.Fatal(err)
	}
	do := func(a *plainauth.Auth, origin, method, path, body string, status int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, origin+"/api/auth/"+path, strings.NewReader(body))
		if method == "POST" {
			req.Header.Set("Origin", origin)
			req.Header.Set("Content-Type", "application/json")
		}
		for _, c := range jar.Cookies(req.URL) {
			req.AddCookie(c)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, req)
		if w.Code != status {
			t.Fatalf("%s: status %d: %s", path, w.Code, w.Body.String())
		}
		jar.SetCookies(req.URL, w.Result().Cookies())
		return w
	}
	cookies := func(origin, suffix string) []*http.Cookie {
		t.Helper()
		u, err := url.Parse(origin)
		if err != nil {
			t.Fatal(err)
		}
		var records []*http.Cookie
		for _, c := range jar.Cookies(u) {
			if strings.HasSuffix(c.Name, "."+suffix) {
				records = append(records, c)
			}
		}
		return records
	}
	const credentials = `{"email":"user@example.com","name":"User","password":"fixture-passphrase","rememberMe":false}`
	legacy := create()
	do(legacy, issuer, "POST", "sign-up/email", credentials, 200)
	if len(cookies(issuer, "session_token")) != 1 || len(cookies(sibling, "session_token")) != 0 {
		t.Fatal("unexpected host-only session scope")
	}

	opts.CrossSubDomainCookies = &plainauth.CrossSubDomainCookiesOptions{Domain: ".example.com"}
	shared := create()
	do(shared, issuer, "POST", "sign-in/email", credentials, 200)
	if len(cookies(issuer, "session_token")) != 1 || len(cookies(sibling, "session_token")) != 1 || len(cookies(sibling, "dont_remember")) != 1 {
		t.Fatal("session scope migration failed")
	}
	for _, foreign := range []string{"https://example.org", "https://notexample.com", "http://app.example.com"} {
		if len(cookies(foreign, "session_token")) != 0 {
			t.Fatal("session escaped configured scope", foreign)
		}
	}
	if len(cookies(sibling, "last_used_login_method")) != 1 {
		t.Fatal("plugin preference was not shared")
	}
	active := do(shared, sibling, "GET", "get-session", "", 200)
	if !strings.Contains(active.Body.String(), `"email":"user@example.com"`) {
		t.Fatal("sibling session unavailable")
	}
	do(shared, sibling, "POST", "sign-out", "{}", 403)
	presented := cookies(sibling, "session_token")[0]
	do(shared, issuer, "POST", "sign-out", "{}", 200)
	for _, host := range []string{issuer, sibling} {
		if len(cookies(host, "session_token")) != 0 || len(cookies(host, "dont_remember")) != 0 {
			t.Fatal("logout left a browser credential", host)
		}
	}
	header := http.Header{"Cookie": {presented.Name + "=" + presented.Value}}
	if active, err := shared.GetSession(t.Context(), header); err != nil || active != nil {
		t.Fatal("session still active after logout", err)
	}
}
