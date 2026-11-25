package goapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/schema"
	"golang.org/x/oauth2"
)

// DynamicBaseURL refuses configurations it cannot serve safely.
func TestDynamicBaseURLConfiguration(t *testing.T) {
	secret := strings.Repeat("s", 32)
	hosts := func(h ...string) *auth.DynamicBaseURLOptions { return &auth.DynamicBaseURLOptions{AllowedHosts: h} }
	jwt, err := auth.NewJWT(auth.JWTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	jwtStore, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"jwt"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer jwtStore.Close()
	for name, tc := range map[string]struct {
		opts auth.Options
		want string
	}{
		"both":            {auth.Options{BaseURL: "https://auth.example", DynamicBaseURL: hosts("auth.example")}, "not both"},
		"no hosts":        {auth.Options{DynamicBaseURL: hosts()}, "cannot be empty"},
		"every host":      {auth.Options{DynamicBaseURL: hosts("*")}, "must name a domain"},
		"every port":      {auth.Options{DynamicBaseURL: hosts("*:*")}, "must name a domain"},
		"path":            {auth.Options{DynamicBaseURL: hosts("app.example/auth")}, "AllowedHosts[0]"},
		"protocol":        {auth.Options{DynamicBaseURL: &auth.DynamicBaseURLOptions{AllowedHosts: []string{"app.example"}, Protocol: "ftp"}}, "Protocol"},
		"proxy headers":   {auth.Options{DynamicBaseURL: &auth.DynamicBaseURLOptions{AllowedHosts: []string{"app.example"}, TrustedProxyHeaders: true}}, "TrustedProxies"},
		"bad fallback":    {auth.Options{DynamicBaseURL: &auth.DynamicBaseURLOptions{AllowedHosts: []string{"app.example"}, Fallback: "app.example"}}, "Fallback"},
		"jwt issuer":      {auth.Options{DynamicBaseURL: hosts("app.example"), Plugins: []auth.Plugin{jwt}, Store: jwtStore}, "Issuer and Audience"},
		"implicit domain": {auth.Options{DynamicBaseURL: hosts("app.example"), CrossSubDomainCookies: &auth.CrossSubDomainCookiesOptions{}}, "set explicitly"},
		"foreign domain":  {auth.Options{DynamicBaseURL: hosts("app.example.com", "*.other.example"), CrossSubDomainCookies: &auth.CrossSubDomainCookiesOptions{Domain: "example.com"}}, "cookie domain"},
		"public suffix":   {auth.Options{DynamicBaseURL: hosts("*.vercel.app"), CrossSubDomainCookies: &auth.CrossSubDomainCookiesOptions{Domain: "vercel.app"}}, "public suffix"},
	} {
		t.Run(name, func(t *testing.T) {
			tc.opts.Secret = secret
			if tc.opts.Store == nil {
				tc.opts.Store = memory.New()
			}
			if _, err := auth.New(tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error about %q", err, tc.want)
			}
		})
	}
	// One shared domain covering every allowed host is accepted.
	if _, err := auth.New(auth.Options{Secret: secret, Store: memory.New(), DynamicBaseURL: hosts("app.example.com", "*.preview.example.com"),
		CrossSubDomainCookies: &auth.CrossSubDomainCookiesOptions{Domain: "example.com"}}); err != nil {
		t.Fatal(err)
	}
}

// Each request's allowed host chooses the origin of its emailed links,
// callbacks and origin checks; other hosts use the fallback or fail.
func TestDynamicBaseURL(t *testing.T) {
	var mu sync.Mutex
	var links []string
	send := func(_ context.Context, m auth.MailLink) error {
		mu.Lock()
		defer mu.Unlock()
		links = append(links, m.URL)
		return nil
	}
	lastLink := func() string {
		mu.Lock()
		defer mu.Unlock()
		return links[len(links)-1]
	}
	originPlugin := auth.Plugin{ID: "request-origin", Endpoints: []auth.Endpoint{{Method: "GET", Path: "/request-origin", Handler: func(c auth.EndpointContext) (any, error) {
		origin, ok := c.RequestOrigin()
		return map[string]any{"origin": origin, "dynamic": ok}, nil
	}}}}
	newNode := func(d *auth.DynamicBaseURLOptions, proxies ...netip.Prefix) *auth.Auth {
		t.Helper()
		store, err := sqlite.Open(":memory:")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		node, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: new(bool),
			DynamicBaseURL: d, ClientIP: auth.ClientIPOptions{TrustedProxies: proxies}, SendResetPassword: send, Plugins: []auth.Plugin{originPlugin},
			TrustedOrigins: []string{"https://static.example"}})
		if err != nil {
			t.Fatal(err)
		}
		return node
	}
	call := func(node http.Handler, target, body string, headers map[string]string) (*http.Response, string) {
		t.Helper()
		r := httptest.NewRequest("POST", target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		node.ServeHTTP(w, r)
		data, _ := io.ReadAll(w.Result().Body)
		return w.Result(), string(data)
	}
	reset := `{"email":"person@example.org","redirectTo":"/reset"}`
	signUp := `{"name":"Person","email":"person@example.org","password":"a dynamic test password"}`

	node := newNode(&auth.DynamicBaseURLOptions{AllowedHosts: []string{"app.example", "*.preview.example", "localhost:3000"}})
	if res, body := call(node, "http://app.example/api/auth/sign-up/email", signUp, nil); res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	for host, want := range map[string]string{
		// A public host gets https links even over plain HTTP; loopback keeps http.
		"app.example":          "https://app.example/api/auth/reset-password/",
		"pr-7.preview.example": "https://pr-7.preview.example/api/auth/reset-password/",
		"localhost:3000":       "http://localhost:3000/api/auth/reset-password/",
	} {
		res, body := call(node, "http://"+host+"/api/auth/request-password-reset", reset, nil)
		if res.StatusCode != 200 || !strings.HasPrefix(lastLink(), want) || !strings.Contains(lastLink(), "callbackURL=%2Freset") {
			t.Fatalf("%s: %d %s, link %q", host, res.StatusCode, body, lastLink())
		}
	}
	// A request on an unlisted host fails without a fallback, and says nothing about the list.
	res, body := call(node, "http://evil.example/api/auth/request-password-reset", reset, nil)
	if res.StatusCode != 500 || strings.Contains(body, "app.example") || strings.Contains(body, "evil") {
		t.Fatalf("an unlisted host answered %d %s", res.StatusCode, body)
	}
	// The request's own origin, the other allowed hosts and the static
	// origins pass the origin check; others do not.
	credentials := `{"email":"person@example.org","password":"a dynamic test password","callbackURL":"https://pr-7.preview.example/home"}`
	for origin, status := range map[string]int{"https://app.example": 200, "https://pr-7.preview.example": 200, "https://static.example": 200, "https://evil.example": 403, "http://app.example": 403} {
		if res, body := call(node, "http://app.example/api/auth/sign-in/email", credentials, map[string]string{"Origin": origin}); res.StatusCode != status {
			t.Fatalf("origin %s answered %d %s", origin, res.StatusCode, body)
		}
	}
	if res, _ := call(node, "http://app.example/api/auth/sign-in/email", credentials, nil); !strings.Contains(res.Header.Get("Set-Cookie"), "Secure") {
		t.Fatal("a public deployment set a cookie without Secure")
	}
	// A direct Go call resolves the origin from the request it acts for.
	r := httptest.NewRequest("GET", "http://pr-9.preview.example/", nil)
	ctx, err := node.RequestContext(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := node.RequestPasswordReset(ctx, "person@example.org", ""); err != nil || !strings.HasPrefix(lastLink(), "https://pr-9.preview.example/api/auth/") {
		t.Fatalf("direct reset: %v, link %q", err, lastLink())
	}
	if err := node.RequestPasswordReset(t.Context(), "person@example.org", ""); err == nil {
		t.Fatal("a direct call without a request or a fallback built a link")
	}
	if _, err := node.RequestContext(httptest.NewRequest("GET", "http://evil.example/", nil)); err == nil {
		t.Fatal("RequestContext accepted an unlisted host")
	}

	// With a fallback, unlisted hosts and direct calls use it.
	fallback := newNode(&auth.DynamicBaseURLOptions{AllowedHosts: []string{"app.example"}, Fallback: "https://auth.example/identity"})
	if fallback.PublicURL() != "https://auth.example/identity" {
		t.Fatal("public URL", fallback.PublicURL())
	}
	call(fallback, "https://app.example/identity/sign-up/email", signUp, nil)
	if res, body := call(fallback, "http://evil.example/identity/request-password-reset", reset, nil); res.StatusCode != 200 || !strings.HasPrefix(lastLink(), "https://auth.example/identity/") {
		t.Fatalf("fallback: %d %s, link %q", res.StatusCode, body, lastLink())
	}
	if err := fallback.RequestPasswordReset(t.Context(), "person@example.org", ""); err != nil || !strings.HasPrefix(lastLink(), "https://auth.example/identity/") {
		t.Fatalf("direct fallback: %v, link %q", err, lastLink())
	}
	// A null Origin stands for the request's own host only on an allowed
	// host; an unlisted host never inherits the fallback's trust.
	res, body = call(fallback, "https://app.example/identity/sign-in/email", `{"email":"person@example.org","password":"a dynamic test password"}`, nil)
	session := res.Header.Get("Set-Cookie")
	if res.StatusCode != 200 || session == "" {
		t.Fatal("fallback sign-in", res.StatusCode, body)
	}
	session, _, _ = strings.Cut(session, ";")
	sameOrigin := map[string]string{"Cookie": session, "Origin": "null", "Sec-Fetch-Site": "same-origin"}
	// Over plain HTTP the request still reached https://app.example, the
	// origin its links use.
	if res, body := call(fallback, "http://app.example/identity/update-user", `{"name":"Renamed"}`, sameOrigin); res.StatusCode != 200 {
		t.Fatal("a same-origin update on an allowed host answered", res.StatusCode, body)
	}
	if res, body := call(fallback, "https://tenant.example/identity/update-user", `{"name":"Renamed"}`, sameOrigin); res.StatusCode != 403 || !strings.Contains(body, "INVALID_ORIGIN") {
		t.Fatal("a null-Origin update on an unlisted host answered", res.StatusCode, body)
	}
	if res, body := call(fallback, "https://app.example/identity/update-user", `{"name":"Renamed"}`, map[string]string{"Cookie": session, "Origin": "https://auth.example"}); res.StatusCode != 200 {
		t.Fatal("the fallback origin was not trusted", res.StatusCode, body)
	}

	// A fixed protocol sets the scheme of every link and the Secure default;
	// a port wildcard admits any port.
	for _, tc := range []struct {
		d      *auth.DynamicBaseURLOptions
		host   string
		link   string
		secure bool
	}{
		{&auth.DynamicBaseURLOptions{AllowedHosts: []string{"localhost:3000"}, Protocol: "https"}, "localhost:3000", "https://localhost:3000/api/auth/", true},
		{&auth.DynamicBaseURLOptions{AllowedHosts: []string{"app.example"}, Protocol: "http"}, "app.example", "http://app.example/api/auth/", false},
		{&auth.DynamicBaseURLOptions{AllowedHosts: []string{"localhost:*"}}, "localhost:4321", "http://localhost:4321/api/auth/", false},
	} {
		n := newNode(tc.d)
		call(n, "http://"+tc.host+"/api/auth/sign-up/email", signUp, nil)
		res, body := call(n, "http://"+tc.host+"/api/auth/request-password-reset", reset, nil)
		if res.StatusCode != 200 || !strings.HasPrefix(lastLink(), tc.link) {
			t.Fatalf("%+v: %d %s, link %q", tc.d, res.StatusCode, body, lastLink())
		}
		res, body = call(n, "http://"+tc.host+"/api/auth/sign-in/email", `{"email":"person@example.org","password":"a dynamic test password"}`, nil)
		if res.StatusCode != 200 || res.Header.Get("Set-Cookie") == "" || strings.Contains(res.Header.Get("Set-Cookie"), "Secure") != tc.secure {
			t.Fatalf("%+v: cookie %q", tc.d, res.Header.Get("Set-Cookie"))
		}
	}

	// Forwarded headers count only from a trusted proxy, and only with
	// TrustedProxyHeaders.
	proxied := newNode(&auth.DynamicBaseURLOptions{AllowedHosts: []string{"app.example", "*.preview.example"}, TrustedProxyHeaders: true}, netip.MustParsePrefix("192.0.2.0/24"))
	call(proxied, "http://app.example/api/auth/sign-up/email", signUp, nil)
	forwarded := func(peer string, headers map[string]string) string {
		t.Helper()
		r := httptest.NewRequest("POST", "http://internal.cluster/api/auth/request-password-reset", strings.NewReader(reset))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = peer + ":4000"
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		proxied.ServeHTTP(w, r)
		if w.Code != 200 {
			return w.Result().Status
		}
		return lastLink()
	}
	if got := forwarded("192.0.2.10", map[string]string{"X-Forwarded-Host": "pr-1.preview.example", "X-Forwarded-Proto": "http"}); !strings.HasPrefix(got, "http://pr-1.preview.example/api/auth/") {
		t.Fatal("a trusted proxy's host was not used:", got)
	}
	if got := forwarded("198.51.100.10", map[string]string{"X-Forwarded-Host": "pr-1.preview.example"}); strings.Contains(got, "pr-1") || !strings.HasPrefix(got, "500") {
		t.Fatal("an untrusted peer chose the host:", got)
	}
	if got := forwarded("192.0.2.10", map[string]string{"X-Forwarded-Host": "pr-1.preview.example, evil.example"}); !strings.HasPrefix(got, "500") {
		t.Fatal("a forwarded host list was used:", got)
	}
	// Behind a proxy that rewrites Host to the fallback's, a null Origin is
	// checked against the unlisted host the proxy forwarded.
	behind := newNode(&auth.DynamicBaseURLOptions{AllowedHosts: []string{"app.example"}, Fallback: "https://auth.example", TrustedProxyHeaders: true}, netip.MustParsePrefix("192.0.2.0/24"))
	call(behind, "https://app.example/api/auth/sign-up/email", signUp, nil)
	res, _ = call(behind, "https://app.example/api/auth/sign-in/email", `{"email":"person@example.org","password":"a dynamic test password"}`, nil)
	cookie, _, _ := strings.Cut(res.Header.Get("Set-Cookie"), ";")
	for forwardedHost, status := range map[string]int{"www.example": 403, "app.example": 200} {
		r := httptest.NewRequest("POST", "https://auth.example/api/auth/update-user", strings.NewReader(`{"name":"Renamed"}`))
		r.RemoteAddr = "192.0.2.10:4000"
		for k, v := range map[string]string{"Content-Type": "application/json", "Cookie": cookie, "Origin": "null", "Sec-Fetch-Site": "same-origin", "X-Forwarded-Host": forwardedHost} {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		behind.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("a null-Origin update forwarded for %s answered %d %s", forwardedHost, w.Code, w.Body.String())
		}
	}

	// Plugins see the host a trusted proxy forwarded, not the Host header.
	r = httptest.NewRequest("GET", "http://internal.cluster/api/auth/request-origin", nil)
	r.RemoteAddr = "192.0.2.10:4000"
	r.Header.Set("X-Forwarded-Host", "pr-1.preview.example")
	w := httptest.NewRecorder()
	proxied.ServeHTTP(w, r)
	if strings.TrimSpace(w.Body.String()) != `{"dynamic":true,"origin":"https://pr-1.preview.example"}` {
		t.Fatal("RequestOrigin behind a proxy:", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	fallback.ServeHTTP(w, httptest.NewRequest("GET", "https://tenant.example/identity/request-origin", nil))
	if strings.TrimSpace(w.Body.String()) != `{"dynamic":true,"origin":"https://tenant.example"}` {
		t.Fatal("RequestOrigin on a fallback request:", w.Body.String())
	}

	// Loopback-only hosts serve plain HTTP cookies.
	local := newNode(&auth.DynamicBaseURLOptions{AllowedHosts: []string{"localhost:3000", "127.0.0.1:3000"}})
	call(local, "http://localhost:3000/api/auth/sign-up/email", signUp, nil)
	if res, body := call(local, "http://localhost:3000/api/auth/sign-in/email", `{"email":"person@example.org","password":"a dynamic test password"}`, nil); res.StatusCode != 200 || strings.Contains(res.Header.Get("Set-Cookie"), "Secure") {
		t.Fatalf("loopback sign-in: %d %s %q", res.StatusCode, body, res.Header.Get("Set-Cookie"))
	}
}

// A social sign-in sends the provider the callback on the request's own host
// and refuses a return to another allowed host.
func TestDynamicBaseURLSocialSignIn(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","expires_in":3600}`))
	}))
	defer provider.Close()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	node, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), RateLimit: new(bool),
		DynamicBaseURL: &auth.DynamicBaseURLOptions{AllowedHosts: []string{"a.example", "b.example"}},
		SocialProviders: map[string]auth.OAuthProvider{"local": {
			Config: oauth2.Config{ClientID: "client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{AuthURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token"}},
			Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) {
				return auth.OAuthProfile{Subject: "subject", Email: "social@example.org", EmailVerified: true, Name: "Social"}, nil
			},
		}}})
	if err != nil {
		t.Fatal(err)
	}
	start := func(host string) (redirectURI, state string, cookies []*http.Cookie) {
		t.Helper()
		r := httptest.NewRequest("POST", "https://"+host+"/api/auth/sign-in/social", strings.NewReader(`{"provider":"local"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		node.ServeHTTP(w, r)
		var started struct{ URL string }
		if err := json.Unmarshal(w.Body.Bytes(), &started); err != nil || started.URL == "" {
			t.Fatal(w.Code, w.Body.String())
		}
		u, _ := url.Parse(started.URL)
		return u.Query().Get("redirect_uri"), u.Query().Get("state"), w.Result().Cookies()
	}
	finish := func(host, state string, cookies []*http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://"+host+"/api/auth/callback/local?"+url.Values{"code": {"code"}, "state": {state}}.Encode(), nil)
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		node.ServeHTTP(w, r)
		return w
	}
	redirect, state, cookies := start("b.example")
	if redirect != "https://b.example/api/auth/callback/local" {
		t.Fatal("redirect_uri", redirect)
	}
	if w := finish("a.example", state, cookies); w.Code != 400 || !strings.Contains(w.Body.String(), "INVALID_CALLBACK_URL") {
		t.Fatal("a return to another host answered", w.Code, w.Body.String())
	}
	_, state, cookies = start("b.example")
	if w := finish("b.example", state, cookies); w.Code != http.StatusFound || w.Header().Get("Location") != "https://b.example" {
		t.Fatal("the return answered", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	var problem *auth.APIError
	if _, err := node.CallbackURL("/x"); !errors.As(err, &problem) && err == nil {
		t.Fatal("a relative callback resolved without a request")
	}
}

// With one shared cookie domain covering every allowed host, a session
// started on any of those hosts is set for the shared domain.
func TestDynamicBaseURLSharedCookieDomain(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	node, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: new(bool),
		DynamicBaseURL:        &auth.DynamicBaseURLOptions{AllowedHosts: []string{"app.example.com", "*.preview.example.com"}},
		CrossSubDomainCookies: &auth.CrossSubDomainCookiesOptions{Domain: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	for i, host := range []string{"app.example.com", "pr-1.preview.example.com"} {
		path, body := "/sign-in/email", `{"email":"person@example.org","password":"a dynamic test password"}`
		if i == 0 {
			path, body = "/sign-up/email", `{"name":"Person","email":"person@example.org","password":"a dynamic test password"}`
		}
		r := httptest.NewRequest("POST", "https://"+host+"/api/auth"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://"+host)
		w := httptest.NewRecorder()
		node.ServeHTTP(w, r)
		var domain string
		for _, c := range w.Result().Cookies() {
			if strings.HasSuffix(c.Name, "session_token") {
				domain = c.Domain
			}
		}
		if w.Code != 200 || domain != "example.com" {
			t.Fatalf("a session on %s answered %d with cookie domain %q: %s", host, w.Code, domain, w.Body.String())
		}
	}
}
