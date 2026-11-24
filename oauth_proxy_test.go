package plainauth

import (
	"errors"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth/internal/httporigin"
)

func TestOAuthProxyConfiguration(t *testing.T) {
	t.Setenv("AUTH_URL", "https://registered.test/auth")
	t.Setenv("VERCEL_URL", "review.vendor.test")
	p, err := NewOAuthProxy(OAuthProxyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	o := p.oauthProxy
	if o.ProductionURL != "https://registered.test" || o.MaxAge != time.Minute {
		t.Fatal("incorrect proxy defaults")
	}
	a := Auth{opts: Options{BaseURL: "https://app.test"}, oauthProxy: o}
	r := httptest.NewRequest("GET", "https://unlisted.test/auth", nil)
	if a.proxyCurrentOrigin(r) != "https://review.vendor.test" {
		t.Fatal("untrusted request host displaced configured vendor origin")
	}
	r.Host = "app.test"
	if a.proxyCurrentOrigin(r) != "https://app.test" {
		t.Fatal("configured origin was not selected")
	}
	keys := []VersionedSecret{{Version: 17, Value: strings.Repeat("k", 32)}}
	explicit, err := NewOAuthProxy(OAuthProxyOptions{ProductionURL: "https://PROD.test:443/", CurrentURL: "https://preview.test/path", Secrets: keys})
	if err != nil {
		t.Fatal(err)
	}
	keys[0].Value = "mutated"
	a.oauthProxy = explicit.oauthProxy
	if a.proxyCurrentOrigin(r) != "https://preview.test" || a.oauthProxy.ProductionURL != "https://prod.test" || a.oauthProxy.Secrets[0].Value == keys[0].Value {
		t.Fatal("explicit origins and key ring should be frozen at setup")
	}
	for _, invalid := range []OAuthProxyOptions{
		{ProductionURL: "http://production.example"}, {CurrentURL: "https://user@example.test"}, {MaxAge: -time.Second},
		{Secret: "short"}, {Secrets: []VersionedSecret{}}, {Secret: strings.Repeat("x", 32), Secrets: keys},
		{Secrets: []VersionedSecret{{0, strings.Repeat("k", 32)}, {0, strings.Repeat("j", 32)}}},
	} {
		if _, err := NewOAuthProxy(invalid); err == nil {
			t.Fatalf("invalid proxy configuration accepted")
		}
	}
}

func TestOAuthProxyProfileLifetimeAndKeys(t *testing.T) {
	const preview = "https://preview.example.test"
	const prod = "https://login.example.test"
	now := time.Date(2026, 1, 2, 14, 0, 0, 0, time.UTC)
	old := VersionedSecret{4, strings.Repeat("o", 32)}
	current := VersionedSecret{5, strings.Repeat("n", 32)}
	a := Auth{opts: Options{BaseURL: preview, BasePath: "/auth"}, now: func() time.Time { return now }, oauthProxy: &OAuthProxyOptions{CurrentURL: preview, ProductionURL: prod, MaxAge: 6 * time.Second, Secrets: []VersionedSecret{old}}}
	result := oauthProxyResult{State: "local-state", Provider: "work", Preview: preview, Production: prod, Callback: "/done", BasePath: "/auth", IssuedAt: now}
	evaluate := func(record string, want string) {
		t.Helper()
		q := url.Values{"callbackURL": {"/done"}, "profile": {record}}
		r := httptest.NewRequest("GET", preview+"/auth/callback/work/oauth-proxy?"+q.Encode(), nil)
		_, err := a.completeProxyCallback(httptest.NewRecorder(), r, "work")
		var failure proxyBrowserError
		if errors.As(err, &failure) && string(failure) == want {
			return
		}
		var api *APIError
		if !errors.As(err, &api) || api.Code != want {
			t.Fatalf("got %v; want %s", err, want)
		}
	}
	sign := func(purpose string) string {
		t.Helper()
		value, err := a.sealProxy(purpose, result)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	prior := sign(proxyProfilePurpose)
	a.oauthProxy.Secrets = []VersionedSecret{current, old}
	// An authenticated profile advances to provider lookup, without issuing a session.
	evaluate(prior, "PROVIDER_NOT_FOUND")
	for _, delta := range []time.Duration{-6 * time.Second, 10 * time.Second} {
		result.IssuedAt = now.Add(delta)
		evaluate(sign(proxyProfilePurpose), "PROVIDER_NOT_FOUND")
	}
	for _, delta := range []time.Duration{-6*time.Second - time.Nanosecond, 10*time.Second + time.Nanosecond} {
		result.IssuedAt = now.Add(delta)
		evaluate(sign(proxyProfilePurpose), "payload_expired")
	}
	result.IssuedAt = now
	evaluate(sign(proxyStatePurpose), "invalid_profile")
	a.oauthProxy.Secrets = []VersionedSecret{current}
	evaluate(prior, "invalid_profile")
}

func TestOAuthProxyHostingOrigins(t *testing.T) {
	vendors := []string{"VERCEL_URL", "NETLIFY_URL", "RENDER_URL", "AWS_LAMBDA_FUNCTION_NAME", "GOOGLE_CLOUD_FUNCTION_NAME", "AZURE_FUNCTION_NAME"}
	for _, env := range vendors {
		t.Setenv(env, "")
	}
	t.Setenv("AUTH_URL", "")
	base := "https://login.example.test"
	for _, env := range append(vendors, "") {
		t.Run(env+"-origin", func(t *testing.T) {
			want := base
			if env != "" {
				want = "https://review.example.test"
				value := want
				if env == "VERCEL_URL" {
					value = "review.example.test"
				}
				t.Setenv(env, value)
			}
			p, err := NewOAuthProxy(OAuthProxyOptions{})
			if err != nil {
				t.Fatal(err)
			}
			a := Auth{opts: Options{BaseURL: base}, oauthProxy: p.oauthProxy}
			req := httptest.NewRequest("GET", "https://unlisted.example.test/", nil)
			if got := a.proxyCurrentOrigin(req); got != want {
				t.Errorf("current origin %q, want %q", got, want)
			}
		})
	}
}

func TestOAuthProxyProductionTrust(t *testing.T) {
	const production = "https://login.example.test"
	const preview = "https://review.example.test"
	now := time.Now().UTC()
	plugin, err := NewOAuthProxy(OAuthProxyOptions{ProductionURL: production, Secret: strings.Repeat("k", 32)})
	if err != nil {
		t.Fatal(err)
	}
	a := Auth{opts: Options{BaseURL: production, BasePath: "/auth"}, oauthProxy: plugin.oauthProxy, now: func() time.Time { return now }}
	rules, err := httporigin.Compile("TrustedOrigins", []string{preview})
	if err != nil {
		t.Fatal(err)
	}
	a.trustedOrigins = append(a.trustedOrigins, rules...)
	grant := oauthProxyState{State: "browser-state", Provider: "work", ClientID: "client", Preview: preview, Production: production, Callback: "/done", Verifier: "verifier", Nonce: "nonce", BasePath: "/auth", ExpiresAt: now.Add(time.Minute)}
	var provider OAuthProvider
	provider.Config.ClientID = "client"
	check := func(host string, state oauthProxyState, accepted bool) {
		t.Helper()
		sealed, err := a.sealProxy(proxyStatePurpose, state)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", host+"/auth/callback/work?error=access_denied&state="+url.QueryEscape(sealed), nil)
		w := httptest.NewRecorder()
		result, err := a.exchangeProxyCallback(w, r, "work", provider)
		target, _ := result.(Redirect)
		if accepted {
			if err != nil || !strings.HasPrefix(string(target), preview+"/auth/") {
				t.Fatal("registered callback rejected a valid preview")
			}
		} else if want := a.ErrorPageURL() + "?error=state_mismatch"; err != nil || string(target) != want {
			// A state production cannot verify goes to its own error page.
			t.Fatalf("invalid grant or request host went to %q, %v", target, err)
		}
	}
	check(production, grant, true)
	check("https://other.example.test", grant, false)
	for _, change := range []func(*oauthProxyState){
		func(g *oauthProxyState) { g.Preview = "https://other.example.test" },
		func(g *oauthProxyState) { g.Production = preview },
		func(g *oauthProxyState) { g.BasePath = "/different" },
		func(g *oauthProxyState) { g.ClientID = "different" },
		func(g *oauthProxyState) { g.Provider = "different" },
		func(g *oauthProxyState) { g.ExpiresAt = now },
	} {
		bad := grant
		change(&bad)
		check(production, bad, false)
	}
}

// With DynamicBaseURL the proxy's current origin is the allowed host a
// request reached through a trusted proxy, and a request that fell back is
// never taken for the fallback's own origin.
func TestOAuthProxyOriginWithDynamicBaseURL(t *testing.T) {
	a, err := New(Options{Store: &refreshFixture{}, Secret: strings.Repeat("s", 32), ClientIP: ClientIPOptions{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
		DynamicBaseURL: &DynamicBaseURLOptions{AllowedHosts: []string{"*.preview.example"}, Fallback: "https://auth.example", TrustedProxyHeaders: true}})
	if err != nil {
		t.Fatal(err)
	}
	origin := func(host, forwarded string) string {
		t.Helper()
		r := httptest.NewRequest("GET", "http://"+host+"/api/auth/ok", nil)
		r.RemoteAddr = "192.0.2.10:4000"
		if forwarded != "" {
			r.Header.Set("X-Forwarded-Host", forwarded)
		}
		scoped, err := a.withRequestScope(r)
		if err != nil {
			t.Fatal(err)
		}
		return a.proxyRequestOrigin(scoped)
	}
	if got := origin("internal.cluster", "pr-1.preview.example"); got != "https://pr-1.preview.example" {
		t.Fatal("a forwarded preview host gave", got)
	}
	if got := origin("auth.example", "www.example"); got == "https://auth.example" {
		t.Fatal("a request that fell back took the fallback's origin")
	}
}
