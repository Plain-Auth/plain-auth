package authn

import (
	"net/http"
	"net/http/httptest"
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
