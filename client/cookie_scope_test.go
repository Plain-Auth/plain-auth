package client

import (
	"net/http"
	"net/url"
	"testing"
)

func TestClientCookiePublicSuffixAndPreferenceScope(t *testing.T) {
	const base = "https://auth.team.github.io"
	c, err := New(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	origin, _ := url.Parse(base)
	sibling, _ := url.Parse("https://app.team.github.io")
	foreign, _ := url.Parse("https://other.github.io")
	jar := c.http.Jar
	const method = "__Secure-authn.last_used_login_method"
	jar.SetCookies(origin, []*http.Cookie{
		{Name: method, Value: "email", Path: "/", Domain: "team.github.io", Secure: true},
		{Name: "separate", Value: "session", Path: "/", Domain: "team.github.io", Secure: true},
		{Name: "outside", Value: "unset", Path: "/", Domain: "github.io", Secure: true},
	})
	if c.LastLoginMethod("") != "email" || len(jar.Cookies(sibling)) != 2 || len(jar.Cookies(foreign)) != 0 {
		t.Fatal("client jar did not isolate the tenant's domain cookies")
	}
	if err := c.ClearSharedLastLoginMethod("", "github.io"); err == nil || c.LastLoginMethod("") != "email" {
		t.Fatal("invalid preference scope changed the jar")
	}
	if err := c.ClearSharedLastLoginMethod("", ".team.github.io"); err != nil {
		t.Fatal(err)
	}
	if c.LastLoginMethod("") != "" || len(jar.Cookies(sibling)) != 1 || jar.Cookies(sibling)[0].Name != "separate" {
		t.Fatal("preference cleanup removed the wrong cookies")
	}
}
