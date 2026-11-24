package goapi_test

import (
	"net/http"
	"strings"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/bearer"
	"github.com/Plain-Org/plain-auth/plugins/multisession"
)

// An after hook that rejects a sign-in leaves the browser no credential for
// the new session: no session cookie, no multi-session cookie and no bearer
// token.
func TestDeleteSessionCookieRemovesEveryCredential(t *testing.T) {
	devices, err := multisession.New(multisession.Options{})
	if err != nil {
		t.Fatal(err)
	}
	off := false
	auth := newHTTPAuth(t, authn.Options{
		BaseURL: "https://auth.example", RateLimit: &off,
		Plugins: []authn.Plugin{devices, bearer.New(bearer.Options{})},
		Hooks: authn.EndpointHooks{After: []authn.EndpointHook{{
			Match: func(c *authn.HookContext) bool { return c.Path == "/sign-in/email" && c.Err == nil },
			Run: func(c *authn.HookContext) error {
				c.DeleteSessionCookie()
				return &authn.APIError{Status: 403, Code: "SIGN_IN_DENIED", Message: "Sign-in is not allowed"}
			},
		}}},
	})
	h := http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
	body := `{"email":"ada@example.com","password":"correct horse battery","name":"Ada"}`
	if res := serve(t, auth, "POST", "/api/auth/sign-up/email", body, h, 200); res.Header.Get("Set-Auth-Token") == "" {
		t.Fatal("the bearer plugin issued no token on sign-up")
	}
	res := serve(t, auth, "POST", "/api/auth/sign-in/email", body, h, 403)
	if token := res.Header.Get("Set-Auth-Token"); token != "" {
		t.Fatal("a rejected sign-in still returned a bearer token")
	}
	multi := 0
	for _, c := range res.Cookies() {
		if strings.Contains(c.Name, "session_token") && c.MaxAge >= 0 {
			t.Fatal("a rejected sign-in still issued", c.Name, res.Header.Values("Set-Cookie"))
		}
		if strings.Contains(c.Name, "_multi-") {
			multi++
		}
	}
	if multi == 0 {
		t.Fatal("the rejected session's multi-session cookie was not expired", res.Header.Values("Set-Cookie"))
	}
}
