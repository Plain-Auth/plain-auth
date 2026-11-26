package goapi_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
)

// get fetches path on the app with the browser, without following redirects.
func (n *tokenAuthNode) get(t *testing.T, path string) *http.Response {
	t.Helper()
	res, err := n.browser.Get(n.base + path)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res
}

func setsCookie(res *http.Response, name string) bool {
	for _, c := range res.Cookies() {
		if strings.HasSuffix(c.Name, name) && c.MaxAge >= 0 {
			return true
		}
	}
	return false
}

// With AllowIdPInitiated, a callback that brings a code and no state starts
// a fresh authorization, with new state, nonce and PKCE, instead of
// exchanging that code; following it signs in toward BaseURL. Without the
// setting, or with an empty, unknown or missing state otherwise, the
// callback fails as usual, and a form POST without state is sent to the GET
// callback first.
func TestOAuthIdPInitiated(t *testing.T) {
	srv, received := tokenProvider(t)
	p := workProvider(srv, "secret", auth.TokenEndpointAuth{})
	p.AllowIdPInitiated = true
	n, err := newTokenAuthNode(t, p)
	if err != nil {
		t.Fatal(err)
	}
	res := n.get(t, "/api/auth/callback/work?code=idp-issued-code")
	target, err := url.Parse(res.Header.Get("Location"))
	if err != nil || res.StatusCode != http.StatusFound || target.Path != "/authorize" || !strings.HasPrefix(target.String(), srv.URL) {
		t.Fatal("the callback answered", res.StatusCode, res.Header.Get("Location"))
	}
	q := target.Query()
	if q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" ||
		q.Get("client_id") != "client" || q.Get("redirect_uri") != n.base+"/api/auth/callback/work" || q.Has("code") {
		t.Fatal("the fresh authorization is", q)
	}
	if !setsCookie(res, "oauth_state") {
		t.Fatal("the restart set no flow cookie")
	}
	approved, err := n.browser.Get(target.String())
	if err != nil {
		t.Fatal(err)
	}
	approved.Body.Close()
	done := n.get(t, strings.TrimPrefix(approved.Header.Get("Location"), n.base))
	if to := done.Header.Get("Location"); strings.TrimSuffix(to, "/") != n.base {
		t.Fatal("the sign-in landed at", to)
	}
	got := received()
	if len(got) != 1 || got[0].form.Get("code") != "c" {
		t.Fatal("the token endpoint received", got)
	}
	session, err := n.browser.Get(n.base + "/api/auth/get-session")
	if err != nil {
		t.Fatal(err)
	}
	var current struct{ User struct{ Email string } }
	_ = json.NewDecoder(session.Body).Decode(&current)
	session.Body.Close()
	if current.User.Email != "person@example.org" {
		t.Fatal("the restarted sign-in has no session")
	}

	form := url.Values{"code": {"idp-issued-code"}}
	posted, err := n.browser.PostForm(n.base+"/api/auth/callback/work", form)
	if err != nil {
		t.Fatal(err)
	}
	posted.Body.Close()
	if res := n.get(t, strings.TrimPrefix(posted.Header.Get("Location"), n.base)); !strings.HasPrefix(res.Header.Get("Location"), srv.URL+"/authorize?") {
		t.Fatal("the form POST without state went to", posted.Header.Get("Location"), "then", res.Header.Get("Location"))
	}

	for query, code := range map[string]string{"code=idp-issued-code&state=": "state_not_found", "code=idp-issued-code&state=unknown": "state_mismatch", "error=access_denied": "state_not_found"} {
		if res := n.get(t, "/api/auth/callback/work?"+query); !strings.Contains(res.Header.Get("Location"), "error="+code) {
			t.Fatal(query, "went to", res.Header.Get("Location"))
		}
	}
	p.AllowIdPInitiated = false
	n, err = newTokenAuthNode(t, p)
	if err != nil {
		t.Fatal(err)
	}
	res = n.get(t, "/api/auth/callback/work?code=idp-issued-code")
	if !strings.Contains(res.Header.Get("Location"), "error=state_not_found") || setsCookie(res, "oauth_state") {
		t.Fatal("a provider without the setting answered", res.Header.Get("Location"))
	}
	if got := received(); len(got) != 0 {
		t.Fatal("a provider-issued code was exchanged")
	}
}
