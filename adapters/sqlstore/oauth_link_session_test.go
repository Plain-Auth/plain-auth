package sqlstore

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"net/http/httptest"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
)

// Linking a provider account needs the session that started the link to
// still be live when the provider redirects back. A session revoked in the
// meantime fails at the link, after the code exchange, with
// unable_to_link_account at the error callback; a browser that signed out
// no longer matches the flow, which fails with state_mismatch before the
// exchange. Neither adds an account or a session, and a live session links.
func TestOAuthLinkRequiresLiveSession(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			store, err := Open(ctx, dialect, organizationTestDSN(t, dialect))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			issuer := newProfileIssuer(t)
			issuer.set("owner", nil)
			app := httptest.NewUnstartedServer(nil)
			base := "http://" + app.Listener.Addr().String()
			off := false
			server, err := auth.New(auth.Options{Store: store, BaseURL: base, Secret: strings.Repeat("s", 40), RateLimit: &off, EmailAndPassword: true,
				SocialProviders: map[string]auth.OAuthProvider{"work": issuer.provider()}})
			if err != nil {
				t.Fatal(err)
			}
			app.Config.Handler = server
			app.Start()
			defer app.Close()
			browser := func() (*client.Client, *http.Client) {
				jar, _ := cookiejar.New(nil)
				transport := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
				c, err := client.New(base, transport)
				if err != nil {
					t.Fatal(err)
				}
				return c, transport
			}
			// begin starts a link and has the provider approve it, returning
			// the callback the provider redirects to and its code.
			begin := func(c *client.Client, transport *http.Client) (*url.URL, string) {
				t.Helper()
				start, err := c.LinkSocial(ctx, client.SocialSignInRequest{Provider: "work", DisableRedirect: true, CallbackURL: "/done", ErrorCallbackURL: "/failed"})
				if err != nil {
					t.Fatal(err)
				}
				approval, err := transport.Get(start.URL)
				if err != nil {
					t.Fatal(err)
				}
				approval.Body.Close()
				callback, err := approval.Location()
				if err != nil {
					t.Fatal(err)
				}
				return callback, callback.Query().Get("code")
			}
			finish := func(transport *http.Client, callback *url.URL) *http.Response {
				t.Helper()
				res, err := transport.Get(callback.String())
				if err != nil {
					t.Fatal(err)
				}
				res.Body.Close()
				for _, c := range res.Cookies() {
					if strings.HasSuffix(c.Name, "session_token") && c.Value != "" {
						t.Fatal("a link callback issued a session cookie")
					}
				}
				return res
			}
			exchanged := func(code string) bool {
				issuer.mu.Lock()
				defer issuer.mu.Unlock()
				_, pending := issuer.codes[code]
				return !pending
			}
			providerAccounts := func(userID string) int {
				t.Helper()
				accounts, err := store.ListUserAccounts(ctx, userID)
				if err != nil {
					t.Fatal(err)
				}
				n := 0
				for _, a := range accounts {
					if a.ProviderID == "work" {
						n++
					}
				}
				return n
			}
			sessions := func(userID string) int {
				t.Helper()
				list, err := store.ListSessions(ctx, userID)
				if err != nil {
					t.Fatal(err)
				}
				return len(list)
			}

			owner, ownerHTTP := browser()
			up, err := owner.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@social.test", Password: "correct horse battery"})
			if err != nil || up.Token == nil {
				t.Fatal(err)
			}
			userID := up.User.ID
			// Revoked while the browser still holds its cookie.
			callback, code := begin(owner, ownerHTTP)
			if err := store.DeleteSession(ctx, *up.Token); err != nil {
				t.Fatal(err)
			}
			res := finish(ownerHTTP, callback)
			if to, _ := res.Location(); res.StatusCode != http.StatusFound || to.Path != "/failed" || to.Query().Get("error") != "unable_to_link_account" {
				t.Fatal("a link whose session was revoked answered", res.StatusCode, to)
			}
			if !exchanged(code) || providerAccounts(userID) != 0 || sessions(userID) != 0 {
				t.Fatal("a link whose session was revoked linked or issued a session")
			}

			// Signed out before the callback.
			out, outHTTP := browser()
			if _, err := out.SignInEmail(ctx, client.SignInRequest{Email: "owner@social.test", Password: "correct horse battery"}); err != nil {
				t.Fatal(err)
			}
			callback, code = begin(out, outHTTP)
			if err := out.SignOut(ctx); err != nil {
				t.Fatal(err)
			}
			res = finish(outHTTP, callback)
			if res.StatusCode != http.StatusFound || res.Header.Get("Location") != base+"/api/auth/error?error=state_mismatch" {
				t.Fatal("a link after sign-out answered", res.StatusCode, res.Header.Get("Location"))
			}
			if exchanged(code) || providerAccounts(userID) != 0 || sessions(userID) != 0 {
				t.Fatal("a link after sign-out exchanged the code, linked or issued a session")
			}

			// A live session links without a new session.
			live, liveHTTP := browser()
			if _, err := live.SignInEmail(ctx, client.SignInRequest{Email: "owner@social.test", Password: "correct horse battery"}); err != nil {
				t.Fatal(err)
			}
			callback, _ = begin(live, liveHTTP)
			res = finish(liveHTTP, callback)
			if to, _ := res.Location(); res.StatusCode != http.StatusFound || to.Path != "/done" || providerAccounts(userID) != 1 || sessions(userID) != 1 {
				t.Fatal("a link with a live session answered", res.StatusCode, to, providerAccounts(userID), sessions(userID))
			}
		})
	}
}
