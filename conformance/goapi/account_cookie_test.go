package goapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

// StoreAccountCookie records which provider account a browser signed in
// with, so the provider credential routes accept useAccountCookie for that
// user only, while the tokens stay in the store. A token refresh of the
// account the cookie selected renews it, and so does a session cache
// re-issued for its user; a cache re-issued for another user expires it.
func TestStoreAccountCookie(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			target, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
			target.RawQuery = url.Values{"code": {"code-" + r.URL.Query().Get("login_hint")}, "state": {r.URL.Query().Get("state")}}.Encode()
			http.Redirect(w, r, target.String(), http.StatusFound)
		case "/token":
			_ = r.ParseForm()
			w.Header().Set("Content-Type", "application/json")
			if r.Form.Get("grant_type") == "refresh_token" {
				_, _ = w.Write([]byte(`{"access_token":"access-2","refresh_token":"refresh-2","token_type":"Bearer","expires_in":3600}`))
				return
			}
			// lin's first token is about to expire, so the next read refreshes it.
			expires := "3600"
			if r.Form.Get("code") == "code-lin" {
				expires = "1"
			}
			_, _ = w.Write([]byte(`{"access_token":"access-` + strings.TrimPrefix(r.Form.Get("code"), "code-") + `","refresh_token":"refresh","token_type":"Bearer","expires_in":` + expires + `}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer provider.Close()
	for _, name := range []string{"on", "off", "short", "cached"} {
		enabled := name != "off"
		t.Run(name, func(t *testing.T) {
			var cache *auth.SessionCookieCacheOptions
			switch name {
			case "short":
				cache = &auth.SessionCookieCacheOptions{MaxAge: time.Second}
			case "cached":
				cache = &auth.SessionCookieCacheOptions{}
			}
			store, err := sqlite.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			app := httptest.NewUnstartedServer(nil)
			base := "http://" + app.Listener.Addr().String()
			node, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: base, RateLimit: new(bool), StoreAccountCookie: enabled, SessionCookieCache: cache,
				SocialProviders: map[string]auth.OAuthProvider{"local": {
					Config: oauth2.Config{ClientID: "client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{AuthURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token"}},
					Resolve: func(_ context.Context, token *oauth2.Token, _ string) (auth.OAuthProfile, error) {
						who := strings.TrimPrefix(strings.TrimSuffix(token.AccessToken, "-2"), "access-")
						return auth.OAuthProfile{Subject: "subject-" + who, Email: who + "@example.org", EmailVerified: true, Name: who}, nil
					},
				}}})
			if err != nil {
				t.Fatal(err)
			}
			app.Config.Handler = node
			app.Start()
			defer app.Close()
			appURL, _ := url.Parse(base)
			cookieName := "authn.account_data"
			var issued []string
			call := func(c *http.Client, method, path, body string) (int, map[string]any) {
				t.Helper()
				r, _ := http.NewRequest(method, base+"/api/auth"+path, bytes.NewReader([]byte(body)))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", base)
				res, err := c.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				issued = res.Header.Values("Set-Cookie")
				data, _ := io.ReadAll(res.Body)
				var out map[string]any
				_ = json.Unmarshal(data, &out)
				return res.StatusCode, out
			}
			// renewed reports whether the last response issued a fresh
			// account cookie.
			age := 300
			if name == "short" {
				age = 1
			}
			renewed := func() bool {
				for _, line := range issued {
					if c, err := http.ParseSetCookie(line); err == nil && c.Name == cookieName && c.Value != "" && c.MaxAge == age {
						return true
					}
				}
				return false
			}
			signIn := func(who string) *http.Client {
				t.Helper()
				jar, _ := cookiejar.New(nil)
				c := &http.Client{Jar: jar}
				status, started := call(c, "POST", "/sign-in/social", `{"provider":"local","callbackURL":"/home","loginHint":"`+who+`"}`)
				target, _ := started["url"].(string)
				if status != 200 || target == "" {
					t.Fatal("start", status, started)
				}
				c.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
					if r.URL.Path == "/home" {
						issued = r.Response.Header.Values("Set-Cookie")
						return http.ErrUseLastResponse
					}
					return nil
				}
				res, err := c.Get(target)
				if err != nil {
					t.Fatal(err)
				}
				res.Body.Close()
				return c
			}
			accountCookie := func(c *http.Client) *http.Cookie {
				for _, cookie := range c.Jar.Cookies(appURL) {
					if cookie.Name == cookieName {
						return cookie
					}
				}
				return nil
			}
			code := func(out map[string]any) string { s, _ := out["code"].(string); return s }

			ada := signIn("ada")
			if (accountCookie(ada) != nil) != enabled {
				t.Fatal("the account cookie was set:", accountCookie(ada))
			}
			// The cookie lasts as long as the session cookie cache, or five
			// minutes, and the server refuses it after that.
			if enabled {
				want := "Max-Age=300"
				if name == "short" {
					want = "Max-Age=1"
				}
				if line := strings.Join(issued, "\n"); !strings.Contains(line, cookieName+"=") || !strings.Contains(line, want) {
					t.Fatalf("the account cookie was issued as %s", line)
				}
			}
			if name == "short" {
				// A refresh renews the cookie's own expiry: the renewed cookie
				// outlives the one issued at sign-in.
				kept := accountCookie(ada)
				time.Sleep(700 * time.Millisecond)
				if status, out := call(ada, "POST", "/refresh-token", `{"useAccountCookie":true}`); status != 200 || !renewed() {
					t.Fatal("a refresh in the cookie's last moments answered", status, out, renewed())
				}
				time.Sleep(700 * time.Millisecond)
				if status, out := call(ada, "POST", "/get-access-token", `{"useAccountCookie":true}`); status != 200 || out["accessToken"] != "access-2" {
					t.Fatal("the renewed account cookie answered", status, out)
				}
				ada.Jar.SetCookies(appURL, []*http.Cookie{{Name: cookieName, Value: kept.Value, Path: "/"}})
				if status, out := call(ada, "POST", "/get-access-token", `{"useAccountCookie":true}`); status != 400 || code(out) != "ACCOUNT_NOT_FOUND" {
					t.Fatal("an expired account cookie answered", status, out)
				}
				return
			}
			status, out := call(ada, "POST", "/get-access-token", `{"useAccountCookie":true}`)
			if !enabled {
				if status != 400 || code(out) != "ACCOUNT_NOT_FOUND" {
					t.Fatal("a cookie selection without the option answered", status, out)
				}
				return
			}
			if status != 200 || out["accessToken"] != "access-ada" {
				t.Fatal("get-access-token answered", status, out)
			}
			if renewed() {
				t.Fatal("a read that refreshed nothing renewed the account cookie")
			}
			status, out = call(ada, "GET", "/account-info?useAccountCookie=true", "")
			account, _ := out["account"].(map[string]any)
			if status != 200 || account["accountId"] != "subject-ada" || renewed() {
				t.Fatal("account-info answered", status, out, renewed())
			}
			status, out = call(ada, "POST", "/refresh-token", `{"useAccountCookie":true}`)
			if status != 200 || out["accessToken"] != "access-2" || out["providerId"] != "local" {
				t.Fatal("refresh-token answered", status, out)
			}
			if !renewed() {
				t.Fatal("a token refresh kept the old account cookie")
			}
			// The renewed cookie still selects ada's account.
			if status, out = call(ada, "POST", "/get-access-token", `{"useAccountCookie":true}`); status != 200 || out["accessToken"] != "access-2" {
				t.Fatal("the renewed account cookie answered", status, out)
			}
			// A refresh selected by account ID leaves the cookie alone.
			if status, out = call(ada, "POST", "/refresh-token", `{"accountId":"`+account["id"].(string)+`"}`); status != 200 || renewed() {
				t.Fatal("a refresh by account ID answered", status, out, renewed())
			}
			// A read that refreshes a due token renews the cookie.
			lin := signIn("lin")
			if status, out = call(lin, "POST", "/get-access-token", `{"useAccountCookie":true}`); status != 200 || out["accessToken"] != "access-2" || !renewed() {
				t.Fatal("a refreshing read answered", status, out, renewed())
			}
			if name == "cached" {
				call(ada, "GET", "/get-session?disableCookieCache=true", "")
				if !renewed() {
					t.Fatal("the session cache was re-issued without the account cookie")
				}
			}
			if status, out = call(ada, "POST", "/get-access-token", `{"useAccountCookie":true,"accountId":"x"}`); status != 400 {
				t.Fatal("two selectors answered", status, out)
			}
			// Another user's session, an altered cookie and no session all fail.
			grace := signIn("grace")
			stolen := accountCookie(ada)
			grace.Jar.SetCookies(appURL, []*http.Cookie{{Name: cookieName, Value: stolen.Value, Path: "/"}})
			if status, out = call(grace, "POST", "/get-access-token", `{"useAccountCookie":true}`); status != 400 || code(out) != "ACCOUNT_NOT_FOUND" {
				t.Fatal("another user's account cookie answered", status, out)
			}
			// A session cache re-issued for grace expires ada's cookie; with
			// no cache the cookie is only refused.
			call(grace, "GET", "/get-session?disableCookieCache=true", "")
			if (accountCookie(grace) == nil) != (name == "cached") {
				t.Fatal("after grace's session was re-read, her jar holds", accountCookie(grace))
			}
			grace.Jar.SetCookies(appURL, []*http.Cookie{{Name: cookieName, Value: stolen.Value, Path: "/"}})
			altered := []byte(stolen.Value)
			altered[len(altered)-3] ^= 1
			ada.Jar.SetCookies(appURL, []*http.Cookie{{Name: cookieName, Value: string(altered), Path: "/"}})
			if status, out = call(ada, "POST", "/get-access-token", `{"useAccountCookie":true}`); status != 400 || code(out) != "ACCOUNT_NOT_FOUND" {
				t.Fatal("an altered account cookie answered", status, out)
			}
			ada.Jar.SetCookies(appURL, []*http.Cookie{{Name: cookieName, Value: stolen.Value, Path: "/"}})
			jar, _ := cookiejar.New(nil)
			anonymous := &http.Client{Jar: jar}
			anonymous.Jar.SetCookies(appURL, []*http.Cookie{{Name: cookieName, Value: stolen.Value, Path: "/"}})
			if status, _ = call(anonymous, "POST", "/get-access-token", `{"useAccountCookie":true}`); status != 401 {
				t.Fatal("a cookie selection without a session answered", status)
			}
			// Sign-out expires the cookie.
			call(ada, "POST", "/sign-out", `{}`)
			if accountCookie(ada) != nil {
				t.Fatal("sign-out kept the account cookie")
			}
		})
	}
	// New needs the stores the cookie selection reads.
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := auth.New(auth.Options{Store: struct{ auth.Store }{store}, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example", StoreAccountCookie: true}); err == nil {
		t.Fatal("StoreAccountCookie was accepted without account stores")
	}
}
