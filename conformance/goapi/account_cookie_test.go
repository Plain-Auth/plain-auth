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
// user only, while the tokens stay in the store.
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
			_, _ = w.Write([]byte(`{"access_token":"access-` + strings.TrimPrefix(r.Form.Get("code"), "code-") + `","refresh_token":"refresh","token_type":"Bearer","expires_in":3600}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer provider.Close()
	for _, name := range []string{"on", "off", "short"} {
		enabled := name != "off"
		t.Run(name, func(t *testing.T) {
			var cache *auth.SessionCookieCacheOptions
			if name == "short" {
				cache = &auth.SessionCookieCacheOptions{MaxAge: time.Second}
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
				data, _ := io.ReadAll(res.Body)
				var out map[string]any
				_ = json.Unmarshal(data, &out)
				return res.StatusCode, out
			}
			var issued []string
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
				kept := accountCookie(ada)
				time.Sleep(1100 * time.Millisecond)
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
			status, out = call(ada, "GET", "/account-info?useAccountCookie=true", "")
			account, _ := out["account"].(map[string]any)
			if status != 200 || account["accountId"] != "subject-ada" {
				t.Fatal("account-info answered", status, out)
			}
			status, out = call(ada, "POST", "/refresh-token", `{"useAccountCookie":true}`)
			if status != 200 || out["accessToken"] != "access-2" || out["providerId"] != "local" {
				t.Fatal("refresh-token answered", status, out)
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
