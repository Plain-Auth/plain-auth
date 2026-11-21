package betterauth_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	auth "github.com/nabuhadba/go-better-auth"
	"github.com/nabuhadba/go-better-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

func TestOAuthBrowserFlow(t *testing.T) {
	type grant struct{ challenge, redirect string }
	var mu sync.Mutex
	codes := map[string]grant{}
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			q := r.URL.Query()
			if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" {
				http.Error(w, "missing PKCE/nonce", 400)
				return
			}
			code := rand.Text()
			mu.Lock()
			codes[code] = grant{q.Get("code_challenge"), q.Get("redirect_uri")}
			mu.Unlock()
			target, _ := url.Parse(q.Get("redirect_uri"))
			v := target.Query()
			v.Set("code", code)
			v.Set("state", q.Get("state"))
			target.RawQuery = v.Encode()
			http.Redirect(w, r, target.String(), 302)
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", 400)
				return
			}
			code := r.Form.Get("code")
			mu.Lock()
			g, valid := codes[code]
			delete(codes, code)
			mu.Unlock()
			if !valid || g.redirect != r.Form.Get("redirect_uri") || oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != g.challenge {
				http.Error(w, "invalid grant", 400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","refresh_token":"refresh","expires_in":3600}`))
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer access" {
				w.WriteHeader(401)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Subject":"stable-subject","Email":"person@example.org","EmailVerified":true,"Name":"Person"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer provider.Close()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	app := httptest.NewUnstartedServer(nil)
	base := "http://" + app.Listener.Addr().String()
	handler, err := auth.New(auth.Options{Secret: strings.Repeat("s", 32), BaseURL: base, Store: store,
		SocialProviders: map[string]auth.OAuthProvider{"local": {
			Config: oauth2.Config{ClientID: "local-client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{AuthURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token"}},
			Resolve: func(ctx context.Context, tok *oauth2.Token, _ string) (auth.OAuthProfile, error) {
				var p auth.OAuthProfile
				res, err := oauth2.NewClient(ctx, oauth2.StaticTokenSource(tok)).Get(provider.URL + "/userinfo")
				if err != nil {
					return p, err
				}
				defer res.Body.Close()
				err = json.NewDecoder(res.Body).Decode(&p)
				return p, err
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	app.Config.Handler = handler
	app.Start()
	defer app.Close()
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start := func() (string, *http.Cookie) {
		req, _ := http.NewRequest("POST", base+"/api/auth/sign-in/social", strings.NewReader(`{"provider":"local","callbackURL":"/signed-in"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", base)
		res, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var result struct {
			URL      string
			Redirect bool
		}
		if err := json.NewDecoder(res.Body).Decode(&result); err != nil || res.StatusCode != 200 || !result.Redirect {
			t.Fatalf("start: %d %+v %v", res.StatusCode, result, err)
		}
		if got := res.Header.Get("Location"); got != result.URL {
			t.Fatalf("location %q", got)
		}
		for _, cookie := range res.Cookies() {
			if strings.HasSuffix(cookie.Name, "oauth_state") {
				return result.URL, cookie
			}
		}
		t.Fatal("missing state cookie")
		return "", nil
	}
	authURL, flowCookie := start()
	res, err := browser.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	callback := res.Header.Get("Location")
	if !strings.HasPrefix(callback, base+"/api/auth/callback/local?") {
		t.Fatalf("wrong callback %q", callback)
	}
	outsider := &http.Client{CheckRedirect: browser.CheckRedirect}
	res, err = outsider.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 400 {
		t.Fatalf("unbound callback status %d", res.StatusCode)
	}
	res, err = browser.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 302 || res.Header.Get("Location") != "/signed-in" {
		t.Fatalf("callback: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	req, _ := http.NewRequest("GET", callback, nil)
	req.AddCookie(flowCookie)
	res, err = outsider.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 400 {
		t.Fatalf("used flow status %d", res.StatusCode)
	}
	res, err = browser.Get(base + "/api/auth/get-session")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var session auth.SessionResult
	if err = json.NewDecoder(res.Body).Decode(&session); err != nil || session.User.Email != "person@example.org" || session.Session.Token == "" {
		t.Fatalf("session: %#v, %v", session, err)
	}
}
