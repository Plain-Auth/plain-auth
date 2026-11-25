package goapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

// The additionalData object a browser sends to /sign-in/social or
// /link-social is kept with the flow and handed to its callback: to the
// provider's callbacks, ValidateUserInfo, database hooks and after hooks on
// the callback. Names the flow's own state uses are dropped, so a browser
// cannot replace the destinations, the PKCE verifier, the link target or the
// expiry. A value that is not an object, or is larger than 8 KiB, is
// refused before anything is stored.
func TestOAuthAdditionalData(t *testing.T) {
	for _, strategy := range []auth.OAuthStateStrategy{auth.OAuthStateDatabase, auth.OAuthStateCookie} {
		t.Run(string(strategy), func(t *testing.T) {
			provider := singleUseProvider(t)
			inner, err := sqlite.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer inner.Close()
			store := &countingFlows{Store: inner}
			var mu sync.Mutex
			seen := map[string]map[string]any{}
			record := func(where string, data map[string]any) {
				mu.Lock()
				defer mu.Unlock()
				seen[where] = data
			}
			views := func() map[string]map[string]any {
				mu.Lock()
				defer mu.Unlock()
				out := seen
				seen = map[string]map[string]any{}
				return out
			}
			social := func(name string) auth.OAuthProvider {
				return auth.OAuthProvider{
					Config: oauth2.Config{ClientID: "client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{AuthURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token"}},
					Resolve: func(ctx context.Context, _ *oauth2.Token, _ string) (auth.OAuthProfile, error) {
						record("provider", auth.OAuthAdditionalData(ctx))
						return auth.OAuthProfile{Subject: name + "-subject", Email: "social@example.org", EmailVerified: true, Name: "Social"}, nil
					},
				}
			}
			app := httptest.NewUnstartedServer(nil)
			base := "http://" + app.Listener.Addr().String()
			node, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: base, RateLimit: new(bool), OAuthStateStrategy: strategy,
				SocialProviders: map[string]auth.OAuthProvider{"local": social("local"), "other": social("other")},
				ValidateUserInfo: func(ctx context.Context, _ auth.UserInfoValidation) error {
					record("user check", auth.OAuthAdditionalData(ctx))
					return nil
				},
				DatabaseHooks: auth.DatabaseHooks{User: auth.ModelHooks[auth.UserRecord]{Create: auth.OperationHooks[auth.UserRecord]{
					Before: func(ctx context.Context, _ *auth.UserRecord, _ *auth.HookContext) error {
						record("database hook", auth.OAuthAdditionalData(ctx))
						return nil
					},
				}}},
				Hooks: auth.EndpointHooks{After: []auth.EndpointHook{{
					Match: func(c *auth.HookContext) bool { return c.Path == "/callback/:id" },
					Run: func(c *auth.HookContext) error {
						record("after hook", auth.OAuthAdditionalData(c.Request.Context()))
						return nil
					},
				}}}})
			if err != nil {
				t.Fatal(err)
			}
			app.Config.Handler = node
			app.Start()
			defer app.Close()
			jar, _ := cookiejar.New(nil)
			browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			send := func(method, path, body string) *http.Response {
				t.Helper()
				r, _ := http.NewRequest(method, base+"/api/auth"+path, bytes.NewReader([]byte(body)))
				if body != "" {
					r.Header.Set("Content-Type", "application/json")
				}
				r.Header.Set("Origin", base)
				res, err := browser.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { res.Body.Close() })
				return res
			}
			// signIn starts a flow with body, has the provider approve it and
			// returns where the callback sends the browser.
			signIn := func(path, body string) string {
				t.Helper()
				res := send("POST", path, body)
				var started struct{ URL string }
				if err := json.NewDecoder(res.Body).Decode(&started); err != nil || res.StatusCode != 200 || started.URL == "" {
					t.Fatal(path, "answered", res.StatusCode, err)
				}
				approved, err := browser.Get(started.URL)
				if err != nil {
					t.Fatal(err)
				}
				approved.Body.Close()
				done, err := browser.Get(approved.Header.Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				done.Body.Close()
				return done.Header.Get("Location")
			}

			// Sign-in, with every reserved name spoofed.
			spoofed := `"callbackURL":"https://evil.example","errorURL":"https://evil.example","newUserURL":"https://evil.example","codeVerifier":"guess",` +
				`"link":{"userId":"someone-else","email":"other@example.org"},"requestSignUp":false,"expiresAt":1,"serverContext":{"spoofed":true},"oauthState":"x","idTokenNonce":"x"`
			landing := signIn("/sign-in/social", `{"provider":"local","callbackURL":"/done","newUserCallbackURL":"/welcome","disableRedirect":true,`+
				`"additionalData":{"invitedBy":"user-123","count":2,`+spoofed+`}}`)
			if landing != "/welcome" {
				t.Fatal("the sign-in landed at", landing)
			}
			want := map[string]any{"invitedBy": "user-123", "count": float64(2)}
			got := views()
			for _, where := range []string{"provider", "user check", "database hook", "after hook"} {
				if !reflect.DeepEqual(got[where], want) {
					t.Fatalf("the %s saw %v, want %v", where, got[where], want)
				}
			}

			// Link, from the signed-in browser.
			if landing := signIn("/link-social", `{"provider":"other","callbackURL":"/linked","additionalData":{"source":"settings","link":{"userId":"someone-else"}}}`); landing != "/linked" {
				t.Fatal("the link landed at", landing)
			}
			if got := views(); !reflect.DeepEqual(got["after hook"], map[string]any{"source": "settings"}) || !reflect.DeepEqual(got["provider"], got["after hook"]) {
				t.Fatal("the link callback saw", got)
			}
			var accounts []struct{ ProviderID string }
			if err := json.NewDecoder(send("GET", "/list-accounts", "").Body).Decode(&accounts); err != nil || len(accounts) != 2 {
				t.Fatal("the signed-in user has accounts", accounts, err)
			}

			// A flow without additionalData has none.
			signIn("/sign-in/social", `{"provider":"local","callbackURL":"/done","disableRedirect":true}`)
			if got := views(); got["provider"] != nil || got["after hook"] != nil {
				t.Fatal("a flow without additionalData saw", got)
			}

			// A value that is not an object, or is too large, is refused
			// before a flow is stored.
			saves := store.saves.Load()
			for _, path := range []string{"/sign-in/social", "/link-social"} {
				for value, kind := range map[string]string{`"x"`: "string", `[]`: "array", `null`: "null"} {
					res := send("POST", path, `{"provider":"local","additionalData":`+value+`}`)
					var problem struct{ Code, Message string }
					_ = json.NewDecoder(res.Body).Decode(&problem)
					if res.StatusCode != 400 || problem.Code != "VALIDATION_ERROR" || problem.Message != "[body.additionalData] Invalid input: expected record, received "+kind {
						t.Fatal(path, "with additionalData", value, "answered", res.StatusCode, problem)
					}
				}
				res := send("POST", path, `{"provider":"local","additionalData":{"note":"`+strings.Repeat("x", 9000)+`"}}`)
				var problem struct{ Code, Message string }
				_ = json.NewDecoder(res.Body).Decode(&problem)
				if res.StatusCode != 400 || problem.Code != "VALIDATION_ERROR" || problem.Message != "Additional data is too large" {
					t.Fatal(path, "with large additionalData answered", res.StatusCode, problem)
				}
				for _, cookie := range res.Cookies() {
					if strings.HasSuffix(cookie.Name, "oauth_state") {
						t.Fatal("a refused start set the state cookie")
					}
				}
			}
			if store.saves.Load() != saves {
				t.Fatal("a refused start stored a flow")
			}
		})
	}
}
