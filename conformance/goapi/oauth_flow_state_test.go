package goapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

// OAuthStateFrom hands a browser OAuth flow's state to the start's after
// hooks and, during the callback, to the provider's callbacks,
// ValidateUserInfo, user and session create hooks and after hooks on
// /callback/:id, under both state strategies; before hooks on the callback
// see none. The state leaves out the PKCE verifier and nonce. Values a before
// hook keeps with AddOAuthServerContext come back in ServerContext, and the
// browser cannot set them.
func TestOAuthFlowState(t *testing.T) {
	for _, strategy := range []auth.OAuthStateStrategy{auth.OAuthStateDatabase, auth.OAuthStateCookie} {
		t.Run(string(strategy), func(t *testing.T) {
			provider := singleUseProvider(t)
			store, err := sqlite.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			var mu sync.Mutex
			seen := map[string]*auth.OAuthState{}
			var secrets []string
			record := func(where string, ctx context.Context) {
				mu.Lock()
				defer mu.Unlock()
				if state, ok := auth.OAuthStateFrom(ctx); ok {
					seen[where] = &state
				} else {
					seen[where] = nil
				}
			}
			views := func() map[string]*auth.OAuthState {
				mu.Lock()
				defer mu.Unlock()
				out := seen
				seen = map[string]*auth.OAuthState{}
				return out
			}
			social := func(name string) auth.OAuthProvider {
				p := auth.OAuthProvider{Config: oauth2.Config{ClientID: "client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{AuthURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token"}}}
				p.ExchangeCode = func(ctx context.Context, cfg oauth2.Config, code, verifier string, _ url.Values) (*oauth2.Token, error) {
					record("code exchange", ctx)
					mu.Lock()
					secrets = append(secrets, verifier)
					mu.Unlock()
					return cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
				}
				p.Resolve = func(ctx context.Context, _ *oauth2.Token, nonce string) (auth.OAuthProfile, error) {
					record("provider", ctx)
					mu.Lock()
					secrets = append(secrets, nonce)
					mu.Unlock()
					return auth.OAuthProfile{Subject: name + "-subject", Email: "social@example.org", EmailVerified: true, Name: "Social"}, nil
				}
				return p
			}
			starts := func(c *auth.HookContext) bool {
				return c.Path == "/sign-in/social" || c.Path == "/link-social" || c.Path == "/oauth-popup/start"
			}
			var addContext atomic.Bool
			addContext.Store(true)
			app := httptest.NewUnstartedServer(nil)
			base := "http://" + app.Listener.Addr().String()
			node, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: base, RateLimit: new(bool), OAuthStateStrategy: strategy,
				SocialProviders: map[string]auth.OAuthProvider{"local": social("local"), "other": social("other")},
				Plugins:         []auth.Plugin{auth.NewOAuthPopup()},
				ValidateUserInfo: func(ctx context.Context, _ auth.UserInfoValidation) error {
					record("user check", ctx)
					return nil
				},
				DatabaseHooks: auth.DatabaseHooks{
					User: auth.ModelHooks[auth.UserRecord]{Create: auth.OperationHooks[auth.UserRecord]{Before: func(ctx context.Context, _ *auth.UserRecord, _ *auth.HookContext) error {
						record("user create", ctx)
						return nil
					}}},
					Session: auth.ModelHooks[auth.SessionRecord]{Create: auth.OperationHooks[auth.SessionRecord]{Before: func(ctx context.Context, _ *auth.SessionRecord, _ *auth.HookContext) error {
						record("session create", ctx)
						return nil
					}}},
				},
				Hooks: auth.EndpointHooks{
					Before: []auth.EndpointHook{
						{Match: starts, Run: func(c *auth.HookContext) error {
							if addContext.Load() {
								c.AddOAuthServerContext(map[string]any{"tenant": "acme", "plan": "free"})
								c.AddOAuthServerContext(map[string]any{"plan": "pro", "seats": 3})
							}
							return nil
						}},
						{Match: func(c *auth.HookContext) bool { return c.Path == "/callback/:id" }, Run: func(c *auth.HookContext) error {
							record("callback before hook", c.Request.Context())
							return nil
						}},
					},
					After: []auth.EndpointHook{
						{Match: starts, Run: func(c *auth.HookContext) error {
							record("start after hook", c.Request.Context())
							return nil
						}},
						{Match: func(c *auth.HookContext) bool { return c.Path == "/callback/:id" }, Run: func(c *auth.HookContext) error {
							record("callback after hook", c.Request.Context())
							return nil
						}},
					},
				}})
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
			// follow has the provider approve a started flow and returns the
			// callback's answer.
			follow := func(target string) *http.Response {
				t.Helper()
				approved, err := browser.Get(target)
				if err != nil {
					t.Fatal(err)
				}
				approved.Body.Close()
				done, err := browser.Get(approved.Header.Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { done.Body.Close() })
				return done
			}
			signIn := func(path, body string) string {
				t.Helper()
				res := send("POST", path, body)
				var started struct{ URL string }
				if err := json.NewDecoder(res.Body).Decode(&started); err != nil || res.StatusCode != 200 || started.URL == "" {
					t.Fatal(path, "answered", res.StatusCode, err)
				}
				return follow(started.URL).Header.Get("Location")
			}
			check := func(got map[string]*auth.OAuthState, want auth.OAuthState, places ...string) {
				t.Helper()
				for _, where := range places {
					state := got[where]
					if state == nil {
						t.Fatalf("the %s saw no flow state", where)
					}
					if !state.ExpiresAt.After(time.Now()) || state.ExpiresAt.After(time.Now().Add(10*time.Minute)) {
						t.Fatalf("the %s saw the expiry %v", where, state.ExpiresAt)
					}
					raw, _ := json.Marshal(state)
					mu.Lock()
					for _, secret := range secrets {
						if secret != "" && bytes.Contains(raw, []byte(secret)) {
							t.Fatalf("the %s saw the PKCE verifier", where)
						}
					}
					mu.Unlock()
					copied := *state
					copied.ExpiresAt = time.Time{}
					if !reflect.DeepEqual(copied, want) {
						t.Fatalf("the %s saw %+v, want %+v", where, copied, want)
					}
				}
				if state, ran := got["callback before hook"]; !ran || state != nil {
					t.Fatal("a before hook on the callback saw the flow state")
				}
			}
			server := map[string]any{"tenant": "acme", "plan": "pro", "seats": float64(3)}

			landing := signIn("/sign-in/social", `{"provider":"local","callbackURL":"/done","newUserCallbackURL":"/welcome","requestSignUp":true,"disableRedirect":true,`+
				`"serverContext":{"tenant":"evil"},"additionalData":{"invitedBy":"user-123","serverContext":{"tenant":"evil"}}}`)
			if landing != "/welcome" {
				t.Fatal("the sign-up landed at", landing)
			}
			want := auth.OAuthState{CallbackURL: "/done", NewUserURL: "/welcome", ErrorURL: base + "/api/auth/error", RequestSignUp: true,
				AdditionalData: map[string]any{"invitedBy": "user-123"}, ServerContext: server}
			got := views()
			check(got, want, "code exchange", "provider", "user check", "user create", "session create", "callback after hook")
			start := want
			start.ErrorURL = ""
			check(map[string]*auth.OAuthState{"start after hook": got["start after hook"], "callback before hook": nil}, start, "start after hook")

			res := send("GET", "/get-session", "")
			var session struct{ User struct{ ID string } }
			if err := json.NewDecoder(res.Body).Decode(&session); err != nil || session.User.ID == "" {
				t.Fatal("no session after the sign-up", err)
			}
			if landing := signIn("/link-social", `{"provider":"other","callbackURL":"/linked","errorCallbackURL":"/oops","additionalData":{"source":"settings"}}`); landing != "/linked" {
				t.Fatal("the link landed at", landing)
			}
			want = auth.OAuthState{CallbackURL: "/linked", ErrorURL: "/oops", LinkUserID: session.User.ID,
				AdditionalData: map[string]any{"source": "settings"}, ServerContext: server}
			got = views()
			check(got, want, "code exchange", "provider", "user check", "callback after hook")
			check(map[string]*auth.OAuthState{"start after hook": got["start after hook"], "callback before hook": nil}, want, "start after hook")
			if _, ran := got["user create"]; ran {
				t.Fatal("a link created a user")
			}

			popup, err := browser.Get(base + "/api/auth/oauth-popup/start?" + url.Values{"provider": {"local"}, "popupOrigin": {base}, "popupNonce": {"n"}, "callbackURL": {"/popped"}}.Encode())
			if err != nil {
				t.Fatal(err)
			}
			popup.Body.Close()
			if page := follow(popup.Header.Get("Location")); page.StatusCode != 200 {
				t.Fatal("the popup callback answered", page.StatusCode)
			}
			want = auth.OAuthState{CallbackURL: "/popped", ErrorURL: base + "/api/auth/error", ServerContext: server}
			got = views()
			check(got, want, "code exchange", "provider", "user check", "session create", "callback after hook")
			start = want
			start.ErrorURL = ""
			check(map[string]*auth.OAuthState{"start after hook": got["start after hook"], "callback before hook": nil}, start, "start after hook")

			// Without a hook, a serverContext the browser sends is ignored.
			addContext.Store(false)
			if landing := signIn("/sign-in/social", `{"provider":"local","callbackURL":"/done","disableRedirect":true,"serverContext":{"tenant":"evil"}}`); landing != "/done" {
				t.Fatal("the sign-in landed at", landing)
			}
			for where, state := range views() {
				if state != nil && state.ServerContext != nil {
					t.Fatalf("the %s saw a server context the browser sent: %v", where, state.ServerContext)
				}
			}
		})
	}
}
