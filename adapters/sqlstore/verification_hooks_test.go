package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// Verification hooks run around a browser OAuth flow's state: create when a
// sign-in or link starts, delete when the callback spends it. A declined
// create fails the start with 500 STATE_GENERATION_ERROR; a declined spend
// refuses the callback with state_mismatch and keeps the flow, so a retry
// signs in. A replay runs no hook, a link's record names the signed-in
// user, and the cookie strategy stores no flow and runs none.
func TestVerificationHooksAroundOAuthFlows(t *testing.T) {
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
			var mu sync.Mutex
			var events []string
			decline := map[string]bool{}
			note := func(event string, rec auth.VerificationRecord) error {
				mu.Lock()
				defer mu.Unlock()
				events = append(events, event+":"+rec.Identifier+":"+rec.UserID)
				if decline[event] {
					return auth.ErrSkipWrite
				}
				return nil
			}
			drain := func() []string {
				mu.Lock()
				defer mu.Unlock()
				out := events
				events = nil
				return out
			}
			hooks := auth.DatabaseHooks{Verification: auth.ModelHooks[auth.VerificationRecord]{
				Create: auth.OperationHooks[auth.VerificationRecord]{
					Before: func(_ context.Context, r *auth.VerificationRecord, _ *auth.HookContext) error {
						return note("create-before", *r)
					},
					After: func(ctx context.Context, r auth.VerificationRecord, _ *auth.HookContext) error {
						// Hooks run outside the store's transaction, so they may use it.
						if _, err := store.FindOAuthFlow(ctx, r.ID, "another browser", time.Now()); !errors.Is(err, auth.ErrNotFound) {
							t.Error("a hook's store read answered", err)
						}
						return note("create-after", r)
					},
				},
				Delete: auth.OperationHooks[auth.VerificationRecord]{
					Before: func(_ context.Context, r *auth.VerificationRecord, _ *auth.HookContext) error {
						return note("delete-before", *r)
					},
					After: func(_ context.Context, r auth.VerificationRecord, _ *auth.HookContext) error {
						return note("delete-after", r)
					},
				},
			}}
			app := httptest.NewUnstartedServer(nil)
			base := "http://" + app.Listener.Addr().String()
			off := false
			opts := auth.Options{Store: store, BaseURL: base, Secret: strings.Repeat("s", 40), RateLimit: &off, EmailAndPassword: true, DatabaseHooks: hooks,
				SocialProviders: map[string]auth.OAuthProvider{"work": issuer.provider()}}
			server, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			app.Config.Handler = server
			app.Start()
			defer app.Close()
			browser := func() *http.Client {
				jar, _ := cookiejar.New(nil)
				return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			}
			post := func(c *http.Client, path, body string) *http.Response {
				t.Helper()
				r, _ := http.NewRequest("POST", base+"/api/auth"+path, bytes.NewReader([]byte(body)))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", base)
				res, err := c.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { res.Body.Close() })
				return res
			}
			// start begins a flow and returns the callback the provider sends
			// the browser to.
			start := func(c *http.Client, path string) string {
				t.Helper()
				res := post(c, path, `{"provider":"work","callbackURL":"/done","disableRedirect":true}`)
				var started struct{ URL string }
				if err := json.NewDecoder(res.Body).Decode(&started); err != nil || res.StatusCode != 200 {
					t.Fatal(path, "answered", res.StatusCode, err)
				}
				approved, err := c.Get(started.URL)
				if err != nil {
					t.Fatal(err)
				}
				approved.Body.Close()
				return approved.Header.Get("Location")
			}
			finish := func(c *http.Client, callback string) string {
				t.Helper()
				res, err := c.Get(callback)
				if err != nil {
					t.Fatal(err)
				}
				res.Body.Close()
				return res.Header.Get("Location")
			}
			same := func(got []string, want ...string) {
				t.Helper()
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("hooks ran as %q, want %q", got, want)
				}
			}

			// A declined create fails the start and sets no state cookie.
			decline["create-before"] = true
			res := post(browser(), "/sign-in/social", `{"provider":"work","callbackURL":"/done","disableRedirect":true}`)
			var problem struct{ Code string }
			_ = json.NewDecoder(res.Body).Decode(&problem)
			if res.StatusCode != 500 || problem.Code != "STATE_GENERATION_ERROR" {
				t.Fatal("a declined OAuth state answered", res.StatusCode, problem.Code)
			}
			for _, c := range res.Cookies() {
				if strings.HasSuffix(c.Name, "oauth_state") && c.MaxAge >= 0 {
					t.Fatal("a declined OAuth state set its cookie")
				}
			}
			same(drain(), "create-before:oauth-state:")
			decline["create-before"] = false

			// A declined spend keeps the flow, so the retry signs in.
			owner := browser()
			callback := start(owner, "/sign-in/social")
			same(drain(), "create-before:oauth-state:", "create-after:oauth-state:")
			decline["delete-before"] = true
			if got := finish(owner, callback); got != base+"/api/auth/error?error=state_mismatch" {
				t.Fatal("a declined spend answered", got)
			}
			same(drain(), "delete-before:oauth-state:")
			decline["delete-before"] = false
			if got := finish(owner, callback); got != "/done" {
				t.Fatal("the retried callback answered", got)
			}
			same(drain(), "delete-before:oauth-state:", "delete-after:oauth-state:")
			if got := finish(owner, callback); got != base+"/api/auth/error?error=state_mismatch" {
				t.Fatal("a replayed callback answered", got)
			}
			same(drain())

			// A link's flow names the signed-in user.
			user, err := store.FindAccountUser(ctx, "owner@social.test")
			if err != nil {
				t.Fatal(err)
			}
			issuer.set("second", nil)
			callback = start(owner, "/link-social")
			finish(owner, callback)
			same(drain(), "create-before:oauth-state:"+user.ID, "create-after:oauth-state:"+user.ID,
				"delete-before:oauth-state:"+user.ID, "delete-after:oauth-state:"+user.ID)

			// The cookie strategy stores no flow and runs no hook.
			opts.OAuthStateStrategy = auth.OAuthStateCookie
			sealed, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			app.Config.Handler = sealed
			issuer.set("owner", nil)
			if got := finish(owner, start(owner, "/sign-in/social")); got != "/done" {
				t.Fatal("a cookie-state sign-in answered", got)
			}
			same(drain())
		})
	}
}

// FindDeletionToken and FindOAuthFlow read a live record of its owner or
// browser without spending it, and report ErrNotFound for an expired,
// foreign or unknown one.
func TestVerificationFinders(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			store, err := Open(ctx, dialect, organizationTestDSN(t, dialect))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			now := time.Now().UTC().Truncate(time.Millisecond)
			owner := auth.User{ID: "owner", Email: "owner@finder.example", CreatedAt: now, UpdatedAt: now}
			session := auth.StoredSession{Session: auth.Session{ID: "s", UserID: owner.ID, Token: "t", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			if err := store.CreateUser(ctx, owner, "", &session); err != nil {
				t.Fatal(err)
			}
			for token, expires := range map[string]time.Time{"live": now.Add(time.Hour), "expired": now.Add(-time.Minute)} {
				if err := store.SaveDeletionToken(ctx, auth.PasswordResetToken{ID: "id-" + token, Token: token, UserID: owner.ID, CreatedAt: now.Add(-time.Hour), ExpiresAt: expires}); err != nil {
					t.Fatal(err)
				}
			}
			found, err := store.FindDeletionToken(ctx, owner.ID, "live", now)
			if err != nil || found.ID != "id-live" || found.UserID != owner.ID || !found.ExpiresAt.After(now) {
				t.Fatal("a live deletion token was found as", found, err)
			}
			for _, tc := range []struct{ user, token string }{{owner.ID, "expired"}, {"someone-else", "live"}, {owner.ID, "unknown"}} {
				if _, err := store.FindDeletionToken(ctx, tc.user, tc.token, now); !errors.Is(err, auth.ErrNotFound) {
					t.Fatal("FindDeletionToken for", tc, "answered", err)
				}
			}
			if err := store.ConsumeDeletionToken(ctx, owner.ID, "live", now); err != nil {
				t.Fatal("finding the token spent it:", err)
			}

			flow := auth.OAuthFlow{State: "state", Binding: "browser", Provider: "work", CallbackURL: "/done", ExpiresAt: now.Add(time.Minute)}
			if err := store.SaveOAuthFlow(ctx, flow, now); err != nil {
				t.Fatal(err)
			}
			got, err := store.FindOAuthFlow(ctx, "state", "browser", now)
			if err != nil || got.CallbackURL != "/done" || got.Provider != "work" {
				t.Fatal("a live flow was found as", got, err)
			}
			for _, tc := range []struct {
				state, binding string
				at             time.Time
			}{{"state", "another", now}, {"other", "browser", now}, {"state", "browser", now.Add(2 * time.Minute)}} {
				if _, err := store.FindOAuthFlow(ctx, tc.state, tc.binding, tc.at); !errors.Is(err, auth.ErrNotFound) {
					t.Fatal("FindOAuthFlow for", tc.state, tc.binding, "answered", err)
				}
			}
			if _, err := store.ConsumeOAuthFlow(ctx, "state", "browser", now); err != nil {
				t.Fatal("finding the flow spent it:", err)
			}
		})
	}
}
