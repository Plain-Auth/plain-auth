package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
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

// FindDeletionToken, FindOAuthFlow, FindMagicLink and FindOneTimeToken read
// a live record of its owner or browser without spending it, and report
// ErrNotFound for an expired, foreign, unknown or malformed one.
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
			owner := auth.User{ID: "owner", Email: "owner@finder.example", EmailVerified: true, CreatedAt: now, UpdatedAt: now}
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

			// Magic links.
			for key, expires := range map[string]time.Time{"live-link": now.Add(time.Minute), "stale-link": now.Add(-time.Minute)} {
				if err := store.SaveMagicLink(ctx, auth.MagicLinkChallenge{Key: key, Email: owner.Email, Name: "Owner", CreatedAt: now.Add(-time.Hour), ExpiresAt: expires}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.db.ExecContext(ctx, store.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`),
				"malformed", "magic-link:malformed", `{"type":"other"}`, store.date(now.Add(time.Hour)), store.date(now), store.date(now)); err != nil {
				t.Fatal(err)
			}
			link, err := store.FindMagicLink(ctx, "live-link", now)
			if err != nil || link.Key != "live-link" || link.Email != owner.Email || link.Name != "Owner" || !link.ExpiresAt.After(now) {
				t.Fatal("a live magic link was found as", link, err)
			}
			for _, key := range []string{"stale-link", "unknown", "LIVE-LINK", "malformed"} {
				if _, err := store.FindMagicLink(ctx, key, now); !errors.Is(err, auth.ErrNotFound) {
					t.Fatal("FindMagicLink for", key, "answered", err)
				}
			}
			returning := auth.StoredSession{Session: auth.Session{ID: "link-session", Token: "link-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			if _, _, err := store.CompleteMagicLink(ctx, "live-link", "unused", returning, true); err != nil {
				t.Fatal("finding the link spent it:", err)
			}

			// One-time tokens.
			if err := store.SaveOneTimeToken(ctx, "transfer", session.Session, now, now.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			userID, expires, err := store.FindOneTimeToken(ctx, "transfer", now)
			if err != nil || userID != owner.ID || !expires.After(now) {
				t.Fatal("a live one-time token was found as", userID, expires, err)
			}
			for _, tc := range []struct {
				key string
				at  time.Time
			}{{"transfer", now.Add(2 * time.Minute)}, {"unknown", now}} {
				if _, _, err := store.FindOneTimeToken(ctx, tc.key, tc.at); !errors.Is(err, auth.ErrNotFound) {
					t.Fatal("FindOneTimeToken for", tc.key, "answered", err)
				}
			}
			if _, err := store.ConsumeOneTimeToken(ctx, "transfer", now); err != nil {
				t.Fatal("finding the token spent it:", err)
			}
		})
	}
}

// Magic link and one-time token verification hooks run on SQLite,
// PostgreSQL and MySQL. Around a planned sign-in the link's delete before
// hook runs once, before the dry run and the user and session before hooks,
// and its after hook before theirs; the hooks run outside the store's
// transaction and see the stored row's ID. A skipped user or a forged denial
// keeps the link, closed sign-up spends it, and a token whose session
// expired runs its after hooks before the refusal.
func TestVerificationHooksAroundMagicLinksAndTokens(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			store, err := Open(ctx, dialect, organizationTestDSN(t, dialect))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			var mu sync.Mutex
			var events, tokens []string
			var created auth.VerificationRecord
			current := ""
			// racing turns off the checks that assume one redemption at a time.
			racing := false
			fail := map[string]error{}
			note := func(event string) error {
				mu.Lock()
				defer mu.Unlock()
				events = append(events, event)
				return fail[event]
			}
			setFail := func(event string, err error) {
				mu.Lock()
				defer mu.Unlock()
				fail[event] = err
			}
			drain := func() []string {
				mu.Lock()
				defer mu.Unlock()
				out := events
				events = nil
				return out
			}
			same := func(got []string, want ...string) {
				t.Helper()
				if len(got)+len(want) > 0 && !reflect.DeepEqual(got, want) {
					t.Fatalf("hooks ran as %q, want %q", got, want)
				}
			}
			hooks := auth.DatabaseHooks{
				Verification: auth.ModelHooks[auth.VerificationRecord]{
					Create: auth.OperationHooks[auth.VerificationRecord]{After: func(_ context.Context, r auth.VerificationRecord, _ *auth.HookContext) error {
						mu.Lock()
						created = r
						mu.Unlock()
						return note("v-create-after:" + r.Identifier)
					}},
					Delete: auth.OperationHooks[auth.VerificationRecord]{
						Before: func(ctx context.Context, r *auth.VerificationRecord, _ *auth.HookContext) error {
							// Outside the store's transaction: the link is still there.
							if r.Identifier == "magic-link" && !racing {
								if _, err := store.FindMagicLink(ctx, current, time.Now()); err != nil {
									t.Error("the link was not readable from its before hook:", err)
								}
							}
							return note("v-delete-before:" + r.Identifier)
						},
						After: func(ctx context.Context, r auth.VerificationRecord, _ *auth.HookContext) error {
							if r.Identifier == "magic-link" && !racing {
								if _, err := store.FindMagicLink(ctx, current, time.Now()); !errors.Is(err, auth.ErrNotFound) {
									t.Error("the link was still readable from its after hook:", err)
								}
							}
							return note("v-delete-after:" + r.Identifier)
						},
					},
				},
				User: auth.ModelHooks[auth.UserRecord]{Create: auth.OperationHooks[auth.UserRecord]{
					Before: func(context.Context, *auth.UserRecord, *auth.HookContext) error { return note("user-before") },
					After:  func(context.Context, auth.UserRecord, *auth.HookContext) error { return note("user-after") },
				}},
				Session: auth.ModelHooks[auth.SessionRecord]{Create: auth.OperationHooks[auth.SessionRecord]{
					Before: func(context.Context, *auth.SessionRecord, *auth.HookContext) error { return note("session-before") },
					After:  func(context.Context, auth.SessionRecord, *auth.HookContext) error { return note("session-after") },
				}},
			}
			instance := func(disableSignUp bool) *auth.Auth {
				t.Helper()
				magic, err := auth.NewMagicLink(auth.MagicLinkOptions{DisableSignUp: disableSignUp, Send: func(_ context.Context, m auth.MagicLinkMessage) error {
					mu.Lock()
					defer mu.Unlock()
					tokens = append(tokens, m.Token)
					return nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				transfers, err := auth.NewOneTimeToken(auth.OneTimeTokenOptions{})
				if err != nil {
					t.Fatal(err)
				}
				off := false
				a, err := auth.New(auth.Options{Store: store, BaseURL: "https://auth.example", Secret: strings.Repeat("s", 40), RateLimit: &off, EmailAndPassword: true,
					Plugins: []auth.Plugin{magic, transfers}, DatabaseHooks: hooks})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			open, closed := instance(false), instance(true)
			serve := func(a *auth.Auth, method, path, body, cookie string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, "https://auth.example/api/auth"+path, strings.NewReader(body))
				r.Header.Set("Origin", "https://auth.example")
				if body != "" {
					r.Header.Set("Content-Type", "application/json")
				}
				if cookie != "" {
					r.Header.Set("Cookie", cookie)
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				return w
			}
			request := func(email string) string {
				t.Helper()
				if w := serve(open, "POST", "/sign-in/magic-link", `{"email":"`+email+`"}`, ""); w.Code != 200 {
					t.Fatal("the magic link request answered", w.Code, w.Body.String())
				}
				mu.Lock()
				defer mu.Unlock()
				current = tokens[len(tokens)-1]
				return current
			}
			verify := func(a *auth.Auth, token string) string {
				return serve(a, "GET", "/magic-link/verify?"+url.Values{"token": {token}, "callbackURL": {"/done"}, "errorCallbackURL": {"/failed"}}.Encode(), "", "").Header().Get("Location")
			}
			rowID := func(identifier string) string {
				t.Helper()
				var id string
				err := store.db.QueryRowContext(ctx, store.bind(`SELECT "id" FROM "verification" WHERE "identifier"=?`), identifier).Scan(&id)
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					t.Fatal(err)
				}
				return id
			}
			const done, failed = "https://auth.example/done", "https://auth.example/failed?error="

			// A new user: the link's hooks wrap the planned sign-in's.
			token := request("new@hooks.example")
			same(drain(), "v-create-after:magic-link")
			if id := rowID("magic-link:" + token); id == "" || created.ID != id {
				t.Fatal("the hook saw ID", created.ID, "for the row", id)
			}
			if got := verify(open, token); got != done {
				t.Fatal("a new user's link answered", got)
			}
			same(drain(), "v-delete-before:magic-link", "user-before", "session-before", "v-delete-after:magic-link", "user-after", "session-after")
			// A returning user.
			token = request("new@hooks.example")
			drain()
			if got := verify(open, token); got != done {
				t.Fatal("a returning user's link answered", got)
			}
			same(drain(), "v-delete-before:magic-link", "session-before", "v-delete-after:magic-link", "session-after")

			// A skipped user keeps the link, and the retry signs in.
			token = request("skipped@hooks.example")
			drain()
			setFail("user-before", auth.ErrSkipWrite)
			if got := verify(open, token); got != failed+"failed_to_create_user" {
				t.Fatal("a skipped user answered", got)
			}
			same(drain(), "v-delete-before:magic-link", "user-before")
			setFail("user-before", nil)
			if rowID("magic-link:"+token) == "" {
				t.Fatal("a skipped user spent the link")
			}
			if got := verify(open, token); got != done {
				t.Fatal("the retried link answered", got)
			}
			drain()

			// A hook that forges the closed sign-up error keeps the link.
			token = request("forged@hooks.example")
			drain()
			setFail("user-before", auth.ErrMagicLinkSignUpDisabled)
			if got := verify(open, token); got != failed+"new_user_signup_disabled" {
				t.Fatal("a forged denial answered", got)
			}
			same(drain(), "v-delete-before:magic-link", "user-before")
			setFail("user-before", nil)
			if rowID("magic-link:"+token) == "" {
				t.Fatal("a forged denial spent the link")
			}

			// Closed sign-up spends the link and runs its after hooks.
			if got := verify(closed, token); got != failed+"new_user_signup_disabled" {
				t.Fatal("closed sign-up answered", got)
			}
			same(drain(), "v-delete-before:magic-link", "v-delete-after:magic-link")
			if rowID("magic-link:"+token) != "" {
				t.Fatal("closed sign-up kept the link")
			}

			// Concurrent redemptions of one link or token run one delete after hook.
			token = request("new@hooks.example")
			drain()
			racing = true
			var wg sync.WaitGroup
			locations := make(chan string, 6)
			for range 6 {
				wg.Go(func() { locations <- verify(open, token) })
			}
			wg.Wait()
			racing = false
			close(locations)
			signedIn := 0
			for location := range locations {
				if location == done {
					signedIn++
				}
			}
			afters := 0
			for _, e := range drain() {
				if e == "v-delete-after:magic-link" {
					afters++
				}
			}
			if signedIn != 1 || afters != 1 {
				t.Fatal("concurrent links signed in", signedIn, "times and ran", afters, "after hooks")
			}

			// One-time tokens carry their owner and the stored row's ID.
			serve(open, "POST", "/sign-up/email", `{"name":"Ada","email":"ada@hooks.example","password":"correct horse battery"}`, "")
			signIn := serve(open, "POST", "/sign-in/email", `{"email":"ada@hooks.example","password":"correct horse battery"}`, "")
			var cookie string
			for _, c := range signIn.Result().Cookies() {
				if strings.HasSuffix(c.Name, "session_token") {
					cookie = c.Name + "=" + c.Value
				}
			}
			ada, err := store.FindAccountUser(ctx, "ada@hooks.example")
			if err != nil || cookie == "" {
				t.Fatal("ada could not sign in", err)
			}
			generate := func() string {
				t.Helper()
				w := serve(open, "GET", "/one-time-token/generate", "", cookie)
				var out struct{ Token string }
				if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Token == "" {
					t.Fatal("generate answered", w.Code, w.Body.String())
				}
				return out.Token
			}
			drain()
			transfer := generate()
			same(drain(), "v-create-after:one-time-token")
			if id := rowID("one-time-token:" + transfer); id == "" || created.ID != id || created.UserID != ada.ID {
				t.Fatal("the token's record was", created, "for the row", id)
			}
			if w := serve(open, "POST", "/one-time-token/verify", `{"token":"`+transfer+`"}`, ""); w.Code != 200 {
				t.Fatal("the token answered", w.Code, w.Body.String())
			}
			same(drain(), "v-delete-before:one-time-token", "v-delete-after:one-time-token")
			// A token whose session expired is spent: its after hooks run first.
			transfer = generate()
			drain()
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "session" SET "expiresAt"=? WHERE "userId"=?`), store.date(time.Now().Add(-time.Minute)), ada.ID); err != nil {
				t.Fatal(err)
			}
			w := serve(open, "POST", "/one-time-token/verify", `{"token":"`+transfer+`"}`, "")
			if w.Code != 400 || !strings.Contains(w.Body.String(), "Session expired") {
				t.Fatal("a token of an expired session answered", w.Code, w.Body.String())
			}
			same(drain(), "v-delete-before:one-time-token", "v-delete-after:one-time-token")
		})
	}
}
