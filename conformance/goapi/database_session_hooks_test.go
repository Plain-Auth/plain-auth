package goapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// Run session update hooks around sliding refreshes and field updates, and
// session delete hooks around sign-out, revocation, expired-session cleanup,
// password changes and multi-session replacement.
func TestDatabaseSessionUpdateAndDeleteHooks(t *testing.T) {
	var mu sync.Mutex
	var events []string
	record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
	seen := func() string { mu.Lock(); defer mu.Unlock(); s := strings.Join(events, ","); events = nil; return s }
	var updateBefore func(*authn.SessionRecord) error
	var deleteBefore func(*authn.SessionRecord) error
	store := memory.New()
	multi, err := authn.NewMultiSession(authn.MultiSessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	app := httptest.NewUnstartedServer(nil)
	base := "http://" + app.Listener.Addr().String()
	every := time.Duration(0)
	off := false
	auth, err := authn.New(authn.Options{
		BaseURL: base, Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off, Logger: slog.New(slog.DiscardHandler),
		SessionUpdateAge:        &every,
		SessionAdditionalFields: map[string]authn.SessionField{"theme": {Type: authn.FieldString}, "plan": {Type: authn.FieldString, ServerOnly: true}},
		Plugins:                 []authn.Plugin{multi},
		DatabaseHooks: authn.DatabaseHooks{Session: authn.ModelHooks[authn.SessionRecord]{
			Update: authn.OperationHooks[authn.SessionRecord]{
				Before: func(_ context.Context, s *authn.SessionRecord, c *authn.HookContext) error {
					// An update hook reads the signed-in caller from the endpoint context.
					if caller, err := c.Session(); err != nil || caller == nil || caller.User.ID != s.UserID {
						return errors.New("the update hook could not read the caller's session")
					}
					record("update-before:" + c.Path)
					if updateBefore != nil {
						return updateBefore(s)
					}
					return nil
				},
				After: func(ctx context.Context, s authn.SessionRecord, c *authn.HookContext) error {
					stored, _, err := store.Session(ctx, s.Token)
					if err != nil {
						return err
					}
					theme, _ := s.Fields["theme"].(string)
					record("update-after:" + c.Path + ":" + boolString(stored.ExpiresAt.Equal(s.ExpiresAt)) + ":" + theme)
					return nil
				},
			},
			Delete: authn.OperationHooks[authn.SessionRecord]{
				Before: func(_ context.Context, s *authn.SessionRecord, c *authn.HookContext) error {
					record("delete-before:" + c.Path)
					if deleteBefore != nil {
						return deleteBefore(s)
					}
					return nil
				},
				After: func(ctx context.Context, s authn.SessionRecord, c *authn.HookContext) error {
					// The row is gone once the after hook runs.
					_, _, err := store.Session(ctx, s.Token)
					record("delete-after:" + c.Path + ":" + boolString(err != nil))
					return nil
				},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	app.Config.Handler = auth
	app.Start()
	defer app.Close()
	newBrowser := func() *http.Client {
		jar, _ := cookiejar.New(nil)
		return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	call := func(browser *http.Client, method, path, body string, status int) map[string]any {
		t.Helper()
		r, _ := http.NewRequest(method, base+"/api/auth"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", base)
		res, err := browser.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		if res.StatusCode != status {
			t.Fatalf("%s %s returned %d, want %d: %v", method, path, res.StatusCode, status, out)
		}
		return out
	}
	signIn := func(browser *http.Client) string {
		t.Helper()
		out := call(browser, "POST", "/sign-in/email", `{"email":"ada@example.com","password":"correct horse battery"}`, 200)
		return out["token"].(string)
	}
	ada := newBrowser()
	out := call(ada, "POST", "/sign-up/email", `{"email":"ada@example.com","password":"correct horse battery","name":"Ada"}`, 200)
	adaID := out["user"].(map[string]any)["id"].(string)

	// A sliding refresh runs the update hooks with the new expiry, which a hook may shorten.
	updateBefore = func(s *authn.SessionRecord) error {
		s.ExpiresAt = s.ExpiresAt.Add(-time.Hour)
		return nil
	}
	session := call(ada, "GET", "/get-session", "", 200)["session"].(map[string]any)
	expires, _ := time.Parse(time.RFC3339, session["expiresAt"].(string))
	if got := seen(); got != "update-before:/get-session,update-after:/get-session:true:" || time.Until(expires) > 7*24*time.Hour-time.Hour+time.Minute {
		t.Fatal("unexpected refresh hooks", got, expires)
	}

	// A field update runs the update hooks, which may change the fields a caller can set.
	updateBefore = func(s *authn.SessionRecord) error {
		s.Fields["theme"] = s.Fields["theme"].(string) + "-checked"
		return nil
	}
	session = call(ada, "POST", "/update-session", `{"theme":"dark"}`, 200)["session"].(map[string]any)
	if session["theme"] != "dark-checked" || seen() != "update-before:/update-session,update-after:/update-session:true:dark-checked" {
		t.Fatal("the field update hooks did not apply", session)
	}
	updateBefore = func(s *authn.SessionRecord) error { s.Fields["plan"] = "pro"; return nil }
	if out = call(ada, "POST", "/update-session", `{"theme":"light"}`, 400); out["code"] != "FIELD_NOT_ALLOWED" {
		t.Fatal("a hook set a server-only field on update", out)
	}
	// Changing anything else in a field update fails it.
	updateBefore = func(s *authn.SessionRecord) error { s.ExpiresAt = s.ExpiresAt.Add(time.Hour); return nil }
	call(ada, "POST", "/update-session", `{"theme":"light"}`, 500)
	// A declined update or refresh ends the browser session like a missing one.
	updateBefore = func(*authn.SessionRecord) error { return authn.ErrSkipWrite }
	if out = call(ada, "POST", "/update-session", `{"theme":"light"}`, 401); out["code"] != "FAILED_TO_GET_SESSION" {
		t.Fatal("a declined field update was not refused", out)
	}
	updateBefore = nil
	seen()
	token := signIn(ada)
	updateBefore = func(*authn.SessionRecord) error { return authn.ErrSkipWrite }
	call(ada, "GET", "/get-session", "", 401)
	updateBefore = nil
	if call(ada, "GET", "/get-session", "", 200) != nil {
		t.Fatal("a declined refresh kept the browser signed in")
	}
	if _, _, err := store.Session(t.Context(), token); err != nil {
		t.Fatal("a declined refresh removed the session", err)
	}
	seen()

	// Sign-out runs the delete hooks; a declined delete still signs the browser out but keeps the row.
	token = signIn(ada)
	seen()
	deleteBefore = func(*authn.SessionRecord) error { return authn.ErrSkipWrite }
	call(ada, "POST", "/sign-out", `{}`, 200)
	deleteBefore = nil
	if _, _, err := store.Session(t.Context(), token); err != nil || seen() != "delete-before:/sign-out" {
		t.Fatal("a declined sign-out removed the session", err)
	}
	token = signIn(ada)
	seen()
	call(ada, "POST", "/sign-out", `{}`, 200)
	if got := seen(); got != "delete-before:/sign-out,delete-after:/sign-out:true" {
		t.Fatal("unexpected sign-out hooks", got)
	}

	// Signing in again in the same browser replaces the older session of that account.
	first := signIn(ada)
	seen()
	signIn(ada)
	if got := seen(); got != "delete-before:/sign-in/email,delete-after:/sign-in/email:true" {
		t.Fatal("unexpected replacement hooks", got)
	}
	if _, _, err := store.Session(t.Context(), first); err == nil {
		t.Fatal("the replaced session survived")
	}

	// Revoking other sessions runs the hooks for each one; one declined row keeps them all.
	other, phone := newBrowser(), newBrowser()
	signIn(other)
	signIn(phone)
	seen()
	count := func() int { s, _ := store.ListSessions(t.Context(), adaID); return len(s) }
	before := count()
	declined := 0
	deleteBefore = func(*authn.SessionRecord) error { declined++; return authn.ErrSkipWrite }
	call(ada, "POST", "/revoke-other-sessions", `{}`, 200)
	deleteBefore = nil
	if count() != before || declined != 1 {
		t.Fatal("a declined revocation removed sessions", before, count(), declined)
	}
	seen()
	call(ada, "POST", "/revoke-other-sessions", `{}`, 200)
	others := strings.Repeat("delete-before:/revoke-other-sessions,", before-1) + strings.TrimSuffix(strings.Repeat("delete-after:/revoke-other-sessions:true,", before-1), ",")
	if got := seen(); got != others || count() != 1 {
		t.Fatal("unexpected revocation hooks", got)
	}

	// An expired session is cleaned up through the hooks.
	now := time.Now().UTC().Truncate(time.Millisecond)
	stale := authn.StoredSession{Session: authn.Session{ID: "stale", Token: "stale-token", UserID: adaID, CreatedAt: now.Add(-2 * time.Hour), UpdatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}}
	if err := store.CreateSession(t.Context(), stale); err != nil {
		t.Fatal(err)
	}
	expired := newBrowser()
	r, _ := http.NewRequest("GET", base+"/api/auth/get-session", nil)
	r.AddCookie(auth.SessionCookie("stale-token", false))
	res, err := expired.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if got := seen(); got != "delete-before:/get-session,delete-after:/get-session:true" {
		t.Fatal("unexpected expired-session hooks", got)
	}

	// Changing the password with revocation runs the delete hooks for every session; a declined
	// revocation still changes the password and keeps every session.
	signIn(other)
	seen()
	deleteBefore = func(*authn.SessionRecord) error { return authn.ErrSkipWrite }
	out = call(ada, "POST", "/change-password", `{"currentPassword":"correct horse battery","newPassword":"second horse battery","revokeOtherSessions":true}`, 200)
	deleteBefore = nil
	if out["token"] != nil || len(func() []authn.StoredSession { s, _ := store.ListSessions(t.Context(), adaID); return s }()) != 2 {
		t.Fatal("a declined revocation changed the sessions", out)
	}
	seen()
	out = call(ada, "POST", "/change-password", `{"currentPassword":"second horse battery","newPassword":"third horse battery","revokeOtherSessions":true}`, 200)
	if got := seen(); out["token"] == nil || got != "delete-before:/change-password,delete-before:/change-password,delete-after:/change-password:true,delete-after:/change-password:true" {
		t.Fatal("unexpected change-password hooks", out, got)
	}
}

// New refuses session update and delete hooks that an enabled feature would bypass.
func TestDatabaseSessionHooksRefuseBypassingFeatures(t *testing.T) {
	update := authn.OperationHooks[authn.SessionRecord]{After: func(context.Context, authn.SessionRecord, *authn.HookContext) error { return nil }}
	base := func() authn.Options {
		return authn.Options{BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), EmailAndPassword: true}
	}
	updating := base()
	updating.Plugins = []authn.Plugin{{ID: "organization"}}
	updating.DatabaseHooks.Session.Update = update
	if _, err := authn.New(updating); err == nil || !strings.Contains(err.Error(), "organization") {
		t.Fatal("session update hooks were accepted with organizations", err)
	}
	codes, err := authn.NewEmailOTP(authn.EmailOTPOptions{Send: func(context.Context, authn.EmailOTPMessage) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	// An email code that proves an unverified account's address removes its sessions inside the store.
	for _, revoke := range []bool{false, true} {
		deleting := base()
		deleting.RevokeSessionsOnPasswordReset = revoke
		deleting.Plugins = []authn.Plugin{codes}
		deleting.DatabaseHooks.Session.Delete = update
		if _, err := authn.New(deleting); err == nil || !strings.Contains(err.Error(), "email-otp") {
			t.Fatal("session delete hooks were accepted with email codes", revoke, err)
		}
	}
	userHook := authn.OperationHooks[authn.UserRecord]{After: func(context.Context, authn.UserRecord, *authn.HookContext) error { return nil }}
	users := base()
	users.Plugins = []authn.Plugin{{ID: "anonymous"}}
	users.DatabaseHooks.User.Delete = userHook
	if _, err := authn.New(users); err == nil || !strings.Contains(err.Error(), "anonymous") {
		t.Fatal("user delete hooks were accepted with anonymous accounts", err)
	}
	profiles := base()
	profiles.Plugins = []authn.Plugin{{ID: "last-login-method"}}
	profiles.DatabaseHooks.User.Update = userHook
	if _, err := authn.New(profiles); err == nil || !strings.Contains(err.Error(), "last-login-method") {
		t.Fatal("user update hooks were accepted with the last-login plugin", err)
	}
}
