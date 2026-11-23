package goapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

// Run user and session create hooks around sign-up, sign-in, anonymous
// sign-in, plugin sessions and password changes: edit rows, skip or fail
// writes, and observe stored rows.
func TestDatabaseCreateHooks(t *testing.T) {
	var mu sync.Mutex
	var events []string
	record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
	seen := func() string { mu.Lock(); defer mu.Unlock(); s := strings.Join(events, ","); events = nil; return s }
	path := func(c *authn.HookContext) string {
		if c == nil {
			return "go"
		}
		return c.Path
	}
	var userBefore func(*authn.UserRecord) error
	var sessionBefore func(*authn.SessionRecord) error
	var userAfter, sessionAfter error
	store := memory.New()
	anonymous, err := authn.NewAnonymous(authn.AnonymousOptions{})
	if err != nil {
		t.Fatal(err)
	}
	issuer := authn.Plugin{ID: "issuer", Endpoints: []authn.Endpoint{{Method: "POST", Path: "/issue", Handler: func(c authn.EndpointContext) (any, error) {
		user, _ := c.Body["userId"].(string)
		return c.IssueSession(user, func(ctx context.Context, s authn.StoredSession) (authn.User, error) {
			if err := store.CreateSession(ctx, s); err != nil {
				return authn.User{}, err
			}
			return authn.User{ID: s.UserID}, nil
		})
	}}}}
	audit := authn.Plugin{ID: "audit", DatabaseHooks: authn.DatabaseHooks{
		User: authn.ModelHooks[authn.UserRecord]{Create: authn.OperationHooks[authn.UserRecord]{
			Before: func(_ context.Context, u *authn.UserRecord, c *authn.HookContext) error {
				record("plugin-user-before:" + path(c))
				return nil
			},
		}},
	}}
	off := false
	auth, err := authn.New(authn.Options{
		BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		Logger:                  slog.New(slog.DiscardHandler),
		UserAdditionalFields:    map[string]authn.UserField{"plan": {Type: authn.FieldString}, "tier": {Type: authn.FieldString, ServerOnly: true, Default: "basic"}},
		SessionAdditionalFields: map[string]authn.SessionField{"device": {Type: authn.FieldString, Default: "unknown"}},
		Plugins:                 []authn.Plugin{audit, anonymous, issuer},
		DatabaseHooks: authn.DatabaseHooks{
			User: authn.ModelHooks[authn.UserRecord]{Create: authn.OperationHooks[authn.UserRecord]{
				Before: func(_ context.Context, u *authn.UserRecord, c *authn.HookContext) error {
					record("user-before:" + path(c) + ":" + u.Email)
					if userBefore != nil {
						return userBefore(u)
					}
					return nil
				},
				After: func(ctx context.Context, u authn.UserRecord, c *authn.HookContext) error {
					// The stored user is visible to hooks, which may use the store.
					stored, err := store.FindAccountUser(ctx, u.Email)
					if err != nil {
						return err
					}
					record("user-after:" + path(c) + ":" + stored.Name + ":" + boolString(stored.EmailVerified))
					return userAfter
				},
			}},
			Session: authn.ModelHooks[authn.SessionRecord]{Create: authn.OperationHooks[authn.SessionRecord]{
				Before: func(_ context.Context, s *authn.SessionRecord, c *authn.HookContext) error {
					record("session-before:" + path(c))
					if sessionBefore != nil {
						return sessionBefore(s)
					}
					return nil
				},
				After: func(_ context.Context, s authn.SessionRecord, c *authn.HookContext) error {
					record("session-after:" + path(c) + ":" + s.UserAgent)
					return sessionAfter
				},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}, "User-Agent": {"browser"}}
	call := func(method, target, body string, status int) (map[string]any, *http.Response) {
		t.Helper()
		r := httptest.NewRequest(method, "https://auth.example/api/auth"+target, strings.NewReader(body))
		r.Header = h.Clone()
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s %s returned %d, want %d: %s", method, target, w.Code, status, w.Body)
		}
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out, w.Result()
	}
	signUp := func(email string, status int) map[string]any {
		t.Helper()
		out, _ := call("POST", "/sign-up/email", `{"email":"`+email+`","password":"correct horse battery","name":"Ada","plan":"free","tier":"gold"}`, status)
		return out
	}

	// Plugin hooks run first; before hooks edit the user, its fields and its session.
	userBefore = func(u *authn.UserRecord) error {
		u.Name, u.EmailVerified = "Ada Lovelace", true
		if _, sneaked := u.Fields["tier"]; sneaked {
			return errors.New("a caller set a server-only field")
		}
		u.Fields["plan"], u.Fields["tier"] = "pro", "silver"
		return nil
	}
	sessionBefore = func(s *authn.SessionRecord) error {
		s.UserAgent, s.ExpiresAt = "hooked", s.ExpiresAt.Add(-time.Hour)
		s.Fields["device"] = "laptop"
		return nil
	}
	out, signUpResponse := call("POST", "/sign-up/email", `{"email":"ada@example.com","password":"correct horse battery","name":"Ada","plan":"free","tier":"gold"}`, 200)
	if got := seen(); got != "plugin-user-before:/sign-up/email,user-before:/sign-up/email:ada@example.com,session-before:/sign-up/email,user-after:/sign-up/email:Ada Lovelace:true,session-after:/sign-up/email:hooked" {
		t.Fatal("unexpected sign-up hooks", got)
	}
	user, _ := out["user"].(map[string]any)
	if user["name"] != "Ada Lovelace" || user["plan"] != "pro" || user["tier"] != "silver" || user["emailVerified"] != true {
		t.Fatal("the hook edits were not stored", out)
	}
	token, _ := out["token"].(string)
	session, user2, err := store.Session(t.Context(), token)
	if err != nil || session.UserAgent != "hooked" || user2.Name != "Ada Lovelace" || time.Until(session.ExpiresAt) > 7*24*time.Hour-time.Hour+time.Minute {
		t.Fatal("the session edits were not stored", session, err)
	}
	for _, c := range signUpResponse.Cookies() {
		h.Add("Cookie", c.Name+"="+c.Value)
	}
	current, _ := call("GET", "/get-session", "", 200)
	h.Del("Cookie")
	if got, _ := current["session"].(map[string]any); got["device"] != "laptop" {
		t.Fatal("the session field edit was not stored", current)
	}
	userBefore, sessionBefore = nil, nil

	// An existing email takes the duplicate path before any hook runs.
	signUp("ada@example.com", 422)
	if got := seen(); got != "" {
		t.Fatal("a duplicate sign-up ran hooks", got)
	}

	// A skipped, rejected or failed user write stores nothing.
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{authn.ErrSkipWrite, 400, "FAILED_TO_CREATE_USER"},
		{&authn.APIError{Status: 403, Code: "DOMAIN_NOT_ALLOWED", Message: "Use a work address"}, 403, "DOMAIN_NOT_ALLOWED"},
		{errors.New("directory unavailable"), 422, "FAILED_TO_CREATE_USER"},
	} {
		userBefore = func(*authn.UserRecord) error { return tc.err }
		if out = signUp("grace@example.com", tc.status); out["code"] != tc.code {
			t.Fatal("unexpected user hook failure", out)
		}
	}
	userBefore = nil
	sessionBefore = func(*authn.SessionRecord) error { return authn.ErrSkipWrite }
	if out = signUp("grace@example.com", 400); out["code"] != "FAILED_TO_CREATE_SESSION" {
		t.Fatal("a skipped session did not fail the sign-up", out)
	}
	sessionBefore = nil
	if _, err := store.FindAccountUser(t.Context(), "grace@example.com"); !errors.Is(err, authn.ErrNotFound) {
		t.Fatal("a cancelled sign-up stored its user", err)
	}
	seen()

	// A hook may change only the fields the write stores, and its values are checked.
	userBefore = func(u *authn.UserRecord) error { u.ID = "chosen"; return nil }
	if out = signUp("grace@example.com", 500); out["code"] != "INTERNAL_SERVER_ERROR" {
		t.Fatal("a changed user ID was accepted", out)
	}
	userBefore = func(u *authn.UserRecord) error { u.Email = "not an email"; return nil }
	if out = signUp("grace@example.com", 400); out["code"] != "INVALID_EMAIL" {
		t.Fatal("an invalid edited email was accepted", out)
	}
	userBefore = func(u *authn.UserRecord) error { u.Fields["plan"] = 7; return nil }
	if out = signUp("grace@example.com", 400); out["code"] != "VALIDATION_ERROR" {
		t.Fatal("an invalid edited field was accepted", out)
	}
	userBefore = nil
	sessionBefore = func(s *authn.SessionRecord) error { s.UserID = "someone-else"; return nil }
	signUp("grace@example.com", 500)
	sessionBefore = nil
	if _, err := store.FindAccountUser(t.Context(), "grace@example.com"); !errors.Is(err, authn.ErrNotFound) {
		t.Fatal("a rejected edit stored its user", err)
	}
	seen()

	// A failing after hook keeps the user but removes the session it has not delivered.
	userAfter = &authn.APIError{Status: 409, Code: "CRM_SYNC_FAILED", Message: "Try again"}
	if out = signUp("grace@example.com", 409); out["code"] != "CRM_SYNC_FAILED" {
		t.Fatal("the after hook error was not returned", out)
	}
	userAfter = nil
	if _, err := store.FindAccountUser(t.Context(), "grace@example.com"); err != nil {
		t.Fatal("a failing after hook removed the stored user", err)
	}
	if got := seen(); got != "plugin-user-before:/sign-up/email,user-before:/sign-up/email:grace@example.com,session-before:/sign-up/email,user-after:/sign-up/email:Ada:false" {
		t.Fatal("unexpected hooks after a failing after hook", got)
	}

	// Sign-in creates a session through the hooks; a skip answers 401.
	sessionBefore = func(*authn.SessionRecord) error { return authn.ErrSkipWrite }
	if out, _ = call("POST", "/sign-in/email", `{"email":"grace@example.com","password":"correct horse battery"}`, 401); out["code"] != "FAILED_TO_CREATE_SESSION" {
		t.Fatal("a skipped sign-in session was not refused", out)
	}
	sessionBefore = nil
	sessionAfter = errors.New("audit log unavailable")
	call("POST", "/sign-in/email", `{"email":"grace@example.com","password":"correct horse battery"}`, 500)
	sessionAfter = nil
	out, res := call("POST", "/sign-in/email", `{"email":"grace@example.com","password":"correct horse battery"}`, 200)
	if got := seen(); got != "session-before:/sign-in/email,session-before:/sign-in/email,session-after:/sign-in/email:browser,session-before:/sign-in/email,session-after:/sign-in/email:browser" {
		t.Fatal("unexpected sign-in hooks", got)
	}
	graceID := out["user"].(map[string]any)["id"].(string)
	if sessions, _ := store.ListSessions(t.Context(), graceID); len(sessions) != 1 {
		t.Fatal("a failing after hook left its undelivered session", len(sessions))
	}

	// Changing the password with revocation creates the replacement session through the hooks.
	for _, c := range res.Cookies() {
		h.Add("Cookie", c.Name+"="+c.Value)
	}
	call("POST", "/change-password", `{"currentPassword":"correct horse battery","newPassword":"another horse battery","revokeOtherSessions":true}`, 200)
	h.Del("Cookie")
	if got := seen(); got != "session-before:/change-password,session-after:/change-password:browser" {
		t.Fatal("unexpected change-password hooks", got)
	}

	// Anonymous sign-in creates its user and session through the hooks; a skip stores nothing.
	call("POST", "/sign-in/anonymous", `{}`, 200)
	if got := seen(); !strings.HasPrefix(got, "plugin-user-before:/sign-in/anonymous,user-before:/sign-in/anonymous:") || !strings.HasSuffix(got, ",session-before:/sign-in/anonymous,user-after:/sign-in/anonymous:Anonymous:false,session-after:/sign-in/anonymous:browser") {
		t.Fatal("unexpected anonymous hooks", got)
	}
	userBefore = func(*authn.UserRecord) error { return authn.ErrSkipWrite }
	if out, _ = call("POST", "/sign-in/anonymous", `{}`, 500); out["code"] != "FAILED_TO_CREATE_USER" {
		t.Fatal("a skipped anonymous user was not refused", out)
	}
	userBefore = func(u *authn.UserRecord) error { u.Fields["plan"] = "trial"; return nil }
	if out, _ = call("POST", "/sign-in/anonymous", `{}`, 500); out["code"] != "INTERNAL_SERVER_ERROR" {
		t.Fatal("a guest field edit was silently dropped", out)
	}
	userBefore = func(u *authn.UserRecord) error { u.Email = "kept-out@example.com"; return nil }
	sessionBefore = func(*authn.SessionRecord) error { return authn.ErrSkipWrite }
	if out, _ = call("POST", "/sign-in/anonymous", `{}`, 400); out["code"] != "COULD_NOT_CREATE_SESSION" {
		t.Fatal("a skipped anonymous session was not refused", out)
	}
	userBefore, sessionBefore = nil, nil
	if _, err := store.FindAccountUser(t.Context(), "kept-out@example.com"); !errors.Is(err, authn.ErrNotFound) {
		t.Fatal("a skipped anonymous session left its user", err)
	}
	seen()

	// A plugin-issued session runs the session hooks.
	call("POST", "/issue", `{"userId":"`+graceID+`"}`, 200)
	if got := seen(); got != "session-before:/issue,session-after:/issue:browser" {
		t.Fatal("unexpected issued-session hooks", got)
	}
	sessionBefore = func(*authn.SessionRecord) error { return authn.ErrSkipWrite }
	call("POST", "/issue", `{"userId":"`+graceID+`"}`, 401)
	sessionBefore = nil
	seen()

	// Direct Go calls run the hooks without an endpoint context.
	if _, err := auth.SignUpEmail(t.Context(), authn.SignUpInput{Email: "lin@example.com", Password: "correct horse battery", Name: "Lin"}, authn.RequestMeta{UserAgent: "cli"}); err != nil {
		t.Fatal(err)
	}
	if got := seen(); got != "plugin-user-before:go,user-before:go:lin@example.com,session-before:go,user-after:go:Lin:false,session-after:go:cli" {
		t.Fatal("unexpected Go call hooks", got)
	}
}

// New refuses database hooks that an enabled feature would bypass.
func TestDatabaseHooksRefuseBypassingFeatures(t *testing.T) {
	create := authn.OperationHooks[authn.UserRecord]{Before: func(context.Context, *authn.UserRecord, *authn.HookContext) error { return nil }}
	update := authn.OperationHooks[authn.SessionRecord]{After: func(context.Context, authn.SessionRecord, *authn.HookContext) error { return nil }}
	base := func() authn.Options {
		return authn.Options{BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), EmailAndPassword: true}
	}
	sqliteStore, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer sqliteStore.Close()
	social := base()
	social.Store = sqliteStore
	social.SocialProviders = map[string]authn.OAuthProvider{"local": {
		Config: oauth2.Config{ClientID: "local", Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example/authorize", TokenURL: "https://idp.example/token"}},
		Resolve: func(context.Context, *oauth2.Token, string) (authn.OAuthProfile, error) {
			return authn.OAuthProfile{}, nil
		},
	}}
	social.DatabaseHooks.User.Create = create
	if _, err := authn.New(social); err == nil || !strings.Contains(err.Error(), "social sign-in") {
		t.Fatal("user create hooks were accepted with social sign-in", err)
	}
	later := base()
	later.DatabaseHooks.Session.Update = update
	if _, err := authn.New(later); err == nil || !strings.Contains(err.Error(), "not supported yet") {
		t.Fatal("session update hooks were accepted", err)
	}
	ok := base()
	ok.DatabaseHooks.User.Create = create
	if _, err := authn.New(ok); err != nil {
		t.Fatal("supported hooks were refused", err)
	}
}
