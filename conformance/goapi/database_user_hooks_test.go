package goapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// Run user update hooks around profile updates, email changes and email
// verification: edit the profile, skip a change, and observe stored users.
func TestDatabaseUserUpdateHooks(t *testing.T) {
	var mu sync.Mutex
	var events []string
	record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
	seen := func() string { mu.Lock(); defer mu.Unlock(); s := strings.Join(events, ","); events = nil; return s }
	var before func(*authn.UserRecord) error
	var mail []authn.MailLink
	store := memory.New()
	off := false
	auth, err := authn.New(authn.Options{
		BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off, Logger: slog.New(slog.DiscardHandler),
		ChangeEmailEnabled: true, UpdateEmailWithoutVerification: true,
		SendVerificationEmail: func(_ context.Context, m authn.MailLink) error { mail = append(mail, m); return nil },
		UserAdditionalFields:  map[string]authn.UserField{"plan": {Type: authn.FieldString}},
		DatabaseHooks: authn.DatabaseHooks{User: authn.ModelHooks[authn.UserRecord]{Update: authn.OperationHooks[authn.UserRecord]{
			Before: func(_ context.Context, u *authn.UserRecord, c *authn.HookContext) error {
				where := "go"
				if c != nil {
					where = c.Path
				}
				record("before:" + where + ":" + u.Email + ":" + boolString(u.EmailVerified))
				if before != nil {
					return before(u)
				}
				return nil
			},
			After: func(ctx context.Context, u authn.UserRecord, _ *authn.HookContext) error {
				stored, err := store.FindAccountUser(ctx, u.Email)
				if err != nil {
					return err
				}
				plan, _ := u.Fields["plan"].(string)
				record("after:" + stored.Name + ":" + stored.Email + ":" + boolString(stored.EmailVerified) + ":" + plan)
				return nil
			},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
	call := func(method, target, body string, status int) map[string]any {
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
		if w.Code == 200 && method == "POST" {
			for _, c := range w.Result().Cookies() {
				h.Set("Cookie", c.Name+"="+c.Value)
			}
		}
		return out
	}
	call("POST", "/sign-up/email", `{"email":"ada@example.com","password":"correct horse battery","name":"Ada"}`, 200)
	user := func(email string) authn.User {
		t.Helper()
		u, err := store.FindAccountUser(t.Context(), email)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}

	// A profile update runs the hooks with the change applied; a hook may adjust the profile.
	before = func(u *authn.UserRecord) error {
		u.Name = strings.TrimSpace(u.Name) + " (verified)"
		u.Fields["plan"] = "pro"
		return nil
	}
	call("POST", "/update-user", `{"name":"  Ada Lovelace "}`, 200)
	if got := seen(); got != "before:/update-user:ada@example.com:false,after:Ada Lovelace (verified):ada@example.com:false:pro" {
		t.Fatal("unexpected profile update hooks", got)
	}
	// A declined update answers like a stored one and stores nothing.
	before = func(*authn.UserRecord) error { return authn.ErrSkipWrite }
	call("POST", "/update-user", `{"name":"Countess"}`, 200)
	if user("ada@example.com").Name != "Ada Lovelace (verified)" {
		t.Fatal("a declined profile update was stored")
	}
	// Changing a field the update does not store fails it.
	before = func(u *authn.UserRecord) error { u.EmailVerified = true; return nil }
	call("POST", "/update-user", `{"name":"Countess"}`, 500)
	before = nil
	seen()

	// Email verification runs the hooks with the address marked verified; a declined one keeps it unverified.
	call("POST", "/send-verification-email", `{"email":"ada@example.com"}`, 200)
	token := mail[len(mail)-1].Token
	before = func(*authn.UserRecord) error { return authn.ErrSkipWrite }
	call("GET", "/verify-email?token="+url.QueryEscape(token), "", 200)
	if user("ada@example.com").EmailVerified {
		t.Fatal("a declined verification was stored")
	}
	before = nil
	call("GET", "/verify-email?token="+url.QueryEscape(token), "", 200)
	if got := seen(); got != "before:/verify-email:ada@example.com:true,before:/verify-email:ada@example.com:true,after:Ada Lovelace (verified):ada@example.com:true:" {
		t.Fatal("unexpected verification hooks", got)
	}

	// A verified address changes through a link; a declined change keeps the old address.
	call("POST", "/change-email", `{"newEmail":"lovelace@example.com"}`, 200)
	link := mail[len(mail)-1].Token
	before = func(*authn.UserRecord) error { return authn.ErrSkipWrite }
	call("GET", "/verify-email?token="+url.QueryEscape(link), "", 200)
	before = nil
	if user("ada@example.com").ID == "" {
		t.Fatal("a declined email change was stored")
	}
	call("GET", "/verify-email?token="+url.QueryEscape(link), "", 200)
	if got := seen(); got != "before:/verify-email:lovelace@example.com:true,before:/verify-email:lovelace@example.com:true,after:Ada Lovelace (verified):lovelace@example.com:true:" {
		t.Fatal("unexpected email change hooks", got)
	}

	// An unverified address changes at once through the hooks.
	call("POST", "/sign-up/email", `{"email":"grace@example.com","password":"correct horse battery","name":"Grace"}`, 200)
	call("POST", "/change-email", `{"newEmail":"hopper@example.com"}`, 200)
	if got := seen(); got != "before:/change-email:hopper@example.com:false,after:Grace:hopper@example.com:false:" {
		t.Fatal("unexpected immediate email change hooks", got)
	}

	// Direct Go calls run the hooks without an endpoint context.
	name := "Rear Admiral Hopper"
	if err := auth.UpdateUser(t.Context(), h, authn.ProfileUpdate{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if got := seen(); got != "before:go:hopper@example.com:false,after:Rear Admiral Hopper:hopper@example.com:false:" {
		t.Fatal("unexpected Go call hooks", got)
	}
	if _, err := store.FindAccountUser(t.Context(), "grace@example.com"); !errors.Is(err, authn.ErrNotFound) {
		t.Fatal("the old address still resolves", err)
	}
}

// Run the session and user delete hooks when a user deletes their account; a
// declined deletion keeps everything and answers like a completed one.
func TestDatabaseUserDeleteHooks(t *testing.T) {
	var mu sync.Mutex
	var events []string
	record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
	seen := func() string { mu.Lock(); defer mu.Unlock(); s := strings.Join(events, ","); events = nil; return s }
	var decline bool
	store := memory.New()
	off := false
	auth, err := authn.New(authn.Options{
		BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off, DeleteUserEnabled: true,
		DatabaseHooks: authn.DatabaseHooks{
			User: authn.ModelHooks[authn.UserRecord]{Delete: authn.OperationHooks[authn.UserRecord]{
				Before: func(_ context.Context, u *authn.UserRecord, c *authn.HookContext) error {
					record("user-before:" + c.Path + ":" + u.Email)
					if decline {
						return authn.ErrSkipWrite
					}
					return nil
				},
				After: func(ctx context.Context, u authn.UserRecord, _ *authn.HookContext) error {
					_, err := store.FindAccountUser(ctx, u.Email)
					record("user-after:" + boolString(errors.Is(err, authn.ErrNotFound)))
					return nil
				},
			}},
			Session: authn.ModelHooks[authn.SessionRecord]{Delete: authn.OperationHooks[authn.SessionRecord]{
				Before: func(context.Context, *authn.SessionRecord, *authn.HookContext) error {
					record("session-before")
					return nil
				},
				After: func(context.Context, authn.SessionRecord, *authn.HookContext) error {
					record("session-after")
					return nil
				},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
	call := func(target, body string, status int) map[string]any {
		t.Helper()
		r := httptest.NewRequest("POST", "https://auth.example/api/auth"+target, strings.NewReader(body))
		r.Header = h.Clone()
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("POST %s returned %d, want %d: %s", target, w.Code, status, w.Body)
		}
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		for _, c := range w.Result().Cookies() {
			if c.MaxAge >= 0 && c.Value != "" {
				h.Set("Cookie", c.Name+"="+c.Value)
			}
		}
		return out
	}
	out := call("/sign-up/email", `{"email":"ada@example.com","password":"correct horse battery","name":"Ada"}`, 200)
	adaID := out["user"].(map[string]any)["id"].(string)
	signedIn := h.Get("Cookie")
	call("/sign-in/email", `{"email":"ada@example.com","password":"correct horse battery"}`, 200)
	h.Set("Cookie", signedIn)

	// A declined deletion answers like a completed one but keeps the user and every session.
	decline = true
	if out = call("/delete-user", `{"password":"correct horse battery"}`, 200); out["message"] != "User deleted" {
		t.Fatal("unexpected declined deletion response", out)
	}
	if sessions, _ := store.ListSessions(t.Context(), adaID); len(sessions) != 2 {
		t.Fatal("a declined deletion removed sessions", len(sessions))
	}
	if got := seen(); got != "session-before,session-before,user-before:/delete-user:ada@example.com" {
		t.Fatal("unexpected declined deletion hooks", got)
	}
	decline = false
	h.Set("Cookie", signedIn)
	call("/delete-user", `{"password":"correct horse battery"}`, 200)
	if got := seen(); got != "session-before,session-before,user-before:/delete-user:ada@example.com,session-after,session-after,user-after:true" {
		t.Fatal("unexpected deletion hooks", got)
	}
}

// Run account hooks around the credential a sign-up stores, password
// changes, setting a first password, unlinking and account deletion.
func TestDatabaseAccountHooks(t *testing.T) {
	var mu sync.Mutex
	var events []string
	record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
	seen := func() string { mu.Lock(); defer mu.Unlock(); s := strings.Join(events, ","); events = nil; return s }
	var decline, edit bool
	op := func(name string) authn.OperationHooks[authn.LinkedAccount] {
		return authn.OperationHooks[authn.LinkedAccount]{
			Before: func(_ context.Context, account *authn.LinkedAccount, _ *authn.HookContext) error {
				record(name + "-before:" + account.ProviderID + ":" + boolString(account.ID != ""))
				if edit {
					account.ProviderID = "github"
				}
				if decline {
					return authn.ErrSkipWrite
				}
				return nil
			},
			After: func(_ context.Context, account authn.LinkedAccount, _ *authn.HookContext) error {
				record(name + "-after:" + account.ProviderID + ":" + boolString(account.ID != ""))
				return nil
			},
		}
	}
	store := memory.New()
	off := false
	auth, err := authn.New(authn.Options{
		BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		Logger: slog.New(slog.DiscardHandler), AllowUnlinkingAll: true, DeleteUserEnabled: true,
		DatabaseHooks: authn.DatabaseHooks{Account: authn.ModelHooks[authn.LinkedAccount]{Create: op("create"), Update: op("update"), Delete: op("delete")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
	call := func(target, body string, status int) map[string]any {
		t.Helper()
		r := httptest.NewRequest("POST", "https://auth.example/api/auth"+target, strings.NewReader(body))
		r.Header = h.Clone()
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("POST %s returned %d, want %d: %s", target, w.Code, status, w.Body)
		}
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		for _, c := range w.Result().Cookies() {
			if c.MaxAge >= 0 && c.Value != "" {
				h.Set("Cookie", c.Name+"="+c.Value)
			}
		}
		return out
	}

	// A declined credential cancels the sign-up; an accepted one is reported with its stored ID.
	decline = true
	if out := call("/sign-up/email", `{"email":"ada@example.com","password":"correct horse battery","name":"Ada"}`, 400); out["code"] != "FAILED_TO_CREATE_USER" {
		t.Fatal("a declined credential did not cancel the sign-up", out)
	}
	decline = false
	out := call("/sign-up/email", `{"email":"ada@example.com","password":"correct horse battery","name":"Ada"}`, 200)
	adaID := out["user"].(map[string]any)["id"].(string)
	if got := seen(); got != "create-before:credential:false,create-before:credential:false,create-after:credential:true" {
		t.Fatal("unexpected sign-up account hooks", got)
	}

	// A declined password change fails, and the old password keeps working.
	decline = true
	if out = call("/change-password", `{"currentPassword":"correct horse battery","newPassword":"second horse battery"}`, 400); out["code"] != "FAILED_TO_UPDATE_USER" {
		t.Fatal("a declined password change did not fail", out)
	}
	decline = false
	call("/sign-in/email", `{"email":"ada@example.com","password":"correct horse battery"}`, 200)
	call("/change-password", `{"currentPassword":"correct horse battery","newPassword":"second horse battery"}`, 200)
	if got := seen(); got != "update-before:credential:true,update-before:credential:true,update-after:credential:true" {
		t.Fatal("unexpected password change hooks", got)
	}
	// Account hooks may not change the account.
	edit = true
	call("/change-password", `{"currentPassword":"second horse battery","newPassword":"third horse battery"}`, 500)
	edit = false
	seen()

	// A declined unlink answers success and keeps the account.
	accounts, _ := store.ListUserAccounts(t.Context(), adaID)
	credential := accounts[0].ID
	decline = true
	call("/unlink-account", `{"accountId":"`+credential+`"}`, 200)
	decline = false
	if accounts, _ = store.ListUserAccounts(t.Context(), adaID); len(accounts) != 1 {
		t.Fatal("a declined unlink removed the account")
	}
	call("/unlink-account", `{"accountId":"`+credential+`"}`, 200)
	if got := seen(); got != "delete-before:credential:true,delete-before:credential:true,delete-after:credential:true" {
		t.Fatal("unexpected unlink hooks", got)
	}

	// Setting a first password creates the credential through the hooks.
	if err := auth.SetPassword(t.Context(), h, "fourth horse battery"); err != nil {
		t.Fatal(err)
	}
	if got := seen(); got != "create-before:credential:false,create-after:credential:true" {
		t.Fatal("unexpected set-password hooks", got)
	}

	// Deleting the user runs the account delete hooks for each account.
	call("/delete-user", `{"password":"fourth horse battery"}`, 200)
	if got := seen(); got != "delete-before:credential:true,delete-after:credential:true" {
		t.Fatal("unexpected account deletion hooks", got)
	}

	// A code reset changes the credential inside the store, so New refuses account hooks with email codes.
	codes, err := authn.NewEmailOTP(authn.EmailOTPOptions{Send: func(context.Context, authn.EmailOTPMessage) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authn.New(authn.Options{
		BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), EmailAndPassword: true,
		Plugins:       []authn.Plugin{codes},
		DatabaseHooks: authn.DatabaseHooks{Account: authn.ModelHooks[authn.LinkedAccount]{Update: op("update")}},
	}); err == nil || !strings.Contains(err.Error(), "email-otp") {
		t.Fatal("account hooks were accepted with email codes", err)
	}
}

// Run the credential account hooks and the revoked sessions' delete hooks
// around a password reset link.
func TestDatabaseHooksAroundPasswordReset(t *testing.T) {
	var mu sync.Mutex
	var events []string
	record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
	seen := func() string { mu.Lock(); defer mu.Unlock(); s := strings.Join(events, ","); events = nil; return s }
	var declineAccount, declineSessions bool
	var link authn.MailLink
	store := memory.New()
	off := false
	auth, err := authn.New(authn.Options{
		BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		RevokeSessionsOnPasswordReset: true,
		SendResetPassword:             func(_ context.Context, m authn.MailLink) error { link = m; return nil },
		DatabaseHooks: authn.DatabaseHooks{
			Account: authn.ModelHooks[authn.LinkedAccount]{Update: authn.OperationHooks[authn.LinkedAccount]{
				Before: func(context.Context, *authn.LinkedAccount, *authn.HookContext) error {
					record("account-before")
					if declineAccount {
						return authn.ErrSkipWrite
					}
					return nil
				},
				After: func(context.Context, authn.LinkedAccount, *authn.HookContext) error {
					record("account-after")
					return nil
				},
			}},
			Session: authn.ModelHooks[authn.SessionRecord]{Delete: authn.OperationHooks[authn.SessionRecord]{
				Before: func(context.Context, *authn.SessionRecord, *authn.HookContext) error {
					record("session-before")
					if declineSessions {
						return authn.ErrSkipWrite
					}
					return nil
				},
				After: func(context.Context, authn.SessionRecord, *authn.HookContext) error {
					record("session-after")
					return nil
				},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	password := "correct horse battery"
	account, err := auth.SignUpEmail(ctx, authn.SignUpInput{Email: "ada@example.com", Password: password, Name: "Ada"}, authn.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.SignInEmail(ctx, authn.SignInInput{Email: "ada@example.com", Password: password}, authn.RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	reset := func(next string) error {
		t.Helper()
		if err := auth.RequestPasswordReset(ctx, "ada@example.com", "/reset"); err != nil {
			t.Fatal(err)
		}
		return auth.ResetPassword(ctx, link.Token, next)
	}
	sessions := func() int { s, _ := store.ListSessions(ctx, account.User.ID); return len(s) }

	// A declined credential update fails the reset and keeps the old password.
	declineAccount = true
	var problem *authn.APIError
	if err := reset("second horse battery"); !errors.As(err, &problem) || problem.Code != "FAILED_TO_UPDATE_USER" {
		t.Fatal("a declined credential update did not fail the reset", err)
	}
	declineAccount = false
	if _, err := auth.SignInEmail(ctx, authn.SignInInput{Email: "ada@example.com", Password: password}, authn.RequestMeta{}); err != nil {
		t.Fatal("the declined reset changed the password", err)
	}
	seen()

	// A declined revocation still resets the password and keeps every session.
	declineSessions = true
	before := sessions()
	if err := reset("second horse battery"); err != nil {
		t.Fatal(err)
	}
	declineSessions = false
	if sessions() != before || seen() != "account-before,session-before,account-after" {
		t.Fatal("a declined revocation removed sessions", sessions(), before)
	}

	// The reset runs the credential hooks and the delete hooks of every revoked session.
	if err := reset("third horse battery"); err != nil {
		t.Fatal(err)
	}
	want := "account-before," + strings.Repeat("session-before,", before) + "account-after" + strings.Repeat(",session-after", before)
	if got := seen(); sessions() != 0 || got != want {
		t.Fatal("unexpected reset hooks", got, want)
	}
}
