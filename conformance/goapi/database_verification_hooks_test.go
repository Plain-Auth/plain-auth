package goapi_test

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// Verification hooks run around password reset and account deletion links:
// create when a link is mailed, delete when it is spent, before the account,
// session and user hooks of the change it allows. A declined create answers
// as a sent link with nothing stored or mailed; a declined spend answers
// INVALID_TOKEN and keeps the link usable. The records carry no token, and
// a link that is another account's runs no verification hook.
func TestDatabaseVerificationHooks(t *testing.T) {
	var mu sync.Mutex
	var events []string
	var records []authn.VerificationRecord
	var contexts []*authn.HookContext
	decline := map[string]bool{}
	fail := map[string]error{}
	edit := false
	note := func(event string, rec authn.VerificationRecord, c *authn.HookContext) error {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
		records, contexts = append(records, rec), append(contexts, c)
		if decline[event] {
			return authn.ErrSkipWrite
		}
		return fail[event]
	}
	plain := func(event string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	}
	drain := func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := events
		events = nil
		return out
	}
	var links []authn.MailLink
	mail := func(_ context.Context, m authn.MailLink) error {
		mu.Lock()
		defer mu.Unlock()
		links = append(links, m)
		return nil
	}
	lastLink := func() (authn.MailLink, int) {
		mu.Lock()
		defer mu.Unlock()
		if len(links) == 0 {
			return authn.MailLink{}, 0
		}
		return links[len(links)-1], len(links)
	}
	hooks := authn.DatabaseHooks{
		Verification: authn.ModelHooks[authn.VerificationRecord]{
			Create: authn.OperationHooks[authn.VerificationRecord]{
				Before: func(_ context.Context, r *authn.VerificationRecord, c *authn.HookContext) error {
					err := note("create-before:"+r.Identifier, *r, c)
					if edit {
						r.UserID = "someone-else"
					}
					return err
				},
				After: func(_ context.Context, r authn.VerificationRecord, c *authn.HookContext) error {
					return note("create-after:"+r.Identifier, r, c)
				},
			},
			Delete: authn.OperationHooks[authn.VerificationRecord]{
				Before: func(_ context.Context, r *authn.VerificationRecord, c *authn.HookContext) error {
					return note("delete-before:"+r.Identifier, *r, c)
				},
				After: func(_ context.Context, r authn.VerificationRecord, c *authn.HookContext) error {
					return note("delete-after:"+r.Identifier, r, c)
				},
			},
		},
		Account: authn.ModelHooks[authn.LinkedAccount]{Update: authn.OperationHooks[authn.LinkedAccount]{
			Before: func(context.Context, *authn.LinkedAccount, *authn.HookContext) error {
				plain("account-update-before")
				return nil
			},
			After: func(context.Context, authn.LinkedAccount, *authn.HookContext) error {
				plain("account-update-after")
				return nil
			},
		}},
		Session: authn.ModelHooks[authn.SessionRecord]{Delete: authn.OperationHooks[authn.SessionRecord]{
			Before: func(context.Context, *authn.SessionRecord, *authn.HookContext) error {
				plain("session-delete-before")
				return nil
			},
			After: func(context.Context, authn.SessionRecord, *authn.HookContext) error {
				plain("session-delete-after")
				return nil
			},
		}},
		User: authn.ModelHooks[authn.UserRecord]{Delete: authn.OperationHooks[authn.UserRecord]{
			Before: func(context.Context, *authn.UserRecord, *authn.HookContext) error {
				plain("user-delete-before")
				return nil
			},
		}},
	}
	off := false
	auth, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		RevokeSessionsOnPasswordReset: true, DeleteUserEnabled: true, SendResetPassword: mail, SendDeleteAccountVerification: mail, DatabaseHooks: hooks})
	if err != nil {
		t.Fatal(err)
	}
	c := sessionClient{t, auth}
	c.post("/sign-up/email", `{"name":"Ada","email":"ada@example.test","password":"`+sessionEndpointPassword+`"}`, "", 200)
	adaCookie, _ := c.signIn("ada@example.test")
	c.post("/sign-up/email", `{"name":"Bo","email":"bo@example.test","password":"`+sessionEndpointPassword+`"}`, "", 200)
	boCookie, _ := c.signIn("bo@example.test")
	drain()
	same := func(got []string, want ...string) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("hooks ran as %q, want %q", got, want)
		}
	}

	// Password reset links.
	request := func() { c.post("/request-password-reset", `{"email":"ada@example.test","redirectTo":"/"}`, "", 200) }
	decline["create-before:reset-password"] = true
	request()
	if _, n := lastLink(); n != 0 {
		t.Fatal("a declined reset link was mailed")
	}
	same(drain(), "create-before:reset-password")
	decline["create-before:reset-password"] = false
	request()
	reset, n := lastLink()
	same(drain(), "create-before:reset-password", "create-after:reset-password")
	mu.Lock()
	created := records[len(records)-1]
	mu.Unlock()
	if n != 1 || created.UserID == "" || created.Identifier != "reset-password" || !created.ExpiresAt.After(time.Now()) {
		t.Fatal("the reset link's record was", created, n)
	}
	for _, field := range []string{created.ID, created.Identifier, created.UserID} {
		if strings.Contains(field, reset.Token) {
			t.Fatal("a verification record holds the mailed token")
		}
	}
	resetBody := `{"token":"` + reset.Token + `","newPassword":"` + sessionEndpointPassword + `"}`
	decline["delete-before:reset-password"] = true
	if code, _, _ := errorBody(t, c.post("/reset-password", resetBody, "", 400)); code != "INVALID_TOKEN" {
		t.Fatal("a declined reset answered", code)
	}
	same(drain(), "delete-before:reset-password")
	decline["delete-before:reset-password"] = false
	c.post("/reset-password", resetBody, "", 200)
	// Ada's sign-up and sign-in sessions are both revoked.
	same(drain(), "delete-before:reset-password", "account-update-before", "session-delete-before", "session-delete-before",
		"delete-after:reset-password", "account-update-after", "session-delete-after", "session-delete-after")
	if code, _, _ := errorBody(t, c.post("/reset-password", resetBody, "", 400)); code != "INVALID_TOKEN" {
		t.Fatal("a spent reset link answered", code)
	}
	same(drain())
	// An after hook's error fails the request; it is not read as a decline.
	fail["create-after:reset-password"] = authn.ErrSkipWrite
	c.post("/request-password-reset", `{"email":"ada@example.test","redirectTo":"/"}`, "", 500)
	delete(fail, "create-after:reset-password")
	drain()
	// A hook may not change the record.
	edit = true
	c.post("/request-password-reset", `{"email":"ada@example.test","redirectTo":"/"}`, "", 500)
	edit = false
	drain()
	// A direct call has no endpoint.
	if err := auth.RequestPasswordReset(context.Background(), "ada@example.test", "/"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	direct := contexts[len(contexts)-1]
	mu.Unlock()
	if direct != nil {
		t.Fatal("a direct reset request passed an endpoint")
	}
	drain()

	// Account deletion links.
	adaCookie, _ = c.signIn("ada@example.test")
	decline["create-before:delete-account"] = true
	_, before := lastLink()
	c.post("/delete-user", `{"callbackURL":"/"}`, adaCookie, 200)
	if _, n := lastLink(); n != before {
		t.Fatal("a declined deletion link was mailed")
	}
	same(drain(), "create-before:delete-account")
	decline["create-before:delete-account"] = false
	c.post("/delete-user", `{"callbackURL":"/"}`, adaCookie, 200)
	deletion, _ := lastLink()
	same(drain(), "create-before:delete-account", "create-after:delete-account")
	callback := "/delete-user/callback?" + url.Values{"token": {deletion.Token}, "callbackURL": {"/"}}.Encode()
	decline["delete-before:delete-account"] = true
	if code, _, _ := errorBody(t, c.get(callback, adaCookie, 404)); code != "INVALID_TOKEN" {
		t.Fatal("a declined deletion answered", code)
	}
	same(drain(), "delete-before:delete-account")
	decline["delete-before:delete-account"] = false
	// Another account's link is refused and spent without verification hooks.
	c.post("/delete-user", `{"callbackURL":"/"}`, adaCookie, 200)
	foreign, _ := lastLink()
	drain()
	if code, _, _ := errorBody(t, c.get("/delete-user/callback?"+url.Values{"token": {foreign.Token}, "callbackURL": {"/"}}.Encode(), boCookie, 404)); code != "INVALID_TOKEN" {
		t.Fatal("another account's link answered", code)
	}
	same(drain())
	if code, _, _ := errorBody(t, c.get("/delete-user/callback?"+url.Values{"token": {foreign.Token}, "callbackURL": {"/"}}.Encode(), adaCookie, 404)); code != "INVALID_TOKEN" {
		t.Fatal("a link spent by another account answered", code)
	}
	same(drain())
	// An after hook's error, even one wrapping ErrNotFound, fails the
	// request rather than reading as an invalid link.
	c.post("/delete-user", `{"callbackURL":"/"}`, adaCookie, 200)
	failing, _ := lastLink()
	drain()
	fail["delete-after:delete-account"] = fmt.Errorf("lookup: %w", authn.ErrNotFound)
	c.get("/delete-user/callback?"+url.Values{"token": {failing.Token}, "callbackURL": {"/"}}.Encode(), adaCookie, 500)
	delete(fail, "delete-after:delete-account")
	same(drain(), "delete-before:delete-account", "delete-after:delete-account")
	// The declined link still deletes the account.
	c.get(callback, adaCookie, 302)
	same(drain(), "delete-before:delete-account", "delete-after:delete-account", "session-delete-before", "user-delete-before", "session-delete-after")
}

// New refuses verification hooks that an enabled feature would bypass: the
// plugins that keep codes in their own stores, and delete hooks on a store
// that cannot read a deletion link or an OAuth flow before spending it.
func TestDatabaseVerificationHooksRefuseBypassingFeatures(t *testing.T) {
	observe := authn.OperationHooks[authn.VerificationRecord]{After: func(context.Context, authn.VerificationRecord, *authn.HookContext) error { return nil }}
	base := func() authn.Options {
		o := authn.Options{BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), EmailAndPassword: true}
		o.DatabaseHooks.Verification.Create = observe
		return o
	}
	if _, err := authn.New(base()); err != nil {
		t.Fatal("verification hooks were refused for the core flows:", err)
	}
	magic, err := authn.NewMagicLink(authn.MagicLinkOptions{Send: func(context.Context, authn.MagicLinkMessage) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	withMagic := base()
	withMagic.Plugins = []authn.Plugin{magic}
	if _, err := authn.New(withMagic); err == nil || !strings.Contains(err.Error(), "magic-link") {
		t.Fatal("verification hooks were accepted with magic links:", err)
	}
	// A store that cannot read a deletion link before spending it.
	deletions := base()
	deletions.DatabaseHooks.Verification.Delete = observe
	deletions.DeleteUserEnabled = true
	deletions.EmailAndPassword = false
	plain := memory.New()
	deletions.Store = struct {
		authn.Store
		authn.AccountLifecycleStore
		authn.DeletionTokenStore
	}{plain, plain, plain}
	if _, err := authn.New(deletions); err == nil || !strings.Contains(err.Error(), "FindDeletionToken") {
		t.Fatal("verification delete hooks were accepted without FindDeletionToken:", err)
	}
	deletions.Store = memory.New()
	if _, err := authn.New(deletions); err != nil {
		t.Fatal("verification delete hooks were refused with the memory store:", err)
	}
}
