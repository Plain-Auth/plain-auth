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
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/plugins/passkey"
	"github.com/Plain-Org/plain-auth/plugins/siwe"
	"github.com/Plain-Org/plain-auth/schema"
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

// New refuses verification hooks that an enabled feature would bypass: SSO,
// which keeps its records in its store, two-factor on a store that cannot
// report the rows its calls lock, authorization codes on a store whose code
// methods do not ask the request's verification gate, update before hooks with email and
// phone codes and two-factor, which count a wrong guess as they judge it, and
// delete hooks on a store that cannot read a deletion link, an OAuth flow, a
// magic link, a one-time token, an email code, a passkey challenge or a
// wallet nonce before spending it, or cannot report what it did to a phone
// code, and create before hooks with custom wallet nonces on a store that
// cannot keep a declined one in the nonce history.
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
	codes, err := authn.NewEmailOTP(authn.EmailOTPOptions{Send: func(context.Context, authn.EmailOTPMessage) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	withCodes := base()
	withCodes.Plugins = []authn.Plugin{codes}
	withCodes.DatabaseHooks.Verification.Update = observe
	withCodes.DatabaseHooks.Verification.Delete = observe
	if _, err := authn.New(withCodes); err != nil {
		t.Fatal("verification hooks were refused with email codes:", err)
	}
	withCodes.DatabaseHooks.Verification.Update.Before = func(context.Context, *authn.VerificationRecord, *authn.HookContext) error { return nil }
	if _, err := authn.New(withCodes); err == nil || !strings.Contains(err.Error(), "update before hooks") || !strings.Contains(err.Error(), "email-otp") {
		t.Fatal("verification update before hooks were accepted with email codes:", err)
	}
	// Guesses need a store that reads a code before judging it; sends do not.
	mailboxes := memory.New()
	withCodes.Store = struct {
		authn.Store
		authn.EmailOTPStore
	}{mailboxes, mailboxes}
	for _, hooks := range []authn.ModelHooks[authn.VerificationRecord]{{Delete: observe}, {Update: observe}} {
		withCodes.DatabaseHooks.Verification = hooks
		if _, err := authn.New(withCodes); err == nil || !strings.Contains(err.Error(), "FindEmailOTP") {
			t.Fatal("verification hooks for guesses were accepted without FindEmailOTP:", err)
		}
	}
	withCodes.DatabaseHooks.Verification = authn.ModelHooks[authn.VerificationRecord]{Create: observe}
	if _, err := authn.New(withCodes); err != nil {
		t.Fatal("verification create hooks were refused on a store without FindEmailOTP:", err)
	}
	// Phone codes run them too, on a store that reports what it did to a code.
	phone, err := authn.NewPhoneNumber(authn.PhoneNumberOptions{SendOTP: func(context.Context, authn.PhoneOTPMessage) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	withPhone := base()
	withPhone.Plugins = []authn.Plugin{phone}
	withPhone.DatabaseHooks.Verification.Update = observe
	withPhone.DatabaseHooks.Verification.Delete = observe
	if _, err := authn.New(withPhone); err != nil {
		t.Fatal("verification hooks were refused with phone codes:", err)
	}
	withPhone.DatabaseHooks.Verification.Update.Before = func(context.Context, *authn.VerificationRecord, *authn.HookContext) error { return nil }
	if _, err := authn.New(withPhone); err == nil || !strings.Contains(err.Error(), "update before hooks") || !strings.Contains(err.Error(), "phone-number") {
		t.Fatal("verification update before hooks were accepted with phone codes:", err)
	}
	numbers := memory.New()
	withPhone.Store = struct {
		authn.Store
		authn.PhoneAccountStore
	}{numbers, numbers}
	for _, hooks := range []authn.ModelHooks[authn.VerificationRecord]{{Delete: observe}, {Update: observe}} {
		withPhone.DatabaseHooks.Verification = hooks
		if _, err := authn.New(withPhone); err == nil || !strings.Contains(err.Error(), "ReportsPhoneOTPDecisions") {
			t.Fatal("verification hooks for phone guesses were accepted without ReportsPhoneOTPDecisions:", err)
		}
	}
	withPhone.DatabaseHooks.Verification = authn.ModelHooks[authn.VerificationRecord]{Create: observe}
	if _, err := authn.New(withPhone); err != nil {
		t.Fatal("verification create hooks were refused on a store without ReportsPhoneOTPDecisions:", err)
	}
	// Two-factor records run them on a store that reports the rows its calls
	// lock and stores new ones under the IDs the Auth gives, which creates
	// need too. A count has no before hook.
	factors := base()
	factors.Plugins = []authn.Plugin{authn.NewTwoFactor(authn.TwoFactorOptions{})}
	if _, err := authn.New(factors); err == nil || !strings.Contains(err.Error(), "ReportsFactorRecords") {
		t.Fatal("verification hooks were accepted with two-factor on the memory store:", err)
	}
	accounts, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"two-factor"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	factors.Store = accounts
	factors.DatabaseHooks.Verification.Update.After = observe.After
	factors.DatabaseHooks.Verification.Delete = observe
	if _, err := authn.New(factors); err != nil {
		t.Fatal("verification hooks were refused with two-factor on SQLite:", err)
	}
	factors.DatabaseHooks.Verification.Update.Before = func(context.Context, *authn.VerificationRecord, *authn.HookContext) error { return nil }
	if _, err := authn.New(factors); err == nil || !strings.Contains(err.Error(), "update before hooks") || !strings.Contains(err.Error(), "two-factor") {
		t.Fatal("verification update before hooks were accepted with two-factor:", err)
	}
	type factorStore = authn.TwoFactorStore
	factors.Store = struct {
		authn.Store
		factorStore
	}{accounts, accounts}
	factors.DatabaseHooks.Verification = authn.ModelHooks[authn.VerificationRecord]{Create: observe}
	if _, err := authn.New(factors); err == nil || !strings.Contains(err.Error(), "ReportsFactorRecords") {
		t.Fatal("verification create hooks were accepted with two-factor without ReportsFactorRecords:", err)
	}
	// SSO's records stay in its store.
	refused := base()
	refused.Plugins = []authn.Plugin{{ID: "sso"}}
	if _, err := authn.New(refused); err == nil || !strings.Contains(err.Error(), "sso") {
		t.Fatal("verification hooks were accepted with sso:", err)
	}
	// Authorization codes run them on a store whose code methods ask the
	// request's gate; the memory store keeps no codes and gets the plugin's
	// own refusal.
	issuer := func(grants ...string) authn.Plugin {
		t.Helper()
		p, err := oauthprovider.New(oauthprovider.Options{GrantTypes: grants})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	issuing := base()
	issuing.EmailAndPassword = false
	issuing.Plugins = []authn.Plugin{issuer()}
	if _, err := authn.New(issuing); err == nil || !strings.Contains(err.Error(), "ConsentStore") {
		t.Fatal("verification hooks with the OAuth provider on the memory store answered", err)
	}
	clients, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"oauth-provider"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer clients.Close()
	issuing.Store = clients
	issuing.DatabaseHooks.Verification.Update = observe
	issuing.DatabaseHooks.Verification.Delete = observe
	if _, err := authn.New(issuing); err != nil {
		t.Fatal("verification hooks were refused with the OAuth provider on SQLite:", err)
	}
	// A store whose code methods do not ask the gate is refused for codes,
	// and not for the other grants or consent management alone.
	type codeStore = oauthprovider.AuthorizationCodeStore
	issuing.Store = struct {
		authn.Store
		codeStore
	}{clients, clients}
	if _, err := authn.New(issuing); err == nil || !strings.Contains(err.Error(), "GatesAuthorizationCodes") {
		t.Fatal("verification hooks were accepted with authorization codes on a store that does not ask the gate:", err)
	}
	for _, p := range []authn.Plugin{issuer("client_credentials"), oauthprovider.ConsentManagement(oauthprovider.ConsentOptions{Scopes: []string{"openid"}})} {
		issuing.Plugins = []authn.Plugin{p}
		if _, err := authn.New(issuing); err != nil && strings.Contains(err.Error(), "GatesAuthorizationCodes") {
			t.Fatal("a configuration without authorization codes was refused for them:", err)
		}
	}
	// Passkey challenges run them, and delete hooks need a store that reads a
	// challenge before spending it.
	keys, err := passkey.New(passkey.Options{RPID: "auth.example", RPName: "Example", Origins: []string{"https://auth.example"}})
	if err != nil {
		t.Fatal(err)
	}
	withKeys := base()
	withKeys.EmailAndPassword = false
	withKeys.Plugins = []authn.Plugin{keys}
	withKeys.DatabaseHooks.Verification.Delete = observe
	if _, err := authn.New(withKeys); err == nil || !strings.Contains(err.Error(), "FindPasskeyChallenge") {
		t.Fatal("verification delete hooks were accepted with passkeys on the memory store:", err)
	}
	passkeys, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"passkey"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer passkeys.Close()
	withKeys.Store = passkeys
	withKeys.DatabaseHooks.Verification.Update = observe
	if _, err := authn.New(withKeys); err != nil {
		t.Fatal("verification hooks were refused with passkeys on SQLite:", err)
	}
	type challenges = passkey.Store
	withKeys.Store = struct {
		authn.Store
		challenges
	}{passkeys, passkeys}
	if _, err := authn.New(withKeys); err == nil || !strings.Contains(err.Error(), "FindPasskeyChallenge") {
		t.Fatal("verification delete hooks were accepted with passkeys without FindPasskeyChallenge:", err)
	}
	withKeys.DatabaseHooks.Verification = authn.ModelHooks[authn.VerificationRecord]{Create: observe}
	if _, err := authn.New(withKeys); err != nil {
		t.Fatal("verification create hooks were refused with passkeys without FindPasskeyChallenge:", err)
	}
	// Wallet nonces run them too. Delete hooks need a store that reads a nonce
	// before spending it, and create before hooks with a custom generator one
	// that keeps a declined nonce in the history.
	wallets, err := siwe.New(siwe.Options{Domain: "auth.example"})
	if err != nil {
		t.Fatal(err)
	}
	withWallets := base()
	withWallets.EmailAndPassword = false
	withWallets.Plugins = []authn.Plugin{wallets}
	withWallets.DatabaseHooks.Verification.Delete = observe
	if _, err := authn.New(withWallets); err == nil || !strings.Contains(err.Error(), "FindWalletNonce") {
		t.Fatal("verification delete hooks were accepted with wallets on the memory store:", err)
	}
	nonces, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"siwe"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer nonces.Close()
	screening := authn.OperationHooks[authn.VerificationRecord]{Before: func(context.Context, *authn.VerificationRecord, *authn.HookContext) error { return nil }}
	withWallets.Store = nonces
	withWallets.DatabaseHooks.Verification = authn.ModelHooks[authn.VerificationRecord]{Create: screening, Update: observe, Delete: observe}
	if _, err := authn.New(withWallets); err != nil {
		t.Fatal("verification hooks were refused with wallets on SQLite:", err)
	}
	type walletStore = siwe.Store
	type nonceHistory = siwe.CustomNonceStore
	withWallets.Store = struct {
		authn.Store
		walletStore
	}{nonces, nonces}
	if _, err := authn.New(withWallets); err == nil || !strings.Contains(err.Error(), "FindWalletNonce") {
		t.Fatal("verification delete hooks were accepted with wallets without FindWalletNonce:", err)
	}
	custom, err := siwe.New(siwe.Options{Domain: "auth.example", GetNonce: func(context.Context) (string, error) { return "Nonce" + strings.Repeat("x", 8), nil }})
	if err != nil {
		t.Fatal(err)
	}
	withWallets.Plugins = []authn.Plugin{custom}
	withWallets.Store = struct {
		authn.Store
		walletStore
		nonceHistory
	}{nonces, nonces, nonces}
	withWallets.DatabaseHooks.Verification = authn.ModelHooks[authn.VerificationRecord]{Create: screening}
	if _, err := authn.New(withWallets); err == nil || !strings.Contains(err.Error(), "RecordWalletNonce") {
		t.Fatal("verification create before hooks were accepted with custom wallet nonces without RecordWalletNonce:", err)
	}
	withWallets.DatabaseHooks.Verification = authn.ModelHooks[authn.VerificationRecord]{Create: observe}
	if _, err := authn.New(withWallets); err != nil {
		t.Fatal("verification create after hooks were refused with custom wallet nonces without RecordWalletNonce:", err)
	}
	withWallets.Store = nonces
	withWallets.DatabaseHooks.Verification = authn.ModelHooks[authn.VerificationRecord]{Create: screening, Delete: observe}
	if _, err := authn.New(withWallets); err != nil {
		t.Fatal("verification hooks were refused with custom wallet nonces on SQLite:", err)
	}
	// Magic links and one-time tokens run them, and delete hooks need a store
	// that reads a link or token before spending it.
	magic, err := authn.NewMagicLink(authn.MagicLinkOptions{Send: func(context.Context, authn.MagicLinkMessage) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	transfers, err := authn.NewOneTimeToken(authn.OneTimeTokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	links := base()
	links.Plugins = []authn.Plugin{magic, transfers}
	links.DatabaseHooks.Verification.Delete = observe
	if _, err := authn.New(links); err != nil {
		t.Fatal("verification hooks were refused with magic links and one-time tokens:", err)
	}
	links.EmailAndPassword = false
	shared := memory.New()
	for _, tc := range []struct {
		plugin authn.Plugin
		store  authn.Store
		finder string
	}{
		{magic, struct {
			authn.Store
			authn.MagicLinkStore
		}{shared, shared}, "FindMagicLink"},
		{transfers, struct {
			authn.Store
			authn.OneTimeTokenStore
		}{shared, shared}, "FindOneTimeToken"},
	} {
		links.Plugins, links.Store = []authn.Plugin{tc.plugin}, tc.store
		links.DatabaseHooks.Verification.Delete = observe
		if _, err := authn.New(links); err == nil || !strings.Contains(err.Error(), tc.finder) {
			t.Fatal("verification delete hooks were accepted without", tc.finder, err)
		}
		links.DatabaseHooks.Verification.Delete = authn.OperationHooks[authn.VerificationRecord]{}
		if _, err := authn.New(links); err != nil {
			t.Fatal("create hooks were refused on a store without", tc.finder, err)
		}
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
