package goapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

// deletionHost is an instance with recorded deletion mail and counted
// deletion hooks.
type deletionHost struct {
	sessionClient
	store   *sqlite.Store
	mu      sync.Mutex
	links   []authn.MailLink
	before  atomic.Int32
	unlinks atomic.Int32
}

// newDeletionHost adds an ID-token provider when social is set, or else a
// counted account delete hook; the two cannot be combined yet.
func newDeletionHost(t *testing.T, opts authn.Options, social bool) *deletionHost {
	t.Helper()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	h := &deletionHost{store: store}
	opts.SendDeleteAccountVerification = func(_ context.Context, m authn.MailLink) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		m.Request = nil
		h.links = append(h.links, m)
		return nil
	}
	opts.BeforeDeleteUser = func(context.Context, authn.User, *http.Request) error {
		h.before.Add(1)
		return nil
	}
	if !social {
		opts.DatabaseHooks.Account.Delete.Before = func(context.Context, *authn.LinkedAccount, *authn.HookContext) error {
			h.unlinks.Add(1)
			return nil
		}
	} else {
		opts.SocialProviders = map[string]authn.OAuthProvider{"work": {Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token"}},
			Resolve: func(context.Context, *oauth2.Token, string) (authn.OAuthProfile, error) {
				return authn.OAuthProfile{}, errors.New("unused")
			},
			VerifyIDToken: func(_ context.Context, raw, _ string) (authn.OAuthProfile, time.Time, error) {
				return authn.OAuthProfile{Subject: raw, Email: raw + "@example.test", EmailVerified: true, Name: "Social"}, time.Now().Add(time.Hour), nil
			}}}
	}
	off := false
	opts.Store, opts.Secret, opts.BaseURL, opts.EmailAndPassword, opts.RateLimit = store, strings.Repeat("s", 32), "https://auth.example", true, &off
	auth, err := authn.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	h.sessionClient = sessionClient{t, auth}
	return h
}

func (h *deletionHost) signUp(email string) string {
	h.t.Helper()
	h.post("/sign-up/email", `{"name":"Person","email":"`+email+`","password":"`+sessionEndpointPassword+`"}`, "", 200)
	cookie, _ := h.signIn(email)
	return cookie
}

// deletionLink requests a deletion mail and returns the link's path and query.
func (h *deletionHost) deletionLink(cookie string) string {
	h.t.Helper()
	h.post("/delete-user", `{"callbackURL":"/goodbye"}`, cookie, 200)
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.links) == 0 {
		h.t.Fatal("no deletion mail was sent")
	}
	u, err := url.Parse(h.links[len(h.links)-1].URL)
	if err != nil {
		h.t.Fatal(err)
	}
	return u.RequestURI()
}

func (h *deletionHost) exists(email string) bool {
	_, err := h.store.FindAccountUser(h.t.Context(), email)
	return err == nil
}

// A deletion token is spent before any deletion hook runs: an expired one,
// or one opened by another account, answers INVALID_TOKEN without running
// BeforeDeleteUser, and a spent one stays spent. An anonymous callback
// answers FAILED_TO_GET_USER_INFO and leaves the token usable.
func TestDeletionTokenSpentFirst(t *testing.T) {
	h := newDeletionHost(t, authn.Options{DeleteUserEnabled: true, DeleteTokenTTL: time.Second}, false)
	ada := h.signUp("ada@example.test")
	bob := h.signUp("bob@example.test")
	expired := h.deletionLink(ada)
	time.Sleep(2100 * time.Millisecond)
	if code, _, _ := errorBody(t, h.get(expired, ada, 404)); code != "INVALID_TOKEN" {
		t.Fatal("an expired deletion link answered", code)
	}
	if h.before.Load() != 0 || !h.exists("ada@example.test") {
		t.Fatal("an expired deletion link ran BeforeDeleteUser or deleted the account")
	}

	long := newDeletionHost(t, authn.Options{DeleteUserEnabled: true}, false)
	ada, bob = long.signUp("ada@example.test"), long.signUp("bob@example.test")
	link := long.deletionLink(ada)
	if code, message, _ := errorBody(t, long.get(link, "", 404)); code != "FAILED_TO_GET_USER_INFO" || message != "Failed to get user info" {
		t.Fatal("an anonymous deletion callback answered", code, message)
	}
	if code, _, _ := errorBody(t, long.get(link, bob, 404)); code != "INVALID_TOKEN" {
		t.Fatal("another account's deletion callback answered", code)
	}
	if long.before.Load() != 0 || !long.exists("ada@example.test") || !long.exists("bob@example.test") {
		t.Fatal("a refused deletion ran BeforeDeleteUser or deleted an account")
	}
	if code, _, _ := errorBody(t, long.get(link, ada, 404)); code != "INVALID_TOKEN" {
		t.Fatal("a spent deletion link answered", code)
	}
	if to := long.get(long.deletionLink(ada), ada, 302).Header.Get("Location"); to != "/goodbye" || long.before.Load() != 1 || long.exists("ada@example.test") {
		t.Fatal("a fresh deletion link redirected to", to, "and deleted", !long.exists("ada@example.test"))
	}

	// The callback needs a token; an empty one is refused, never treated as
	// a deletion without a token.
	if code, message, _ := errorBody(t, long.get("/delete-user/callback?callbackURL=/goodbye", bob, 400)); code != "VALIDATION_ERROR" || message != "[query.token] Invalid input: expected string, received undefined" {
		t.Fatal("a callback without a token answered", code, message)
	}
	if code, _, _ := errorBody(t, long.get("/delete-user/callback?token=", bob, 404)); code != "INVALID_TOKEN" {
		t.Fatal("an empty token answered", code)
	}
	if code, _, _ := errorBody(t, long.get("/delete-user/callback?token=", "", 404)); code != "FAILED_TO_GET_USER_INFO" {
		t.Fatal("an anonymous empty token answered", code)
	}
	if !long.exists("bob@example.test") {
		t.Fatal("an empty token deleted the account")
	}

	// The callback refuses an untrusted callback, and without one answers
	// JSON; the mailed token also works posted to delete-user.
	link = long.deletionLink(bob)
	token := strings.TrimPrefix(link[strings.Index(link, "token="):], "token=")
	if code, _, _ := errorBody(t, long.get("/delete-user/callback?token="+token+"&callbackURL=https://evil.example", bob, 403)); code != "INVALID_CALLBACK_URL" || !long.exists("bob@example.test") {
		t.Fatal("an untrusted deletion callback answered", code)
	}
	r := long.get("/delete-user/callback?token="+token, bob, 200)
	var out map[string]any
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil || out["success"] != true || out["message"] != "User deleted" || long.exists("bob@example.test") {
		t.Fatal("a callback without a callbackURL answered", out, err)
	}
	carl := long.signUp("carl@example.test")
	link = long.deletionLink(carl)
	token = strings.TrimPrefix(link[strings.Index(link, "token="):], "token=")
	r = long.post("/delete-user", `{"token":"`+token+`"}`, carl, 200)
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil || out["message"] != "User deleted" || long.exists("carl@example.test") {
		t.Fatal("deleting with the mailed token answered", out, err)
	}

	disabled := newDeletionHost(t, authn.Options{}, false)
	cookie := disabled.signUp("ada@example.test")
	for _, who := range []string{"", cookie} {
		if code, _, _ := errorBody(t, disabled.post("/delete-user", `{}`, who, 404)); code != "NOT_FOUND" {
			t.Fatal("a disabled delete-user answered", code)
		}
	}
}

// unlink-account answers ACCOUNT_NOT_FOUND for another user's or an
// unknown account, removes one of the caller's own, and refuses the last
// one before any account hook runs.
func TestUnlinkAccountContract(t *testing.T) {
	h := newDeletionHost(t, authn.Options{}, true)
	ada := h.signUp("ada@example.test")
	h.post("/link-social", `{"provider":"work","idToken":{"token":"ada","nonce":"n"}}`, ada, 200)
	bob := h.signUp("bob@example.test")
	accounts := func(cookie string) map[string]string { return accountsOf(t, h.sessionClient, cookie) }
	adas, bobs := accounts(ada), accounts(bob)
	if len(adas) != 2 || adas["work"] == "" || bobs["credential"] == "" {
		t.Fatal("unexpected accounts", adas, bobs)
	}
	for _, id := range []string{bobs["credential"], "unknown"} {
		if code, message, _ := errorBody(t, h.post("/unlink-account", `{"accountId":"`+id+`"}`, ada, 400)); code != "ACCOUNT_NOT_FOUND" || message != "Account not found" {
			t.Fatal("unlinking", id, "answered", code, message)
		}
	}
	if len(accounts(ada)) != 2 || len(accounts(bob)) != 1 {
		t.Fatal("a refused unlink removed an account")
	}
	statusBody(t, h.post("/unlink-account", `{"accountId":"`+adas["work"]+`"}`, ada, 200))
	if len(accounts(ada)) != 1 {
		t.Fatal("unlinking the provider account did not remove it")
	}
	if code, message, _ := errorBody(t, h.post("/unlink-account", `{"accountId":"`+adas["credential"]+`"}`, ada, 400)); code != "FAILED_TO_UNLINK_LAST_ACCOUNT" || message != "You can't unlink your last account" {
		t.Fatal("unlinking the last account answered", code, message)
	}

	// With account delete hooks, the last account is refused before they run.
	hooked := newDeletionHost(t, authn.Options{}, false)
	cookie := hooked.signUp("ada@example.test")
	id := accountsOf(t, hooked.sessionClient, cookie)["credential"]
	if code, _, _ := errorBody(t, hooked.post("/unlink-account", `{"accountId":"`+id+`"}`, cookie, 400)); code != "FAILED_TO_UNLINK_LAST_ACCOUNT" || hooked.unlinks.Load() != 0 {
		t.Fatal("the last-account refusal answered", code, "after", hooked.unlinks.Load(), "account delete hooks")
	}
}

// accountsOf lists the caller's account IDs by provider.
func accountsOf(t *testing.T, c sessionClient, cookie string) map[string]string {
	t.Helper()
	var list []struct{ ID, ProviderID string }
	if err := json.NewDecoder(c.get("/list-accounts", cookie, 200).Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, a := range list {
		ids[a.ProviderID] = a.ID
	}
	return ids
}
