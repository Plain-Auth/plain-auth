package goapi_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
)

// verificationHost is an auth instance with a recorded verification sender.
type verificationHost struct {
	sessionClient
	store *sqlite.Store
	mu    sync.Mutex
	links []authn.MailLink
}

func newVerificationHost(t *testing.T, opts authn.Options, send bool) *verificationHost {
	t.Helper()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	h := &verificationHost{store: store}
	if send {
		opts.SendVerificationEmail = func(_ context.Context, m authn.MailLink) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			m.Request = nil
			h.links = append(h.links, m)
			return nil
		}
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

func (h *verificationHost) mails() []authn.MailLink {
	h.mu.Lock()
	defer h.mu.Unlock()
	links := h.links
	h.links = nil
	return links
}

// link requests a verification mail for an unverified address and returns
// its URL path and query.
func (h *verificationHost) link(email string) string {
	h.t.Helper()
	statusBody(h.t, h.post("/send-verification-email", `{"email":"`+email+`"}`, "", 200))
	links := h.mails()
	if len(links) != 1 {
		h.t.Fatal("send-verification-email sent", len(links), "mails")
	}
	u, err := url.Parse(links[0].URL)
	if err != nil {
		h.t.Fatal(err)
	}
	return u.Path + "?" + u.RawQuery
}

// tokenOnly drops a mailed link's callback, so the link answers in JSON.
func tokenOnly(link string) string {
	u, _ := url.Parse(link)
	return u.Path + "?token=" + url.QueryEscape(u.Query().Get("token"))
}

// tokenLifetime returns exp minus iat of a verification link's token.
func tokenLifetime(t *testing.T, link string) int64 {
	t.Helper()
	u, _ := url.Parse(link)
	parts := strings.Split(u.Query().Get("token"), ".")
	if len(parts) != 3 {
		t.Fatal("the link carries no JWT:", link)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct{ Iat, Exp int64 }
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims.Exp - claims.Iat
}

// send-verification-email answers an anonymous request the same way for
// any address after at least half a second, mails only an unverified one,
// and refuses a signed-in caller's other or verified address.
func TestSendVerificationEmailContract(t *testing.T) {
	h := newVerificationHost(t, authn.Options{}, true)
	h.post("/sign-up/email", `{"name":"Ada","email":"ada@example.test","password":"`+sessionEndpointPassword+`"}`, "", 200)
	h.post("/sign-up/email", `{"name":"Bob","email":"bob@example.test","password":"`+sessionEndpointPassword+`"}`, "", 200)
	bob, err := h.store.FindAccountUser(t.Context(), "bob@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.VerifyAccountEmail(t.Context(), bob.ID, "bob@example.test", time.Now()); err != nil {
		t.Fatal(err)
	}
	h.mails()
	for email, mails := range map[string]int{"nobody@example.test": 0, "bob@example.test": 0, "ADA@example.test": 1} {
		start := time.Now()
		statusBody(t, h.post("/send-verification-email", `{"email":"`+email+`"}`, "", 200))
		if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
			t.Fatal("an anonymous request for", email, "answered after", elapsed)
		}
		if got := h.mails(); len(got) != mails || mails == 1 && (got[0].User.Email != "ada@example.test" || !strings.Contains(got[0].URL, "callbackURL=%2F")) {
			t.Fatalf("a request for %s mailed %+v", email, got)
		}
	}
	ada, _ := h.signIn("ada@example.test")
	if code, message, _ := errorBody(t, h.post("/send-verification-email", `{"email":"bob@example.test"}`, ada, 400)); code != "EMAIL_MISMATCH" || message != "Email mismatch" {
		t.Fatal("another address answered", code, message)
	}
	verified, _ := h.signIn("bob@example.test")
	if code, message, _ := errorBody(t, h.post("/send-verification-email", `{"email":"bob@example.test"}`, verified, 400)); code != "EMAIL_ALREADY_VERIFIED" || message != "Email is already verified" {
		t.Fatal("a verified address answered", code, message)
	}
	for body, message := range map[string]string{`{}`: "[body.email] Invalid input: expected string, received undefined", `{"email":"nope"}`: "[body.email] Invalid email address"} {
		if code, got, _ := errorBody(t, h.post("/send-verification-email", body, "", 400)); code != "VALIDATION_ERROR" || got != message {
			t.Fatal(body, "answered", code, got)
		}
	}
	quiet := newVerificationHost(t, authn.Options{}, false)
	if code, message, _ := errorBody(t, quiet.post("/send-verification-email", `{"email":"ada@example.test"}`, "", 400)); code != "VERIFICATION_EMAIL_NOT_ENABLED" || message != "Verification email isn't enabled" {
		t.Fatal("without a sender the request answered", code, message)
	}
}

// verify-email validates its query before the callback, treats an empty
// token as an invalid one, reports expired, invalid and orphaned links with
// the reference's codes (redirected when there is a callback), and without
// AutoSignInAfterVerification verifies the address without a session.
func TestVerifyEmailContract(t *testing.T) {
	h := newVerificationHost(t, authn.Options{DeleteUserEnabled: true}, true)
	h.post("/sign-up/email", `{"name":"Ada","email":"ada@example.test","password":"`+sessionEndpointPassword+`"}`, "", 200)
	h.mails()
	link := h.link("ada@example.test")
	if lifetime := tokenLifetime(t, link); lifetime != 3600 {
		t.Fatal("a verification link lasts", lifetime, "seconds by default")
	}
	for query, message := range map[string]string{
		"?callbackURL=https://evil.example":      "[query.token] Invalid input: expected string, received undefined",
		"?token=a&token=b":                       "[query.token] Invalid input: expected string, received array",
		"?token=a&callbackURL=/a&callbackURL=/b": "[query.callbackURL] Invalid input: expected string, received array",
	} {
		if code, got, _ := errorBody(t, h.get("/verify-email"+query, "", 400)); code != "VALIDATION_ERROR" || got != message {
			t.Fatalf("query %q answered %s %s", query, code, got)
		}
	}
	for _, token := range []string{"", "garbage"} {
		if code, _, _ := errorBody(t, h.get("/verify-email?token="+token, "", 401)); code != "INVALID_TOKEN" {
			t.Fatalf("token %q answered %s", token, code)
		}
		if to := h.get("/verify-email?token="+token+"&callbackURL=/done", "", 302).Header.Get("Location"); to != "/done?error=INVALID_TOKEN" {
			t.Fatalf("token %q redirected to %s", token, to)
		}
	}
	// The mailed link carries callbackURL=/ and redirects there; without
	// the callback the answer is JSON. Neither starts a session.
	r := h.get(tokenOnly(link), "", 200)
	var out map[string]any
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil || out["status"] != true || out["user"] != nil || len(r.Header.Values("Set-Cookie")) != 0 {
		t.Fatal("verifying without automatic sign-in answered", out, r.Header.Values("Set-Cookie"), err)
	}
	if r := h.get(link, "", 302); r.Header.Get("Location") != "/" || len(r.Header.Values("Set-Cookie")) != 0 {
		t.Fatal("the mailed link redirected to", r.Header.Get("Location"), "with cookies", r.Header.Values("Set-Cookie"))
	}
	if u, err := h.store.FindAccountUser(t.Context(), "ada@example.test"); err != nil || !u.EmailVerified {
		t.Fatal("the link did not verify the address", err)
	}

	// A link whose account was deleted reports the missing user.
	h.post("/sign-up/email", `{"name":"Bob","email":"bob@example.test","password":"`+sessionEndpointPassword+`"}`, "", 200)
	h.mails()
	orphan := h.link("bob@example.test")
	bob, _ := h.signIn("bob@example.test")
	h.post("/delete-user", `{"password":"`+sessionEndpointPassword+`"}`, bob, 200)
	if code, message, _ := errorBody(t, h.get(tokenOnly(orphan), "", 401)); code != "USER_NOT_FOUND" || message != "User not found" {
		t.Fatal("a link for a deleted account answered", code, message)
	}
	if to := h.get(orphan, "", 302).Header.Get("Location"); to != "/?error=USER_NOT_FOUND" {
		t.Fatal("a mailed link for a deleted account redirected to", to)
	}

	// A configured lifetime applies, and an expired link says so.
	short := newVerificationHost(t, authn.Options{EmailVerificationTokenTTL: time.Second}, true)
	short.post("/sign-up/email", `{"name":"Ada","email":"ada@example.test","password":"`+sessionEndpointPassword+`"}`, "", 200)
	short.mails()
	expiring := short.link("ada@example.test")
	if lifetime := tokenLifetime(t, expiring); lifetime != 1 {
		t.Fatal("a one-second link lasts", lifetime, "seconds")
	}
	time.Sleep(2100 * time.Millisecond)
	if code, _, _ := errorBody(t, short.get(tokenOnly(expiring), "", 401)); code != "TOKEN_EXPIRED" {
		t.Fatal("an expired link answered", code)
	}
	if to, _ := url.Parse(short.get(tokenOnly(expiring)+"&callbackURL=/done", "", 302).Header.Get("Location")); to.Path != "/done" || to.Query().Get("error") != "TOKEN_EXPIRED" {
		t.Fatal("an expired link redirected to", to)
	}
}

// With a verification mail on sign-up and automatic sign-in, the mail goes
// out before the session's after hooks run, so a failing session hook still
// leaves one mail for the stored account.
func TestSignUpVerificationMailBeforeSessionHooks(t *testing.T) {
	on := true
	h := newVerificationHost(t, authn.Options{SendVerificationOnSignUp: &on, DatabaseHooks: authn.DatabaseHooks{Session: authn.ModelHooks[authn.SessionRecord]{Create: authn.OperationHooks[authn.SessionRecord]{
		After: func(context.Context, authn.SessionRecord, *authn.HookContext) error {
			return errors.New("session hook failed")
		},
	}}}}, true)
	h.post("/sign-up/email", `{"name":"Ada","email":"ada@example.test","password":"`+sessionEndpointPassword+`"}`, "", 500)
	if mails := h.mails(); len(mails) != 1 || mails[0].User.Email != "ada@example.test" {
		t.Fatalf("a sign-up whose session hook failed mailed %+v", mails)
	}
	if _, err := h.store.FindAccountUser(t.Context(), "ada@example.test"); err != nil {
		t.Fatal("the account was not kept:", err)
	}

	// A sign-up whose user hook fails sends no mail.
	failed := newVerificationHost(t, authn.Options{SendVerificationOnSignUp: &on, DatabaseHooks: authn.DatabaseHooks{User: authn.ModelHooks[authn.UserRecord]{Create: authn.OperationHooks[authn.UserRecord]{
		After: func(context.Context, authn.UserRecord, *authn.HookContext) error {
			return errors.New("user hook failed")
		},
	}}}}, true)
	failed.post("/sign-up/email", `{"name":"Ada","email":"ada@example.test","password":"`+sessionEndpointPassword+`"}`, "", 500)
	if mails := failed.mails(); len(mails) != 0 {
		t.Fatalf("a failed sign-up mailed %+v", mails)
	}
}
