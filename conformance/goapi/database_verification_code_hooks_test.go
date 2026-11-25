package goapi_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// codeHost serves email codes with recorded verification hooks. Its codes
// read "code-<n>", so a record that held one would show it.
type codeHost struct {
	t      *testing.T
	auth   *authn.Auth
	mu     sync.Mutex
	mail   []authn.EmailOTPMessage
	resets []string
	hashed atomic.Int32
}

func newCodeHost(t *testing.T, store authn.Store, events *verificationEvents, otp authn.EmailOTPOptions, edit func(*authn.Options)) *codeHost {
	t.Helper()
	h := &codeHost{t: t}
	var n atomic.Int32
	otp.GenerateOTP = func(context.Context, string, authn.EmailOTPPurpose) (string, error) {
		return fmt.Sprintf("code-%d", n.Add(1)), nil
	}
	otp.Send = func(_ context.Context, m authn.EmailOTPMessage) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.mail = append(h.mail, m)
		return nil
	}
	codes, err := authn.NewEmailOTP(otp)
	if err != nil {
		t.Fatal(err)
	}
	off := false
	opts := authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		Plugins: []authn.Plugin{codes}, DatabaseHooks: events.hooks(),
		PasswordHash: func(ctx context.Context, password string) (string, error) {
			h.hashed.Add(1)
			return authn.HashPassword(ctx, password)
		},
		PasswordVerify: authn.VerifyPasswordHash,
		OnPasswordReset: func(context.Context, authn.User, *http.Request) error {
			return events.note("on-password-reset", nil, nil)
		},
		SendResetPassword: func(_ context.Context, m authn.MailLink) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.resets = append(h.resets, m.Token)
			return nil
		},
	}
	if edit != nil {
		edit(&opts)
	}
	if h.auth, err = authn.New(opts); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *codeHost) serve(path, body, cookie string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://auth.example/api/auth"+path, strings.NewReader(body))
	r.Header.Set("Origin", "https://auth.example")
	r.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	w := httptest.NewRecorder()
	h.auth.ServeHTTP(w, r)
	return w
}

// call posts body to path and fails unless it answers status, and the body
// holds want when set.
func (h *codeHost) call(path, body, cookie string, status int, want string) *httptest.ResponseRecorder {
	h.t.Helper()
	w := h.serve(path, body, cookie)
	if w.Code != status || !strings.Contains(w.Body.String(), want) {
		h.t.Fatalf("%s answered %d %s, want %d with %q", path, w.Code, w.Body.String(), status, want)
	}
	return w
}

func (h *codeHost) mailed() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.mail)
}

// lastCode returns the code mailed last, or "" when the count of mails is
// still before.
func (h *codeHost) lastCode(before int) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.mail) == before {
		return ""
	}
	return h.mail[len(h.mail)-1].OTP
}

// send asks for a code and returns the mailed one, or "" when nothing was mailed.
func (h *codeHost) send(email, kind string) string {
	h.t.Helper()
	before := h.mailed()
	h.call("/email-otp/send-verification-otp", `{"email":"`+email+`","type":"`+kind+`"}`, "", 200, `{"success":true}`)
	return h.lastCode(before)
}

// signUp creates a password account and returns its session cookie.
func (h *codeHost) signUp(email string) string {
	h.t.Helper()
	w := h.call("/sign-up/email", `{"email":"`+email+`","password":"correct horse battery","name":"Ada"}`, "", 200, "")
	for _, c := range w.Result().Cookies() {
		if strings.HasSuffix(c.Name, "session_token") {
			return c.Name + "=" + c.Value
		}
	}
	h.t.Fatal("sign-up set no session cookie")
	return ""
}

func signInBody(email, code string) string {
	return `{"email":"` + email + `","otp":"` + code + `"}`
}

// blindCodes hides every email code from FindEmailOTP, as a custom store
// that breaks the finder contract would.
type blindCodes struct{ *memory.Store }

func (blindCodes) FindEmailOTP(context.Context, authn.EmailOTPRequest) (string, time.Time, error) {
	return "", time.Time{}, authn.ErrNotFound
}

// Verification hooks run around email codes: create when a code is stored,
// delete before every guess, delete after when the code is spent or
// removed, and update after when a wrong guess is counted. A declined send
// stores and mails nothing, a declined guess is refused before the code is
// compared, a code that expired runs no hook, and a spent code's hooks run
// before the user and session hooks of its sign-in.
func TestDatabaseVerificationHooksForEmailCodes(t *testing.T) {
	ctx := t.Context()
	events := newVerificationEvents()
	store := memory.New()
	h := newCodeHost(t, store, events, authn.EmailOTPOptions{}, nil)
	find := func(email string, purpose authn.EmailOTPPurpose) (string, time.Time, error) {
		return store.FindEmailOTP(ctx, authn.EmailOTPRequest{Email: email, Purpose: purpose})
	}

	// A stored code's record names its kind and row, and holds neither the
	// code nor the address.
	first := h.send("new@example.test", "sign-in")
	sameEvents(t, events.drain(), "create-before:sign-in-otp", "create-after:sign-in-otp")
	created, c := events.last()
	id, expiresAt, err := find("new@example.test", authn.OTPSignIn)
	if err != nil || created.ID != id || created.Identifier != "sign-in-otp" || created.UserID != "" || !created.ExpiresAt.Equal(expiresAt.UTC().Truncate(time.Millisecond)) {
		t.Fatal("the code's record was", created, id, expiresAt, err)
	}
	if s := fmt.Sprintf("%+v", created); strings.Contains(s, first) || strings.Contains(s, "new@example.test") {
		t.Fatal("a verification record holds the code or the address:", s)
	}
	if c == nil || c.Path != "/email-otp/send-verification-otp" {
		t.Fatal("the create hook saw the endpoint", c)
	}

	// A declined send answers as a sent one, mails nothing and keeps the earlier code.
	events.set(events.decline, "create-before:sign-in-otp", true)
	if code := h.send("new@example.test", "sign-in"); code != "" {
		t.Fatal("a declined code was mailed")
	}
	sameEvents(t, events.drain(), "create-before:sign-in-otp")
	events.set(events.decline, "create-before:sign-in-otp", false)
	if kept, _, _ := find("new@example.test", authn.OTPSignIn); kept != id {
		t.Fatal("a declined send replaced the earlier code")
	}

	// A code the store withholds runs only the create before hooks.
	before := h.mailed()
	h.call("/email-otp/request-password-reset", `{"email":"nobody@example.test"}`, "", 200, `{"success":true}`)
	if h.lastCode(before) != "" {
		t.Fatal("a code was mailed to an unknown address")
	}
	sameEvents(t, events.drain(), "create-before:forget-password-otp")

	// A declined guess is refused before the code is compared.
	events.set(events.decline, "delete-before:sign-in-otp", true)
	for _, guess := range []string{"nope", "nope", "nope", first} {
		h.call("/sign-in/email-otp", signInBody("new@example.test", guess), "", 400, "INVALID_OTP")
		sameEvents(t, events.drain(), "delete-before:sign-in-otp")
	}
	events.set(events.decline, "delete-before:sign-in-otp", false)
	if rec, err := store.ReadEmailOTP(ctx, authn.EmailOTPRequest{Email: "new@example.test", Purpose: authn.OTPSignIn, Now: time.Now()}); err != nil || rec == nil || rec.Attempts != 0 {
		t.Fatal("declined guesses were counted", rec, err)
	}

	// The code signs a new user in: its hooks run before the user's and the session's.
	h.call("/sign-in/email-otp", signInBody("new@example.test", first), "", 200, "")
	sameEvents(t, events.drain(), "delete-before:sign-in-otp", "delete-after:sign-in-otp", "user-create-after", "session-create-after")
	spent, c := events.last()
	if spent != created || c == nil || c.Path != "/sign-in/email-otp" || c.Body["otp"] != first {
		t.Fatal("the spend's record or endpoint was", spent, c)
	}
	h.call("/sign-in/email-otp", signInBody("new@example.test", first), "", 400, "INVALID_OTP")
	sameEvents(t, events.drain())

	// Each counted wrong guess runs the update after hooks; the code that runs out is removed with its delete hooks.
	code := h.send("count@example.test", "sign-in")
	counted, _ := events.last()
	events.drain()
	for range 3 {
		h.call("/sign-in/email-otp", signInBody("count@example.test", "nope"), "", 400, "INVALID_OTP")
		sameEvents(t, events.drain(), "delete-before:sign-in-otp", "update-after:sign-in-otp")
		if updated, _ := events.last(); updated != counted {
			t.Fatal("the counted guess's record was", updated, counted)
		}
	}
	h.call("/sign-in/email-otp", signInBody("count@example.test", code), "", 403, "TOO_MANY_ATTEMPTS")
	sameEvents(t, events.drain(), "delete-before:sign-in-otp", "delete-after:sign-in-otp")
	h.call("/sign-in/email-otp", signInBody("count@example.test", code), "", 400, "INVALID_OTP")
	sameEvents(t, events.drain())

	// A code that has expired runs no hook, and the store removes it.
	now := time.Now().UTC().Truncate(time.Millisecond)
	stale := authn.EmailOTPRequest{Email: "stale@example.test", Purpose: authn.OTPSignIn, Now: now}
	if _, err := store.SaveEmailOTP(ctx, stale, true, now.Add(-time.Minute), func(*authn.EmailOTPRecord) (string, string, int, error) {
		return "stale-code", "stale-code", 0, nil
	}); err != nil {
		t.Fatal(err)
	}
	h.call("/sign-in/email-otp", signInBody("stale@example.test", "stale-code"), "", 400, "OTP_EXPIRED")
	sameEvents(t, events.drain())
	if _, _, err := find("stale@example.test", authn.OTPSignIn); !errors.Is(err, authn.ErrNotFound) {
		t.Fatal("the expired code stayed", err)
	}

	// A before hook's API error answers as itself, and an edit fails; both keep the code.
	code = h.send("edit@example.test", "sign-in")
	events.drain()
	events.failWith("delete-before:sign-in-otp", &authn.APIError{Status: 403, Code: "blocked", Message: "Blocked"})
	h.call("/sign-in/email-otp", signInBody("edit@example.test", code), "", 403, "blocked")
	sameEvents(t, events.drain(), "delete-before:sign-in-otp")
	events.failWith("delete-before:sign-in-otp", nil)
	events.set(events.edit, "delete-before:sign-in-otp", true)
	h.call("/sign-in/email-otp", signInBody("edit@example.test", code), "", 500, "")
	sameEvents(t, events.drain(), "delete-before:sign-in-otp")
	events.set(events.edit, "delete-before:sign-in-otp", false)
	h.call("/sign-in/email-otp", signInBody("edit@example.test", code), "", 200, "")
	sameEvents(t, events.drain(), "delete-before:sign-in-otp", "delete-after:sign-in-otp", "user-create-after", "session-create-after")
	events.set(events.edit, "create-before:sign-in-otp", true)
	before = h.mailed()
	h.call("/email-otp/send-verification-otp", `{"email":"edit@example.test","type":"sign-in"}`, "", 500, "")
	if h.lastCode(before) != "" {
		t.Fatal("a code whose create hook failed was mailed")
	}
	sameEvents(t, events.drain(), "create-before:sign-in-otp")
	events.set(events.edit, "create-before:sign-in-otp", false)

	// An after hook's error is not read as an invalid code: the sign-in
	// fails, its session is removed, and the spent code stays spent.
	code = h.send("late@example.test", "sign-in")
	events.drain()
	events.failWith("delete-after:sign-in-otp", fmt.Errorf("late: %w", authn.ErrNotFound))
	w := h.call("/sign-in/email-otp", signInBody("late@example.test", code), "", 500, "")
	if w.Header().Get("Set-Cookie") != "" {
		t.Fatal("a failed sign-in set a cookie")
	}
	sameEvents(t, events.drain(), "delete-before:sign-in-otp", "delete-after:sign-in-otp")
	events.failWith("delete-after:sign-in-otp", nil)
	late, err := store.FindAccountUser(ctx, "late@example.test")
	if err != nil {
		t.Fatal("the user the failed sign-in created is gone", err)
	}
	if sessions, err := store.ListSessions(ctx, late.ID); err != nil || len(sessions) != 0 {
		t.Fatal("the failed sign-in kept its session", sessions, err)
	}
	h.call("/sign-in/email-otp", signInBody("late@example.test", code), "", 400, "INVALID_OTP")
	sameEvents(t, events.drain())

	// A check judges the code without spending it.
	h.signUp("ada@example.test")
	events.drain()
	code = h.send("ada@example.test", "email-verification")
	sameEvents(t, events.drain(), "create-before:email-verification-otp", "create-after:email-verification-otp")
	check := func(email, code string, status int, want string) {
		t.Helper()
		h.call("/email-otp/check-verification-otp", `{"email":"`+email+`","type":"email-verification","otp":"`+code+`"}`, "", status, want)
	}
	check("ada@example.test", code, 200, `{"success":true}`)
	sameEvents(t, events.drain(), "delete-before:email-verification-otp")
	check("ada@example.test", "nope", 400, "INVALID_OTP")
	sameEvents(t, events.drain(), "delete-before:email-verification-otp", "update-after:email-verification-otp")
	// Verifying the address spends the checked code.
	h.call("/email-otp/verify-email", signInBody("ada@example.test", code), "", 200, `"emailVerified":true`)
	sameEvents(t, events.drain(), "delete-before:email-verification-otp", "delete-after:email-verification-otp")

	// A code for an address without an account: a check keeps it, a
	// verification spends it.
	ghost, err := h.auth.CreateEmailOTP(ctx, "ghost@example.test", authn.OTPVerifyEmail)
	if err != nil {
		t.Fatal(err)
	}
	sameEvents(t, events.drain(), "create-before:email-verification-otp", "create-after:email-verification-otp")
	if _, c := events.last(); c != nil {
		t.Fatal("a direct Go call's hook saw an endpoint", c)
	}
	check("ghost@example.test", ghost, 400, "USER_NOT_FOUND")
	sameEvents(t, events.drain(), "delete-before:email-verification-otp")
	h.call("/email-otp/verify-email", signInBody("ghost@example.test", ghost), "", 400, "USER_NOT_FOUND")
	sameEvents(t, events.drain(), "delete-before:email-verification-otp", "delete-after:email-verification-otp")

	// A reset runs one guess: a declined one is refused before the password
	// is hashed, a wrong one is counted, and the reset's hooks run before the
	// reset callback.
	before = h.mailed()
	h.call("/email-otp/request-password-reset", `{"email":"ada@example.test"}`, "", 200, "")
	code = h.lastCode(before)
	sameEvents(t, events.drain(), "create-before:forget-password-otp", "create-after:forget-password-otp")
	reset := func(email, code string, status int, want string) {
		t.Helper()
		h.call("/email-otp/reset-password", `{"email":"`+email+`","otp":"`+code+`","password":"second horse battery"}`, "", status, want)
	}
	hashed := h.hashed.Load()
	events.set(events.decline, "delete-before:forget-password-otp", true)
	reset("ada@example.test", code, 400, "INVALID_OTP")
	sameEvents(t, events.drain(), "delete-before:forget-password-otp")
	events.set(events.decline, "delete-before:forget-password-otp", false)
	reset("ada@example.test", "nope", 400, "INVALID_OTP")
	sameEvents(t, events.drain(), "delete-before:forget-password-otp", "update-after:forget-password-otp")
	if h.hashed.Load() != hashed {
		t.Fatal("a refused reset hashed the password")
	}
	reset("ada@example.test", code, 200, "")
	sameEvents(t, events.drain(), "delete-before:forget-password-otp", "delete-after:forget-password-otp", "on-password-reset")
	h.call("/sign-in/email", `{"email":"ada@example.test","password":"second horse battery"}`, "", 200, "")
	events.drain()

	// An after hook's error fails the reset after the password changed,
	// without the reset callback or the address verification.
	h.signUp("bo@example.test")
	before = h.mailed()
	h.call("/email-otp/request-password-reset", `{"email":"bo@example.test"}`, "", 200, "")
	code = h.lastCode(before)
	events.drain()
	events.failWith("delete-after:forget-password-otp", errors.New("late"))
	reset("bo@example.test", code, 500, "")
	sameEvents(t, events.drain(), "delete-before:forget-password-otp", "delete-after:forget-password-otp")
	events.failWith("delete-after:forget-password-otp", nil)
	h.call("/sign-in/email", `{"email":"bo@example.test","password":"second horse battery"}`, "", 200, `"emailVerified":false`)
	events.drain()

	// A code that proves an unverified account's address removes its reset
	// links without hooks, and the sign-in runs only the code's and the
	// session's hooks.
	h.signUp("eve@example.test")
	h.call("/request-password-reset", `{"email":"eve@example.test","redirectTo":"/reset"}`, "", 200, "")
	sameEvents(t, events.drain(), "user-create-after", "session-create-after", "create-before:reset-password", "create-after:reset-password")
	h.mu.Lock()
	link := h.resets[len(h.resets)-1]
	h.mu.Unlock()
	code = h.send("eve@example.test", "sign-in")
	events.drain()
	h.call("/sign-in/email-otp", signInBody("eve@example.test", code), "", 200, `"emailVerified":true`)
	sameEvents(t, events.drain(), "delete-before:sign-in-otp", "delete-after:sign-in-otp", "session-create-after")
	h.call("/reset-password", `{"newPassword":"third horse battery","token":"`+link+`"}`, "", 400, "INVALID_TOKEN")
	sameEvents(t, events.drain())

	// A code sent while a guess's hooks run is a new code: the guess is
	// refused uncounted, and the new code signs in.
	code = h.send("race@example.test", "sign-in")
	events.drain()
	var once sync.Once
	before = h.mailed()
	events.during("delete-before:sign-in-otp", func(ctx context.Context) {
		once.Do(func() {
			if err := h.auth.SendEmailOTP(ctx, "race@example.test", authn.OTPSignIn); err != nil {
				t.Error(err)
			}
		})
	})
	h.call("/sign-in/email-otp", signInBody("race@example.test", code), "", 400, "INVALID_OTP")
	events.during("delete-before:sign-in-otp", nil)
	sameEvents(t, events.drain(), "delete-before:sign-in-otp", "create-before:sign-in-otp", "create-after:sign-in-otp")
	h.call("/sign-in/email-otp", signInBody("race@example.test", h.lastCode(before)), "", 200, "")
	sameEvents(t, events.drain(), "delete-before:sign-in-otp", "delete-after:sign-in-otp", "user-create-after", "session-create-after")

	// Concurrent guesses with the right code spend it once.
	code = h.send("many@example.test", "sign-in")
	events.drain()
	var wg sync.WaitGroup
	var ok atomic.Int32
	for range 8 {
		wg.Go(func() {
			if h.serve("/sign-in/email-otp", signInBody("many@example.test", code), "").Code == 200 {
				ok.Add(1)
			}
		})
	}
	wg.Wait()
	spends, guesses := 0, 0
	for _, e := range events.drain() {
		switch e {
		case "delete-after:sign-in-otp":
			spends++
		case "delete-before:sign-in-otp":
			guesses++
		}
	}
	if ok.Load() != 1 || spends != 1 || guesses < 1 || guesses > 8 {
		t.Fatal("concurrent guesses signed in", ok.Load(), "times with", spends, "spends and", guesses, "guesses")
	}

	// A declined CreateEmailOTP returns a code that was never stored.
	events.set(events.decline, "create-before:sign-in-otp", true)
	unstored, err := h.auth.CreateEmailOTP(ctx, "unstored@example.test", authn.OTPSignIn)
	events.set(events.decline, "create-before:sign-in-otp", false)
	if err != nil || unstored == "" {
		t.Fatal("a declined CreateEmailOTP returned", unstored, err)
	}
	if err := h.auth.CheckEmailOTP(ctx, "unstored@example.test", unstored, authn.OTPSignIn); err == nil || !strings.Contains(err.Error(), "Invalid OTP") {
		t.Fatal("a declined code checked as", err)
	}
	sameEvents(t, events.drain(), "create-before:sign-in-otp")
}

// A code that closed sign-up, invalid registration fields or a blind
// finder refuses: a refusal that spends the code runs its delete after
// hooks first, and a store that hides the code refuses the guess without
// hooks. A reuse resend stores the code again under a new ID, and the sign-up
// code's hooks see the sign-up endpoint.
func TestDatabaseVerificationHooksForEmailCodeRefusals(t *testing.T) {
	ctx := t.Context()
	events := newVerificationEvents()
	store := memory.New()
	open := newCodeHost(t, store, events, authn.EmailOTPOptions{}, nil)

	// Closed sign-up spends a code for an unknown address.
	closed := newCodeHost(t, store, events, authn.EmailOTPOptions{DisableSignUp: true}, nil)
	code, err := open.auth.CreateEmailOTP(ctx, "closed@example.test", authn.OTPSignIn)
	if err != nil {
		t.Fatal(err)
	}
	events.drain()
	closed.call("/sign-in/email-otp", signInBody("closed@example.test", code), "", 400, "INVALID_OTP")
	sameEvents(t, events.drain(), "delete-before:sign-in-otp", "delete-after:sign-in-otp")

	// Invalid registration fields spend the code.
	fields := newCodeHost(t, memory.New(), events, authn.EmailOTPOptions{}, func(o *authn.Options) {
		o.UserAdditionalFields = map[string]authn.UserField{"locale": {Type: authn.FieldString, Required: true}}
	})
	code = fields.send("fields@example.test", "sign-in")
	events.drain()
	fields.call("/sign-in/email-otp", signInBody("fields@example.test", code), "", 400, "")
	sameEvents(t, events.drain(), "delete-before:sign-in-otp", "delete-after:sign-in-otp")
	fields.call("/sign-in/email-otp", signInBody("fields@example.test", code), "", 400, "INVALID_OTP")
	sameEvents(t, events.drain())

	// A store that hides the code refuses the guess without hooks and keeps the code.
	blind := newCodeHost(t, blindCodes{memory.New()}, events, authn.EmailOTPOptions{}, nil)
	code = blind.send("blind@example.test", "sign-in")
	events.drain()
	blind.call("/sign-in/email-otp", signInBody("blind@example.test", code), "", 400, "INVALID_OTP")
	sameEvents(t, events.drain())
	if kept, err := blind.auth.ReadEmailOTP(ctx, "blind@example.test", authn.OTPSignIn); err != nil || kept == nil || *kept != code {
		t.Fatal("the hidden code was touched", kept, err)
	}

	// A reuse resend stores the code again under a new ID, keeping its attempts.
	reuse := newCodeHost(t, memory.New(), events, authn.EmailOTPOptions{ResendStrategy: "reuse"}, nil)
	code = reuse.send("reuse@example.test", "sign-in")
	first, _ := events.last()
	events.drain()
	reuse.call("/sign-in/email-otp", signInBody("reuse@example.test", "nope"), "", 400, "INVALID_OTP")
	sameEvents(t, events.drain(), "delete-before:sign-in-otp", "update-after:sign-in-otp")
	if again := reuse.send("reuse@example.test", "sign-in"); again != code {
		t.Fatal("the reuse resend mailed", again, "not", code)
	}
	sameEvents(t, events.drain(), "create-before:sign-in-otp", "create-after:sign-in-otp")
	if second, _ := events.last(); second.ID == first.ID || second.ID == "" {
		t.Fatal("the resent code kept its ID", second, first)
	}
	for range 2 {
		reuse.call("/sign-in/email-otp", signInBody("reuse@example.test", "nope"), "", 400, "INVALID_OTP")
		sameEvents(t, events.drain(), "delete-before:sign-in-otp", "update-after:sign-in-otp")
	}
	reuse.call("/sign-in/email-otp", signInBody("reuse@example.test", code), "", 403, "TOO_MANY_ATTEMPTS")
	sameEvents(t, events.drain(), "delete-before:sign-in-otp", "delete-after:sign-in-otp")

	// The sign-up code's hooks see the sign-up endpoint; a declined code
	// mails nothing, and a failing hook is logged without failing sign-up.
	signUp := newCodeHost(t, memory.New(), events, authn.EmailOTPOptions{SendVerificationOnSignUp: true}, nil)
	signUp.signUp("first@example.test")
	sameEvents(t, events.drain(), "user-create-after", "session-create-after", "create-before:email-verification-otp", "create-after:email-verification-otp")
	if _, c := events.last(); c == nil || c.Path != "/sign-up/email" {
		t.Fatal("the sign-up code's hook saw the endpoint", c)
	}
	before := signUp.mailed()
	events.set(events.decline, "create-before:email-verification-otp", true)
	signUp.signUp("second@example.test")
	events.set(events.decline, "create-before:email-verification-otp", false)
	events.failWith("create-before:email-verification-otp", errors.New("down"))
	signUp.signUp("third@example.test")
	events.failWith("create-before:email-verification-otp", nil)
	if signUp.lastCode(before) != "" {
		t.Fatal("a declined or failed sign-up code was mailed")
	}
	sameEvents(t, events.drain(), "user-create-after", "session-create-after", "create-before:email-verification-otp",
		"user-create-after", "session-create-after", "create-before:email-verification-otp")
}

// Verification hooks run around email address changes. With
// VerifyCurrentEmail the current address's code is judged in the store call
// that stores the new code: its delete before hooks run first, and its
// after hooks before the new code's. A declined new code spends nothing.
func TestDatabaseVerificationHooksForEmailChanges(t *testing.T) {
	ctx := t.Context()
	events := newVerificationEvents()
	store := memory.New()
	h := newCodeHost(t, store, events, authn.EmailOTPOptions{ChangeEmail: authn.EmailOTPChangeOptions{Enabled: true}}, nil)
	cookie := h.signUp("ada@example.test")
	ada, err := store.FindAccountUser(ctx, "ada@example.test")
	if err != nil {
		t.Fatal(err)
	}
	events.drain()
	request := func(h *codeHost, cookie, newEmail, otp string, status int, want string) string {
		t.Helper()
		body := `{"newEmail":"` + newEmail + `"}`
		if otp != "" {
			body = `{"newEmail":"` + newEmail + `","otp":"` + otp + `"}`
		}
		before := h.mailed()
		h.call("/email-otp/request-email-change", body, cookie, status, want)
		return h.lastCode(before)
	}

	// A change code names the signed-in user who asked for it.
	code := request(h, cookie, "ada2@example.test", "", 200, `{"success":true}`)
	sameEvents(t, events.drain(), "create-before:change-email-otp", "create-after:change-email-otp")
	created, _ := events.last()
	if created.Identifier != "change-email-otp" || created.UserID != ada.ID {
		t.Fatal("the change code's record was", created)
	}
	h.call("/email-otp/change-email", `{"newEmail":"ada2@example.test","otp":"`+code+`"}`, cookie, 200, "")
	sameEvents(t, events.drain(), "delete-before:change-email-otp", "delete-after:change-email-otp")
	if spent, _ := events.last(); spent != created {
		t.Fatal("the change's record was", spent, created)
	}

	// An address taken after the code was sent spends the code.
	code = request(h, cookie, "taken@example.test", "", 200, "")
	h.signUp("taken@example.test")
	events.drain()
	h.call("/email-otp/change-email", `{"newEmail":"taken@example.test","otp":"`+code+`"}`, cookie, 400, "Email already in use")
	sameEvents(t, events.drain(), "delete-before:change-email-otp", "delete-after:change-email-otp")

	// With VerifyCurrentEmail the current address's code is a guess.
	current := newCodeHost(t, store, events, authn.EmailOTPOptions{ChangeEmail: authn.EmailOTPChangeOptions{Enabled: true, VerifyCurrentEmail: true}}, nil)
	cy := current.signUp("cy@example.test")
	current.signUp("held@example.test")
	events.drain()
	proof := current.send("cy@example.test", "email-verification")
	events.drain()
	attempts := func() int {
		t.Helper()
		rec, err := store.ReadEmailOTP(ctx, authn.EmailOTPRequest{Email: "cy@example.test", Purpose: authn.OTPVerifyEmail, Now: time.Now()})
		if err != nil || rec == nil {
			t.Fatal("the current address's code is gone", err)
		}
		return rec.Attempts
	}

	// A declined current guess stores nothing.
	events.set(events.decline, "delete-before:email-verification-otp", true)
	if mailed := request(current, cy, "next@example.test", proof, 400, "INVALID_OTP"); mailed != "" {
		t.Fatal("a declined current guess mailed a code")
	}
	sameEvents(t, events.drain(), "delete-before:email-verification-otp")
	events.set(events.decline, "delete-before:email-verification-otp", false)

	// A declined new code answers as sent and leaves the current code untouched.
	events.set(events.decline, "create-before:change-email-otp", true)
	if mailed := request(current, cy, "next@example.test", proof, 200, ""); mailed != "" {
		t.Fatal("a declined change code was mailed")
	}
	sameEvents(t, events.drain(), "delete-before:email-verification-otp", "create-before:change-email-otp")
	events.set(events.decline, "create-before:change-email-otp", false)
	if n := attempts(); n != 0 {
		t.Fatal("a declined change counted the current code", n)
	}

	// A wrong current code is counted and stores no new code.
	if mailed := request(current, cy, "next@example.test", "nope", 400, "INVALID_OTP"); mailed != "" {
		t.Fatal("a wrong current code mailed a change code")
	}
	sameEvents(t, events.drain(), "delete-before:email-verification-otp", "create-before:change-email-otp", "update-after:email-verification-otp")
	if n := attempts(); n != 1 {
		t.Fatal("the wrong current code was counted", n, "times")
	}

	// A new address someone holds spends the current code and mails nothing.
	if mailed := request(current, cy, "held@example.test", proof, 200, ""); mailed != "" {
		t.Fatal("a change to a held address was mailed")
	}
	sameEvents(t, events.drain(), "delete-before:email-verification-otp", "create-before:change-email-otp", "delete-after:email-verification-otp")

	// The current code's after hooks run before the new code's.
	proof = current.send("cy@example.test", "email-verification")
	events.drain()
	if mailed := request(current, cy, "next@example.test", proof, 200, ""); mailed == "" {
		t.Fatal("the change code was not mailed")
	}
	sameEvents(t, events.drain(), "delete-before:email-verification-otp", "create-before:change-email-otp", "delete-after:email-verification-otp", "create-after:change-email-otp")

	// Observed verifications run the code's hooks before BeforeEmailVerification;
	// an after hook's error discards the spend and leaves the address unverified.
	observed := newCodeHost(t, memory.New(), events, authn.EmailOTPOptions{}, func(o *authn.Options) {
		o.BeforeEmailVerification = func(context.Context, authn.User, *http.Request) error {
			return events.note("before-email-verification", nil, nil)
		}
	})
	observed.signUp("dee@example.test")
	code = observed.send("dee@example.test", "email-verification")
	events.drain()
	events.failWith("delete-after:email-verification-otp", errors.New("late"))
	observed.call("/email-otp/verify-email", signInBody("dee@example.test", code), "", 500, "")
	sameEvents(t, events.drain(), "delete-before:email-verification-otp", "delete-after:email-verification-otp")
	events.failWith("delete-after:email-verification-otp", nil)
	code = observed.send("dee@example.test", "email-verification")
	events.drain()
	observed.call("/email-otp/verify-email", signInBody("dee@example.test", code), "", 200, `"emailVerified":true`)
	sameEvents(t, events.drain(), "delete-before:email-verification-otp", "delete-after:email-verification-otp", "before-email-verification")
}

// phoneHost serves phone codes with recorded verification hooks.
type phoneHost struct {
	t      *testing.T
	auth   *authn.Auth
	mu     sync.Mutex
	sms    []authn.PhoneOTPMessage
	hashed atomic.Int32
}

func newPhoneHost(t *testing.T, store authn.Store, events *verificationEvents, edit func(*authn.PhoneNumberOptions, *authn.Options)) *phoneHost {
	t.Helper()
	h := &phoneHost{t: t}
	capture := func(_ context.Context, m authn.PhoneOTPMessage) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.sms = append(h.sms, m)
		return nil
	}
	o := authn.PhoneNumberOptions{SendOTP: capture, SendPasswordResetOTP: capture,
		SignUpOnVerification: &authn.PhoneSignUpOptions{GetTempEmail: func(n string) string { return strings.TrimPrefix(n, "+") + "@phone.test" }}}
	off := false
	opts := authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off, DatabaseHooks: events.hooks(),
		PasswordHash: func(ctx context.Context, password string) (string, error) {
			h.hashed.Add(1)
			return authn.HashPassword(ctx, password)
		},
		PasswordVerify: authn.VerifyPasswordHash,
		OnPasswordReset: func(context.Context, authn.User, *http.Request) error {
			return events.note("on-password-reset", nil, nil)
		},
	}
	if edit != nil {
		edit(&o, &opts)
	}
	phone, err := authn.NewPhoneNumber(o)
	if err != nil {
		t.Fatal(err)
	}
	opts.Plugins = []authn.Plugin{phone}
	if h.auth, err = authn.New(opts); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *phoneHost) call(path, body, cookie string, status int, want string) *httptest.ResponseRecorder {
	h.t.Helper()
	r := httptest.NewRequest("POST", "https://auth.example/api/auth"+path, strings.NewReader(body))
	r.Header.Set("Origin", "https://auth.example")
	r.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	w := httptest.NewRecorder()
	h.auth.ServeHTTP(w, r)
	if w.Code != status || !strings.Contains(w.Body.String(), want) {
		h.t.Fatalf("%s answered %d %s, want %d with %q", path, w.Code, w.Body.String(), status, want)
	}
	return w
}

func (h *phoneHost) texted() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.sms)
}

// lastCode returns the code texted last, or "" when the count is still before.
func (h *phoneHost) lastCode(before int) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.sms) == before {
		return ""
	}
	return h.sms[len(h.sms)-1].Code
}

func (h *phoneHost) send(number string) string {
	h.t.Helper()
	before := h.texted()
	h.call("/phone-number/send-otp", `{"phoneNumber":"`+number+`"}`, "", 200, "code sent")
	return h.lastCode(before)
}

func phoneBody(number, code string) string {
	return `{"phoneNumber":"` + number + `","code":"` + code + `"}`
}

// Verification hooks run around phone codes: create when a code is stored,
// delete before every guess, before a custom VerifyOTP is asked, delete
// after when the code is spent or removed, and update after when a wrong
// guess is counted. A declined send stores and texts nothing, and a code a
// refused sign-up or link spends runs its after hooks before the refusal.
func TestDatabaseVerificationHooksForPhoneCodes(t *testing.T) {
	ctx := t.Context()
	events := newVerificationEvents()
	store := memory.New()
	h := newPhoneHost(t, store, events, nil)
	read := func(number string, purpose authn.PhoneOTPPurpose) *authn.PhoneOTPRecord {
		t.Helper()
		r, err := store.ReadPhoneOTP(ctx, number, purpose)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	// A stored code's record names its kind and row, and holds neither the code nor the number.
	code := h.send("+15550000001")
	sameEvents(t, events.drain(), "create-before:phone-number-otp", "create-after:phone-number-otp")
	created, _ := events.last()
	stored := read("+15550000001", authn.PhoneVerify)
	if created.ID != stored.ID || created.Identifier != "phone-number-otp" || created.UserID != "" || !created.ExpiresAt.Equal(stored.ExpiresAt.UTC().Truncate(time.Millisecond)) {
		t.Fatal("the phone code's record was", created, stored.ID)
	}
	if s := fmt.Sprintf("%+v", created); strings.Contains(s, "5550000001") {
		t.Fatal("a verification record holds the number:", s)
	}
	// A declined send answers as a sent one, texts nothing and keeps the earlier code.
	events.set(events.decline, "create-before:phone-number-otp", true)
	if again := h.send("+15550000001"); again != "" {
		t.Fatal("a declined phone code was texted")
	}
	events.set(events.decline, "create-before:phone-number-otp", false)
	sameEvents(t, events.drain(), "create-before:phone-number-otp")
	if kept := read("+15550000001", authn.PhoneVerify); kept == nil || kept.ID != stored.ID {
		t.Fatal("a declined send replaced the earlier code")
	}

	// Each counted wrong phone guess runs the update after hooks.
	for range 3 {
		h.call("/phone-number/verify", phoneBody("+15550000001", "nope"), "", 400, "INVALID_OTP")
		sameEvents(t, events.drain(), "delete-before:phone-number-otp", "update-after:phone-number-otp")
		if updated, _ := events.last(); updated != created {
			t.Fatal("the counted guess's record was", updated, created)
		}
	}
	h.call("/phone-number/verify", phoneBody("+15550000001", code), "", 403, "TOO_MANY_ATTEMPTS")
	sameEvents(t, events.drain(), "delete-before:phone-number-otp", "delete-after:phone-number-otp")
	h.call("/phone-number/verify", phoneBody("+15550000001", code), "", 400, "OTP_NOT_FOUND")
	sameEvents(t, events.drain())

	// A code that has expired runs no hook.
	past := time.Now().UTC().Add(-time.Minute)
	if err := store.SavePhoneOTP(ctx, authn.PhoneOTPRecord{ID: "stale", PhoneNumber: "+15550000002", Code: "123456", Purpose: authn.PhoneVerify, CreatedAt: past.Add(-time.Minute), ExpiresAt: past}); err != nil {
		t.Fatal(err)
	}
	h.call("/phone-number/verify", phoneBody("+15550000002", "123456"), "", 400, "OTP_EXPIRED")
	sameEvents(t, events.drain())

	// A sign-up on verification: the code's hooks run before the user's and session's.
	code = h.send("+15550000003")
	events.drain()
	h.call("/phone-number/verify", phoneBody("+15550000003", code), "", 200, `"status":true`)
	sameEvents(t, events.drain(), "delete-before:phone-number-otp", "delete-after:phone-number-otp", "user-create-after", "session-create-after")

	// An after hook's error fails the sign-up and removes its session.
	code = h.send("+15550000004")
	events.drain()
	events.failWith("delete-after:phone-number-otp", errors.New("late"))
	if w := h.call("/phone-number/verify", phoneBody("+15550000004", code), "", 500, ""); w.Header().Get("Set-Cookie") != "" {
		t.Fatal("a failed sign-up set a cookie")
	}
	events.failWith("delete-after:phone-number-otp", nil)
	sameEvents(t, events.drain(), "delete-before:phone-number-otp", "delete-after:phone-number-otp")
	late, err := store.FindAccountUser(ctx, "15550000004@phone.test")
	if err != nil {
		t.Fatal("the user the failed sign-up created is gone", err)
	}
	if sessions, err := store.ListSessions(ctx, late.ID); err != nil || len(sessions) != 0 {
		t.Fatal("the failed sign-up kept its session", sessions, err)
	}

	// A link without a session, and a link to a number someone holds, spend the code.
	code = h.send("+15550000005")
	events.drain()
	h.call("/phone-number/verify", `{"phoneNumber":"+15550000005","code":"`+code+`","updatePhoneNumber":true}`, "", 401, "USER_NOT_FOUND")
	sameEvents(t, events.drain(), "delete-before:phone-number-otp", "delete-after:phone-number-otp")
	w := h.call("/sign-up/email", `{"email":"ada@phone.test","password":"correct horse battery","name":"Ada"}`, "", 200, "")
	var cookie string
	for _, c := range w.Result().Cookies() {
		if strings.HasSuffix(c.Name, "session_token") {
			cookie = c.Name + "=" + c.Value
		}
	}
	code = h.send("+15550000003")
	events.drain()
	h.call("/phone-number/verify", `{"phoneNumber":"+15550000003","code":"`+code+`","updatePhoneNumber":true}`, cookie, 400, "PHONE_NUMBER_EXIST")
	sameEvents(t, events.drain(), "delete-before:phone-number-otp", "delete-after:phone-number-otp")
	// A link to a free number gives Ada a number for the resets below.
	code = h.send("+15550000006")
	events.drain()
	h.call("/phone-number/verify", `{"phoneNumber":"+15550000006","code":"`+code+`","updatePhoneNumber":true}`, cookie, 200, `"status":true`)
	sameEvents(t, events.drain(), "delete-before:phone-number-otp", "delete-after:phone-number-otp")

	// A field a caller may not set spends the code.
	code = h.send("+15550000007")
	events.drain()
	h.call("/phone-number/verify", `{"phoneNumber":"+15550000007","code":"`+code+`","phoneNumberVerified":true}`, "", 400, "FIELD_NOT_ALLOWED")
	sameEvents(t, events.drain(), "delete-before:phone-number-otp", "delete-after:phone-number-otp")

	// A reset request stores a code for any number, so its hooks reveal nothing.
	before := h.texted()
	h.call("/phone-number/request-password-reset", `{"phoneNumber":"+15550000099"}`, "", 200, `"status":true`)
	if h.lastCode(before) != "" {
		t.Fatal("a reset code was texted to an unknown number")
	}
	sameEvents(t, events.drain(), "create-before:phone-number-reset", "create-after:phone-number-reset")
	events.set(events.decline, "create-before:phone-number-reset", true)
	h.call("/phone-number/request-password-reset", `{"phoneNumber":"+15550000098"}`, "", 200, `"status":true`)
	events.set(events.decline, "create-before:phone-number-reset", false)
	sameEvents(t, events.drain(), "create-before:phone-number-reset")
	if r := read("+15550000098", authn.PhonePasswordReset); r != nil {
		t.Fatal("a declined reset code was stored")
	}

	// A reset runs one guess: a declined one is refused before the password
	// is hashed, a wrong one is counted, and the reset's hooks run before the
	// reset callback.
	before = h.texted()
	h.call("/phone-number/request-password-reset", `{"phoneNumber":"+15550000006"}`, "", 200, "")
	code = h.lastCode(before)
	events.drain()
	reset := func(code string, status int, want string) {
		t.Helper()
		h.call("/phone-number/reset-password", `{"phoneNumber":"+15550000006","otp":"`+code+`","newPassword":"second horse battery"}`, "", status, want)
	}
	hashed := h.hashed.Load()
	events.set(events.decline, "delete-before:phone-number-reset", true)
	reset(code, 400, "INVALID_OTP")
	events.set(events.decline, "delete-before:phone-number-reset", false)
	sameEvents(t, events.drain(), "delete-before:phone-number-reset")
	reset("nope", 400, "INVALID_OTP")
	sameEvents(t, events.drain(), "delete-before:phone-number-reset", "update-after:phone-number-reset")
	if h.hashed.Load() != hashed {
		t.Fatal("a refused reset hashed the password")
	}
	reset(code, 200, "")
	sameEvents(t, events.drain(), "delete-before:phone-number-reset", "delete-after:phone-number-reset", "on-password-reset")
	h.call("/sign-in/phone-number", `{"phoneNumber":"+15550000006","password":"second horse battery"}`, "", 200, "")
	events.drain()
	// An after hook's error fails the reset after the password changed, without the callback.
	before = h.texted()
	h.call("/phone-number/request-password-reset", `{"phoneNumber":"+15550000006"}`, "", 200, "")
	code = h.lastCode(before)
	events.drain()
	events.failWith("delete-after:phone-number-reset", errors.New("late"))
	h.call("/phone-number/reset-password", `{"phoneNumber":"+15550000006","otp":"`+code+`","newPassword":"third horse battery"}`, "", 500, "")
	events.failWith("delete-after:phone-number-reset", nil)
	sameEvents(t, events.drain(), "delete-before:phone-number-reset", "delete-after:phone-number-reset")
	h.call("/sign-in/phone-number", `{"phoneNumber":"+15550000006","password":"third horse battery"}`, "", 200, "")
	events.drain()

	// A direct Go call's hooks see no endpoint.
	code = h.send("+15550000008")
	events.drain()
	if err := h.auth.ConsumePhoneNumberOTP(ctx, "+15550000008", code); err != nil {
		t.Fatal(err)
	}
	sameEvents(t, events.drain(), "delete-before:phone-number-otp", "delete-after:phone-number-otp")
	if _, c := events.last(); c != nil {
		t.Fatal("a direct Go call's hook saw an endpoint", c)
	}
}

// A custom VerifyOTP is asked only after a guess's delete before hooks, so
// a declined guess never reaches it, and a guess it rejects is counted even
// when the client has gone. ValidateUserInfo's refusal spends the code and
// runs its after hooks first.
func TestDatabaseVerificationHooksForPhoneProviders(t *testing.T) {
	ctx := t.Context()
	events := newVerificationEvents()
	store := memory.New()
	var asked atomic.Int32
	var cancelGuess atomic.Pointer[context.CancelFunc]
	h := newPhoneHost(t, store, events, func(o *authn.PhoneNumberOptions, opts *authn.Options) {
		o.VerifyOTP = func(_ context.Context, m authn.PhoneOTPMessage) (bool, error) {
			asked.Add(1)
			if cancel := cancelGuess.Load(); cancel != nil {
				(*cancel)()
			}
			return m.Code == "right", nil
		}
		opts.ValidateUserInfo = func(_ context.Context, v authn.UserInfoValidation) error {
			if strings.HasPrefix(v.User.Email, "15550000019") {
				return errors.New("refused")
			}
			return nil
		}
	})
	h.send("+15550000011")
	events.drain()

	// A declined phone guess never reaches the provider or the attempt count.
	events.set(events.decline, "delete-before:phone-number-otp", true)
	for range 3 {
		h.call("/phone-number/verify", phoneBody("+15550000011", "nope"), "", 400, "INVALID_OTP")
		sameEvents(t, events.drain(), "delete-before:phone-number-otp")
	}
	events.set(events.decline, "delete-before:phone-number-otp", false)
	if r, _ := store.ReadPhoneOTP(ctx, "+15550000011", authn.PhoneVerify); asked.Load() != 0 || r == nil || r.Attempts != 0 {
		t.Fatal("declined guesses reached the provider", asked.Load(), "times or were counted", r)
	}

	// A wrong guess the Auth judged is counted even when the client has gone.
	guess, cancel := context.WithCancel(ctx)
	cancelGuess.Store(&cancel)
	if _, err := h.auth.VerifyPhoneNumber(guess, http.Header{}, authn.PhoneVerificationInput{PhoneNumber: "+15550000011", Code: "nope"}, authn.RequestMeta{}); err == nil || !strings.Contains(err.Error(), "Invalid OTP") {
		t.Fatal("a rejected guess answered", err)
	}
	cancelGuess.Store(nil)
	sameEvents(t, events.drain(), "delete-before:phone-number-otp", "update-after:phone-number-otp")
	if r, _ := store.ReadPhoneOTP(ctx, "+15550000011", authn.PhoneVerify); asked.Load() != 1 || r == nil || r.Attempts != 1 {
		t.Fatal("the rejected guess was asked", asked.Load(), "times and counted as", r)
	}
	// The provider's acceptance signs up.
	h.call("/phone-number/verify", phoneBody("+15550000011", "right"), "", 200, `"status":true`)
	sameEvents(t, events.drain(), "delete-before:phone-number-otp", "delete-after:phone-number-otp", "user-create-after", "session-create-after")

	// ValidateUserInfo's refusal spends the code and runs its after hooks first.
	h.send("+15550000019")
	events.drain()
	h.call("/phone-number/verify", phoneBody("+15550000019", "right"), "", 403, "")
	sameEvents(t, events.drain(), "delete-before:phone-number-otp", "delete-after:phone-number-otp")
	h.call("/phone-number/verify", phoneBody("+15550000019", "right"), "", 400, "OTP_NOT_FOUND")
	sameEvents(t, events.drain())
}
