package goapi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
)

// changeEmailHost is one auth instance with recorded change-email mail.
type changeEmailHost struct {
	t      *testing.T
	auth   *authn.Auth
	store  *sqlite.Store
	mu     sync.Mutex
	mail   []authn.MailLink
	client sessionClient
}

func newChangeEmailHost(t *testing.T, opts authn.Options, confirm, verify bool) *changeEmailHost {
	t.Helper()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	h := &changeEmailHost{t: t, store: store}
	record := func(_ context.Context, m authn.MailLink) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		m.Request = nil
		h.mail = append(h.mail, m)
		return nil
	}
	if confirm {
		opts.SendChangeEmailConfirmation = record
	}
	if verify {
		opts.SendVerificationEmail = record
	}
	off := false
	opts.Store, opts.Secret, opts.BaseURL, opts.EmailAndPassword, opts.RateLimit = store, strings.Repeat("s", 32), "https://auth.example", true, &off
	h.auth, err = authn.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	h.client = sessionClient{t, h.auth}
	return h
}

func (h *changeEmailHost) mails() []authn.MailLink {
	h.mu.Lock()
	defer h.mu.Unlock()
	mails := h.mail
	h.mail = nil
	return mails
}

// signUp creates an account, optionally verified, and returns its cookie.
func (h *changeEmailHost) signUp(email string, verified bool) string {
	h.t.Helper()
	h.client.post("/sign-up/email", `{"name":"Person","email":"`+email+`","password":"`+sessionEndpointPassword+`"}`, "", 200)
	if verified {
		u, err := h.store.FindAccountUser(h.t.Context(), email)
		if err != nil {
			h.t.Fatal(err)
		}
		if err := h.store.VerifyAccountEmail(h.t.Context(), u.ID, email, time.Now()); err != nil {
			h.t.Fatal(err)
		}
	}
	h.mails()
	cookie, _ := h.client.signIn(email)
	return cookie
}

// owns reports whether the account with this id holds the address.
func (h *changeEmailHost) owns(email, id string) bool {
	h.t.Helper()
	u, err := h.store.FindAccountUser(h.t.Context(), email)
	return err == nil && u.ID == id
}

func (h *changeEmailHost) userID(email string) string {
	h.t.Helper()
	u, err := h.store.FindAccountUser(h.t.Context(), email)
	if err != nil {
		h.t.Fatal(email, err)
	}
	return u.ID
}

// errorBody decodes an error answer, reporting whether it has a code.
func errorBody(t *testing.T, r *http.Response) (code, message string, coded bool) {
	t.Helper()
	var out map[string]any
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	code, coded = out["code"].(string)
	message, _ = out["message"].(string)
	return code, message, coded
}

// /change-email validates its body before anything else, needs a session
// before reporting that the feature is off, answers an address another
// account holds exactly like a free one, and gives the reference's errors.
func TestChangeEmailRequestContract(t *testing.T) {
	anon := ""
	for _, enabled := range []bool{false, true} {
		h := newChangeEmailHost(t, authn.Options{ChangeEmailEnabled: enabled}, false, true)
		cookie := h.signUp("old@example.test", false)
		for _, who := range []string{anon, cookie} {
			code, message, _ := errorBody(t, h.client.post("/change-email", `{"newEmail":"not-an-email"}`, who, 400))
			if code != "VALIDATION_ERROR" || message != "[body.newEmail] Invalid email address" {
				t.Fatal("a malformed address answered", code, message)
			}
		}
		if code, _, _ := errorBody(t, h.client.post("/change-email", `{"newEmail":"new@example.test"}`, anon, 401)); code != "UNAUTHORIZED" {
			t.Fatal("change-email without a session answered", code)
		}
		if enabled {
			continue
		}
		r := h.client.post("/change-email", `{"newEmail":"new@example.test"}`, cookie, 400)
		if code, message, _ := errorBody(t, r); code != "CHANGE_EMAIL_DISABLED" || message != "Change email is disabled" || len(r.Header.Values("Set-Cookie")) != 0 {
			t.Fatal("disabled change-email answered", code, message)
		}
		if len(h.mails()) != 0 || !h.owns("old@example.test", h.userID("old@example.test")) || h.owns("new@example.test", h.userID("old@example.test")) {
			t.Fatal("a disabled change-email sent mail or changed the address")
		}
	}

	h := newChangeEmailHost(t, authn.Options{ChangeEmailEnabled: true}, true, true)
	cookie := h.signUp("old@example.test", false)
	r := serve(t, h.auth, "POST", "/api/auth/change-email", "", http.Header{"Origin": {"https://auth.example"}}, 400)
	if _, message, _ := errorBody(t, r); message != "[body] Invalid input: expected object, received undefined" {
		t.Fatal("an empty body answered", message)
	}
	if _, message, _ := errorBody(t, h.client.post("/change-email", `{}`, cookie, 400)); message != "[body.newEmail] Invalid input: expected string, received undefined" {
		t.Fatal("a body without newEmail answered", message)
	}
	if _, message, coded := errorBody(t, h.client.post("/change-email", `{"newEmail":"OLD@Example.test"}`, cookie, 400)); message != "Email is the same" || coded {
		t.Fatal("the current address answered", message, coded)
	}
	for body, message := range map[string]string{
		`{"newEmail":"new@example.test","callbackURL":null}`: "[body.callbackURL] Invalid input: expected string, received null",
		`{"newEmail":"nope","callbackURL":false}`:            "[body.newEmail] Invalid email address; [body.callbackURL] Invalid input: expected string, received boolean",
		`{"newEmail":"\u212Aate@example.test"}`:              "[body.newEmail] Invalid email address",
	} {
		if code, got, _ := errorBody(t, h.client.post("/change-email", body, cookie, 400)); code != "VALIDATION_ERROR" || got != message {
			t.Fatal(body, "answered", code, got)
		}
	}
	if len(h.mails()) != 0 {
		t.Fatal("a refused change-email sent mail")
	}

	// An address another account holds answers like a free one, sends no
	// mail and changes nothing, whether the caller is verified or not.
	other := h.userID(func() string { h.signUp("taken@example.test", false); return "taken@example.test" }())
	owner := h.userID("old@example.test")
	for _, verified := range []bool{false, true} {
		if verified {
			if err := h.store.VerifyAccountEmail(t.Context(), owner, "old@example.test", time.Now()); err != nil {
				t.Fatal(err)
			}
			cookie, _ = h.client.signIn("old@example.test")
		}
		r := h.client.post("/change-email", `{"newEmail":"Taken@example.test"}`, cookie, 200)
		statusBody(t, r)
		if len(r.Header.Values("Set-Cookie")) != 0 || len(h.mails()) != 0 {
			t.Fatal("a taken address set cookies or sent mail")
		}
		statusBody(t, h.client.post("/change-email", `{"newEmail":"free@example.test"}`, cookie, 200))
		if len(h.mails()) != 1 {
			t.Fatal("a free address did not send one mail")
		}
	}
	if !h.owns("old@example.test", owner) || !h.owns("taken@example.test", other) {
		t.Fatal("asking for a taken address changed an account")
	}

	// Without a verification sender, a taken and a free address get the same
	// code-less error.
	quiet := newChangeEmailHost(t, authn.Options{ChangeEmailEnabled: true}, true, false)
	cookie = quiet.signUp("old@example.test", true)
	quiet.signUp("taken@example.test", false)
	for _, address := range []string{"taken@example.test", "free@example.test"} {
		if _, message, coded := errorBody(t, quiet.client.post("/change-email", `{"newEmail":"`+address+`"}`, cookie, 400)); message != "Verification email isn't enabled" || coded {
			t.Fatal("change-email without a verification sender answered", message, coded)
		}
	}
	if len(quiet.mails()) != 0 {
		t.Fatal("change-email without a verification sender sent mail")
	}
}

// An address changed at once is published in fresh session cookies, so the
// cached session view shows it, and the next sign-in uses it. A change a
// database hook declines answers success without changing, mailing or
// setting cookies.
func TestChangeEmailImmediately(t *testing.T) {
	h := newChangeEmailHost(t, authn.Options{ChangeEmailEnabled: true, UpdateEmailWithoutVerification: true, SessionCookieCache: &authn.SessionCookieCacheOptions{}}, false, true)
	cookie := h.signUp("old@example.test", false)
	h.client.user(cookie) // fills the cookie cache with the old address
	r := h.client.post("/change-email", `{"newEmail":"new@example.test","callbackURL":"/done"}`, cookie, 200)
	statusBody(t, r)
	var token, data string
	for _, c := range r.Cookies() {
		switch {
		case strings.HasSuffix(c.Name, "session_token") && c.MaxAge >= 0:
			token = c.Name + "=" + c.Value
		case strings.HasSuffix(c.Name, "session_data") && c.MaxAge >= 0:
			data = c.Name + "=" + c.Value
		}
	}
	if token == "" || data == "" {
		t.Fatal("an immediate change did not re-issue the session cookies:", r.Cookies())
	}
	if got := h.client.user(token + "; " + data); got != "new@example.test" {
		t.Fatal("the cached session showed", got)
	}
	mails := h.mails()
	if len(mails) != 1 || mails[0].User.Email != "new@example.test" || mails[0].NewEmail != "" {
		t.Fatalf("an immediate change mailed %+v", mails)
	}
	if u, err := url.Parse(mails[0].URL); err != nil || u.Query().Get("callbackURL") != "/done" {
		t.Fatal("the verification link lost its callback:", mails[0].URL)
	}
	h.client.post("/sign-in/email", `{"email":"new@example.test","password":"`+sessionEndpointPassword+`"}`, "", 200)
	h.client.post("/sign-in/email", `{"email":"old@example.test","password":"`+sessionEndpointPassword+`"}`, "", 401)

	// A browser that signed in without "remember me" keeps its marker.
	browser := newChangeEmailHost(t, authn.Options{ChangeEmailEnabled: true, UpdateEmailWithoutVerification: true}, false, false)
	browser.client.post("/sign-up/email", `{"name":"Person","email":"old@example.test","password":"`+sessionEndpointPassword+`"}`, "", 200)
	r = browser.client.post("/sign-in/email", `{"email":"old@example.test","password":"`+sessionEndpointPassword+`","rememberMe":false}`, "", 200)
	var jar []string
	for _, c := range r.Cookies() {
		jar = append(jar, c.Name+"="+c.Value)
	}
	r = browser.client.post("/change-email", `{"newEmail":"new@example.test"}`, strings.Join(jar, "; "), 200)
	marker := false
	for _, c := range r.Cookies() {
		marker = marker || strings.HasSuffix(c.Name, "dont_remember") && c.Value != "" && c.MaxAge >= 0
	}
	if !marker {
		t.Fatal("an immediate change did not re-issue the dont_remember marker:", r.Cookies())
	}

	declined := newChangeEmailHost(t, authn.Options{ChangeEmailEnabled: true, UpdateEmailWithoutVerification: true, DatabaseHooks: authn.DatabaseHooks{User: authn.ModelHooks[authn.UserRecord]{Update: authn.OperationHooks[authn.UserRecord]{
		Before: func(context.Context, *authn.UserRecord, *authn.HookContext) error { return authn.ErrSkipWrite },
	}}}}, false, true)
	cookie = declined.signUp("old@example.test", false)
	id := declined.userID("old@example.test")
	r = declined.client.post("/change-email", `{"newEmail":"new@example.test"}`, cookie, 200)
	statusBody(t, r)
	if len(r.Header.Values("Set-Cookie")) != 0 || len(declined.mails()) != 0 || !declined.owns("old@example.test", id) {
		t.Fatal("a declined change set cookies, sent mail or changed the address")
	}
}

// Opening the verification link of a change in a signed-in browser stores
// the address and re-issues that browser's session cookies; without a
// session it starts none.
func TestChangeEmailVerificationLinkCookies(t *testing.T) {
	for _, signedIn := range []bool{true, false} {
		h := newChangeEmailHost(t, authn.Options{ChangeEmailEnabled: true, SessionCookieCache: &authn.SessionCookieCacheOptions{}}, false, true)
		cookie := h.signUp("old@example.test", true)
		id := h.userID("old@example.test")
		statusBody(t, h.client.post("/change-email", `{"newEmail":"new@example.test"}`, cookie, 200))
		mails := h.mails()
		if len(mails) != 1 || mails[0].NewEmail != "new@example.test" {
			t.Fatalf("change-email mailed %+v", mails)
		}
		link, err := url.Parse(mails[0].URL)
		if err != nil {
			t.Fatal(err)
		}
		headers := http.Header{}
		if signedIn {
			headers.Set("Cookie", cookie)
		}
		r := serve(t, h.auth, "GET", link.Path+"?"+link.RawQuery, "", headers, 302)
		var token string
		for _, c := range r.Cookies() {
			if strings.HasSuffix(c.Name, "session_token") && c.MaxAge >= 0 {
				token = c.Name + "=" + c.Value
			}
		}
		if signedIn && token == "" || !signedIn && len(r.Header.Values("Set-Cookie")) != 0 {
			body, _ := io.ReadAll(r.Body)
			t.Fatalf("signed in %v: the verification link set %v (%s)", signedIn, r.Header.Values("Set-Cookie"), body)
		}
		if !h.owns("new@example.test", id) {
			t.Fatal("the verification link did not store the address")
		}
		if signedIn {
			var data string
			for _, c := range r.Cookies() {
				if strings.HasSuffix(c.Name, "session_data") && c.MaxAge >= 0 {
					data = c.Name + "=" + c.Value
				}
			}
			if data == "" {
				t.Fatal("the verification link did not re-issue the cached session view")
			}
			if got := h.client.user(token + "; " + data); got != "new@example.test" {
				t.Fatal("after the link the browser's session showed", got)
			}
		}
	}
}

// A confirmation link opened after the verification sender was removed
// redirects to its callback with the error rather than reporting progress.
func TestChangeEmailConfirmationWithoutVerificationSender(t *testing.T) {
	first := newChangeEmailHost(t, authn.Options{ChangeEmailEnabled: true}, true, true)
	cookie := first.signUp("old@example.test", true)
	statusBody(t, first.client.post("/change-email", `{"newEmail":"new@example.test"}`, cookie, 200))
	mails := first.mails()
	if len(mails) != 1 {
		t.Fatalf("change-email mailed %+v", mails)
	}
	link, err := url.Parse(mails[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	off := false
	without, err := authn.New(authn.Options{Store: first.store, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example", EmailAndPassword: true, RateLimit: &off,
		ChangeEmailEnabled: true, SendChangeEmailConfirmation: func(context.Context, authn.MailLink) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	r := serve(t, without, "GET", link.Path+"?"+link.RawQuery, "", http.Header{"Cookie": {cookie}}, 302)
	if to, _ := url.Parse(r.Header.Get("Location")); to.Path != "/" || to.Query().Get("error") != "VERIFICATION_EMAIL_NOT_ENABLED" {
		t.Fatal("the confirmation link redirected to", r.Header.Get("Location"))
	}
}
