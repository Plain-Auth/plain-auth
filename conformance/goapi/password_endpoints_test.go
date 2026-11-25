package goapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

// passwordHost is an auth instance with a recorded reset sender and an
// ID-token provider for accounts without a password.
type passwordHost struct {
	sessionClient
	mu    sync.Mutex
	links []authn.MailLink
}

func newPasswordHost(t *testing.T) *passwordHost {
	t.Helper()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	h := &passwordHost{}
	profile := func(raw string) authn.OAuthProfile {
		return authn.OAuthProfile{Subject: raw, Email: raw + "@example.test", EmailVerified: true, Name: "Social"}
	}
	provider := authn.OAuthProvider{Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token"}},
		Resolve: func(context.Context, *oauth2.Token, string) (authn.OAuthProfile, error) {
			return authn.OAuthProfile{}, errors.New("unused")
		},
		VerifyIDToken: func(_ context.Context, raw, _ string) (authn.OAuthProfile, time.Time, error) {
			return profile(raw), time.Now().Add(time.Hour), nil
		},
	}
	off := false
	auth, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		DeleteUserEnabled: true, SocialProviders: map[string]authn.OAuthProvider{"work": provider},
		SendResetPassword: func(_ context.Context, m authn.MailLink) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			m.Request = nil
			h.links = append(h.links, m)
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	h.sessionClient = sessionClient{t, auth}
	return h
}

func (h *passwordHost) resetLinks() []authn.MailLink {
	h.mu.Lock()
	defer h.mu.Unlock()
	links := h.links
	h.links = nil
	return links
}

// socialSignIn signs in an account that has no password.
func (h *passwordHost) socialSignIn(name string) string {
	h.t.Helper()
	r := h.post("/sign-in/social", `{"provider":"work","idToken":{"token":"`+name+`","nonce":"n"}}`, "", 200)
	for _, c := range r.Cookies() {
		if strings.HasSuffix(c.Name, "session_token") {
			return c.Name + "=" + c.Value
		}
	}
	h.t.Fatal("social sign-in set no session cookie")
	return ""
}

func (h *passwordHost) signUp(email string) string {
	h.t.Helper()
	h.post("/sign-up/email", `{"name":"Person","email":"`+email+`","password":"`+sessionEndpointPassword+`"}`, "", 200)
	cookie, _ := h.signIn(email)
	return cookie
}

// Requesting a reset answers the same for any address, mails a link that
// carries the redirect, refuses an untrusted or malformed redirect, and the
// callback redirects without spending the token.
func TestPasswordResetContract(t *testing.T) {
	h := newPasswordHost(t)
	h.signUp("ada@example.test")
	const message = "If this email exists in our system, check your email for the reset link"
	for _, email := range []string{"ada@example.test", "nobody@example.test"} {
		r := h.post("/request-password-reset", `{"email":"`+email+`","redirectTo":"/choose?z=1"}`, "", 200)
		var out map[string]any
		if err := json.NewDecoder(r.Body).Decode(&out); err != nil || len(out) != 2 || out["status"] != true || out["message"] != message {
			t.Fatalf("a reset request for %s answered %v", email, out)
		}
	}
	links := h.resetLinks()
	if len(links) != 1 || links[0].User.Email != "ada@example.test" {
		t.Fatalf("reset requests mailed %+v", links)
	}
	link, err := url.Parse(links[0].URL)
	if err != nil || link.Path != "/api/auth/reset-password/"+links[0].Token || link.Query().Get("callbackURL") != "/choose?z=1" {
		t.Fatal("the reset link was", links[0].URL)
	}
	if code, message, _ := errorBody(t, h.post("/request-password-reset", `{"email":"ada@example.test","redirectTo":"https://evil.example"}`, "", 403)); code != "INVALID_REDIRECT_URL" || message != "Invalid redirectURL" {
		t.Fatal("an untrusted redirect answered", code, message)
	}
	if _, message, coded := errorBody(t, h.post("/request-password-reset", `{"email":"ada@example.test","redirectTo":123}`, "", 400)); message != "Invalid redirectURL: expected a string" || coded {
		t.Fatal("a numeric redirect answered", message, coded)
	}
	if code, message, _ := errorBody(t, h.post("/request-password-reset", `{"email":"ada@example.test","redirectTo":null}`, "", 400)); code != "VALIDATION_ERROR" || message != "[body.redirectTo] Invalid input: expected string, received null" {
		t.Fatal("a null redirect answered", code, message)
	}
	if code, _, _ := errorBody(t, h.post("/request-password-reset?callbackURL=https://evil.example", `{"email":"ada@example.test","callbackURL":""}`, "", 403)); code != "INVALID_CALLBACK_URL" {
		t.Fatal("an empty body callback skipped the query callback's check:", code)
	}
	if len(h.resetLinks()) != 0 {
		t.Fatal("a refused reset request sent mail")
	}

	token := links[0].Token
	r := h.get("/reset-password/"+token+"?callbackURL="+url.QueryEscape("/choose?z=1"), "", 302)
	if to, _ := url.Parse(r.Header.Get("Location")); to.Path != "/choose" || to.Query().Get("token") != token || to.Query().Get("z") != "1" {
		t.Fatal("the reset callback redirected to", r.Header.Get("Location"))
	}
	if to, _ := url.Parse(h.get("/reset-password/unknown?callbackURL=/choose", "", 302).Header.Get("Location")); to.Path != "/choose" || to.Query().Get("error") != "INVALID_TOKEN" {
		t.Fatal("an unknown reset token redirected to", to)
	}
	if to := h.get("/reset-password/"+token+"?callbackURL=", "", 302).Header.Get("Location"); to != "https://auth.example/api/auth/error?error=INVALID_TOKEN" {
		t.Fatal("an empty callback redirected to", to)
	}
	for query, message := range map[string]string{
		"":                               "[query.callbackURL] Invalid input: expected string, received undefined",
		"?callbackURL=/a&callbackURL=/b": "[query.callbackURL] Invalid input: expected string, received array",
	} {
		if code, got, _ := errorBody(t, h.get("/reset-password/"+token+query, "", 400)); code != "VALIDATION_ERROR" || got != message {
			t.Fatalf("callback query %q answered %s %s", query, code, got)
		}
	}
	if code, _, _ := errorBody(t, h.get("/reset-password/"+token+"?callbackURL=https://evil.example", "", 403)); code != "INVALID_CALLBACK_URL" {
		t.Fatal("an untrusted reset callback answered", code)
	}

	// Resetting: every body problem is reported, a missing token is checked
	// first, a short password keeps the token, and the query token works.
	if _, message, _ := errorBody(t, h.post("/reset-password", `{"newPassword":5,"token":7}`, "", 400)); message != "[body.newPassword] Invalid input: expected string, received number; [body.token] Invalid input: expected string, received number" {
		t.Fatal("a malformed reset answered", message)
	}
	if code, _, _ := errorBody(t, h.post("/reset-password", `{"newPassword":"x"}`, "", 400)); code != "INVALID_TOKEN" {
		t.Fatal("a reset without a token answered", code)
	}
	if code, _, _ := errorBody(t, h.post("/reset-password?token="+token, `{"newPassword":"short"}`, "", 400)); code != "PASSWORD_TOO_SHORT" {
		t.Fatal("a short reset password answered", code)
	}
	statusBody(t, h.post("/reset-password?token="+token, `{"newPassword":"a brand new password"}`, "", 200))
	h.post("/sign-in/email", `{"email":"ada@example.test","password":"a brand new password"}`, "", 200)
	if code, _, _ := errorBody(t, h.post("/reset-password?token="+token, `{"newPassword":"another new password"}`, "", 400)); code != "INVALID_TOKEN" {
		t.Fatal("a spent reset token answered", code)
	}

	// An account without a password gets one through a reset.
	h.socialSignIn("sam")
	h.post("/request-password-reset", `{"email":"sam@example.test"}`, "", 200)
	links = h.resetLinks()
	if len(links) != 1 {
		t.Fatal("an account without a password got no reset mail")
	}
	statusBody(t, h.post("/reset-password", `{"newPassword":"a first password","token":"`+links[0].Token+`"}`, "", 200))
	h.post("/sign-in/email", `{"email":"sam@example.test","password":"a first password"}`, "", 200)
}

// Checking and changing a password: a user without a password gets
// CREDENTIAL_ACCOUNT_NOT_FOUND from change-password and delete-user but
// INVALID_PASSWORD from verify-password, every body problem is reported,
// and a change without revokeOtherSessions keeps the other sessions.
func TestPasswordCheckContract(t *testing.T) {
	h := newPasswordHost(t)
	cookie := h.signUp("ada@example.test")
	other, _ := h.signIn("ada@example.test")
	if code, _, _ := errorBody(t, h.post("/verify-password", `{"password":"wrong password here"}`, cookie, 400)); code != "INVALID_PASSWORD" {
		t.Fatal("a wrong password answered", code)
	}
	statusBody(t, h.post("/verify-password", `{"password":"`+sessionEndpointPassword+`"}`, cookie, 200))
	if code, _, _ := errorBody(t, h.post("/verify-password", `{"password":"x"}`, "", 401)); code != "UNAUTHORIZED" {
		t.Fatal("verify-password without a session answered", code)
	}
	if _, message, _ := errorBody(t, h.post("/change-password", `{}`, cookie, 400)); message != "[body.newPassword] Invalid input: expected string, received undefined; [body.currentPassword] Invalid input: expected string, received undefined" {
		t.Fatal("an empty change-password answered", message)
	}
	r := h.post("/change-password", `{"currentPassword":"`+sessionEndpointPassword+`","newPassword":"a changed password"}`, cookie, 200)
	var changed struct {
		Token *string
		User  struct{ Email string }
	}
	if err := json.NewDecoder(r.Body).Decode(&changed); err != nil || changed.Token != nil || changed.User.Email != "ada@example.test" {
		t.Fatal("change-password without revocation answered", changed, err)
	}
	if h.user(other) != "ada@example.test" {
		t.Fatal("change-password without revocation ended another session")
	}

	social := h.socialSignIn("sam")
	if code, _, _ := errorBody(t, h.post("/verify-password", `{"password":"any password at all"}`, social, 400)); code != "INVALID_PASSWORD" {
		t.Fatal("verify-password without a password answered", code)
	}
	for path, body := range map[string]string{
		"/change-password": `{"currentPassword":"any password at all","newPassword":"a changed password"}`,
		"/delete-user":     `{"password":"any password at all"}`,
	} {
		if code, message, _ := errorBody(t, h.post(path, body, social, 400)); code != "CREDENTIAL_ACCOUNT_NOT_FOUND" || message != "Credential account not found" {
			t.Fatal(path, "without a password answered", code, message)
		}
	}
	if h.user(social) != "sam@example.test" {
		t.Fatal("a refused delete-user ended the session")
	}
}

// SetPassword gives an account without a password its first one, once. It
// is a Go method only; the HTTP route does not exist.
func TestSetPasswordContract(t *testing.T) {
	h := newPasswordHost(t)
	social := h.socialSignIn("sam")
	headers := http.Header{"Cookie": {social}}
	var api *authn.APIError
	if err := h.auth.(*authn.Auth).SetPassword(t.Context(), http.Header{}, "a first password"); !errors.As(err, &api) || api.Code != "UNAUTHORIZED" {
		t.Fatal("SetPassword without a session returned", err)
	}
	if err := h.auth.(*authn.Auth).SetPassword(t.Context(), headers, "short"); !errors.As(err, &api) || api.Code != "PASSWORD_TOO_SHORT" {
		t.Fatal("a short first password returned", err)
	}
	if err := h.auth.(*authn.Auth).SetPassword(t.Context(), headers, strings.Repeat("x", 200)); !errors.As(err, &api) || api.Code != "PASSWORD_TOO_LONG" {
		t.Fatal("a long first password returned", err)
	}
	if err := h.auth.(*authn.Auth).SetPassword(t.Context(), headers, "a first password"); err != nil {
		t.Fatal(err)
	}
	h.post("/sign-in/email", `{"email":"sam@example.test","password":"a first password"}`, "", 200)
	if err := h.auth.(*authn.Auth).SetPassword(t.Context(), headers, "a second password"); !errors.As(err, &api) || api.Code != "PASSWORD_ALREADY_SET" {
		t.Fatal("a second first password returned", err)
	}
	h.post("/sign-in/email", `{"email":"sam@example.test","password":"a first password"}`, "", 200)
	serve(t, h.auth, "POST", "/api/auth/set-password", `{"newPassword":"a third password"}`, h.headers(social), 404)
}
