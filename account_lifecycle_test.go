package authn_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	authn "github.com/nabuhadba/go-better-auth"
)

func TestVerificationGatedSignUpAndSignIn(t *testing.T) {
	off := false
	var messages []authn.MailLink
	auth := newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example", RateLimit: &off, RequireEmailVerification: true, SendVerificationOnSignIn: true,
		SendVerificationEmail: func(_ context.Context, m authn.MailLink) error { messages = append(messages, m); return nil },
	})
	input := authn.SignUpInput{Name: "First", Email: "gated@example.test", Password: "a correct password"}
	ctx := t.Context()
	first, err := auth.SignUpEmail(ctx, input, authn.RequestMeta{CallbackURL: "/after"})
	if err != nil || first.Token != "" || len(messages) != 1 {
		t.Fatalf("verification-gated signup: %+v, %v", first, err)
	}
	second, err := auth.SignUpEmail(ctx, input, authn.RequestMeta{})
	if err != nil || second.Token != "" || second.User.ID == first.User.ID || len(messages) != 1 {
		t.Fatal("duplicate registration disclosed an existing account or sent mail")
	}
	login := authn.SignInInput{Email: input.Email, Password: input.Password}
	var e *authn.APIError
	if _, err = auth.SignInEmail(ctx, login, authn.RequestMeta{}); !errors.As(err, &e) || e.Code != "EMAIL_NOT_VERIFIED" || len(messages) != 2 {
		t.Fatalf("unverified login: %v", err)
	}
	u, err := url.Parse(messages[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	if res := serve(t, auth, "GET", u.RequestURI(), "", nil, 302); res.Header.Get("Location") != "/after" {
		t.Fatal("missing signup callback")
	}
	ok, err := auth.SignInEmail(ctx, login, authn.RequestMeta{})
	if err != nil || ok.Token == "" || !ok.User.EmailVerified {
		t.Fatalf("verified login: %v", err)
	}
	disabled := newHTTPAuth(t, authn.Options{BaseURL: "http://auth.example", DisableSignUp: true})
	if _, err = disabled.SignUpEmail(ctx, input, authn.RequestMeta{}); !errors.As(err, &e) || e.Code != "EMAIL_PASSWORD_SIGN_UP_DISABLED" {
		t.Fatalf("registration control: %v", err)
	}
	noAuto := newHTTPAuth(t, authn.Options{BaseURL: "http://auth.example", DisableAutoSignIn: true})
	registered, err := noAuto.SignUpEmail(ctx, input, authn.RequestMeta{})
	if err != nil || registered.Token != "" {
		t.Fatal("autoSignIn controlled registration unexpectedly signed in")
	}
	if signed, err := noAuto.SignInEmail(ctx, login, authn.RequestMeta{}); err != nil || signed.Token == "" {
		t.Fatal("manual login failed")
	}
}

func TestConfirmedEmailChangeAndDeletion(t *testing.T) {
	off := false
	var confirmations, verifications, deletions []authn.MailLink
	auth := newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example", RateLimit: &off, DeleteUserEnabled: true, ChangeEmailEnabled: true,
		SendChangeEmailConfirmation: func(_ context.Context, m authn.MailLink) error {
			confirmations = append(confirmations, m)
			return nil
		},
		SendVerificationEmail: func(_ context.Context, m authn.MailLink) error {
			verifications = append(verifications, m)
			return nil
		},
		SendDeleteAccountVerification: func(_ context.Context, m authn.MailLink) error { deletions = append(deletions, m); return nil },
	})
	register := func(email string) (authn.AuthResult, http.Header) {
		t.Helper()
		input := authn.SignUpInput{Name: email, Email: email, Password: "a test password"}
		signup, err := auth.SignUpEmail(t.Context(), input, authn.RequestMeta{})
		if err != nil {
			t.Fatal(err)
		}
		c := auth.SessionCookie(signup.Token, true)
		h := http.Header{"Content-Type": {"application/json"}, "Origin": {"https://auth.example"}, "Cookie": {c.Name + "=" + c.Value}}
		return signup, h
	}
	owner, h := register("old@example.test")
	_, other := register("other@example.test")
	serve(t, auth, "POST", "/api/auth/send-verification-email", `{"email":"old@example.test"}`, h, 200)
	if err := auth.VerifyEmail(t.Context(), verifications[0].Token); err != nil {
		t.Fatal(err)
	}
	serve(t, auth, "POST", "/api/auth/change-email", `{"newEmail":"new@example.test","callbackURL":"/account"}`, h, 200)
	if len(confirmations) != 1 || confirmations[0].User.Email != owner.User.Email || confirmations[0].NewEmail != "new@example.test" {
		t.Fatal("wrong address for current inbox confirmation")
	}
	confirmPath := "/api/auth/verify-email?token=" + confirmations[0].Token
	serve(t, auth, "GET", confirmPath, "", other, 401)
	serve(t, auth, "GET", confirmPath, "", h, 200)
	if len(verifications) != 2 || verifications[1].User.Email != "new@example.test" {
		t.Fatal("replacement inbox was not sent its own verification")
	}
	newPath := "/api/auth/verify-email?token=" + verifications[1].Token
	serve(t, auth, "GET", newPath, "", h, 200)
	serve(t, auth, "GET", newPath, "", h, 401)
	session, err := auth.GetSession(t.Context(), h)
	if err != nil || session == nil || session.User.Email != "new@example.test" || !session.User.EmailVerified {
		t.Fatal("change did not persist")
	}
	var e *authn.APIError
	if err = auth.SetPassword(t.Context(), h, "should not overwrite"); !errors.As(err, &e) || e.Code != "PASSWORD_ALREADY_SET" {
		t.Fatalf("set an existing password: %v", err)
	}
	serve(t, auth, "POST", "/api/auth/set-password", `{"newPassword":"should not overwrite"}`, h, 404)
	serve(t, auth, "POST", "/api/auth/delete-user", `{"callbackURL":"/goodbye"}`, h, 200)
	if len(deletions) != 1 || deletions[0].User.Email != "new@example.test" {
		t.Fatal("missing owner-bound deletion link")
	}
	d, err := url.Parse(deletions[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	serve(t, auth, "GET", d.RequestURI(), "", other, 404)
	serve(t, auth, "GET", d.RequestURI(), "", h, 302)
	if sess, err := auth.GetSession(t.Context(), h); err != nil || sess != nil {
		t.Fatal("deleted account session still active")
	}
	if sess, err := auth.GetSession(t.Context(), other); err != nil || sess == nil {
		t.Fatal("unrelated account was deleted")
	}
}

func TestFreshDeletionAndUnverifiedAddressChange(t *testing.T) {
	off := false
	auth := newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example", RateLimit: &off, DeleteUserEnabled: true, ChangeEmailEnabled: true, UpdateEmailWithoutVerification: true})
	user, err := auth.SignUpEmail(t.Context(), authn.SignUpInput{Name: "Fixture", Email: "old@example.test", Password: "a test password"}, authn.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	c := auth.SessionCookie(user.Token, true)
	h := http.Header{"Content-Type": {"application/json"}, "Origin": {"https://auth.example"}, "Cookie": {c.Name + "=" + c.Value}}
	serve(t, auth, "POST", "/api/auth/change-email", `{"newEmail":"after@example.test"}`, h, 200)
	curr, err := auth.GetSession(t.Context(), h)
	if err != nil || curr.User.Email != "after@example.test" || curr.User.EmailVerified {
		t.Fatal("unverified address change")
	}
	serve(t, auth, "POST", "/api/auth/delete-user", `{"password":"wrong"}`, h, 400)
	res := serve(t, auth, "POST", "/api/auth/delete-user", `{}`, h, 200)
	var body struct{ Message string }
	if err = json.NewDecoder(res.Body).Decode(&body); err != nil || !strings.Contains(body.Message, "deleted") {
		t.Fatal("fresh-session deletion failed")
	}
}
