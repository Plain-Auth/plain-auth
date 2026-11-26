package storetest

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"sync"

	auth "github.com/Plain-Org/plain-auth"
)

// authFlow signs a user up, in and out through plainauth.New on the store,
// and resets the password when the store is an AccountStore.
func authFlow(f *fixture) {
	var mu sync.Mutex
	var resetToken string
	opts := auth.Options{Store: f.store, BaseURL: "https://app.example.test", Secret: strings.Repeat("s", 32), EmailAndPassword: true,
		PasswordHash:   func(_ context.Context, p string) (string, error) { return "plain:" + p, nil },
		PasswordVerify: func(_ context.Context, encoded, p string) (bool, error) { return encoded == "plain:"+p, nil },
	}
	_, resettable := f.store.(auth.AccountStore)
	if resettable {
		opts.SendResetPassword = func(_ context.Context, l auth.MailLink) error {
			mu.Lock()
			defer mu.Unlock()
			resetToken = l.Token
			return nil
		}
	}
	a, err := auth.New(opts)
	if err != nil {
		f.Fatal("New:", err)
	}
	email := "storetest-flow-" + strings.ToLower(rand.Text()[:12]) + "@example.test"
	signedUp, err := a.SignUpEmail(f.ctx, auth.SignUpInput{Name: "Flow", Email: email, Password: "first password"}, auth.RequestMeta{})
	if err != nil {
		f.Fatal("SignUpEmail:", err)
	}
	f.cleanupUser(signedUp.User.ID)
	headers := func(token string) http.Header {
		r, _ := http.NewRequest("GET", "https://app.example.test/", nil)
		r.AddCookie(a.SessionCookie(token, true))
		return r.Header
	}
	session := func(token string) *auth.SessionResult {
		f.Helper()
		s, err := a.GetSession(f.ctx, headers(token))
		if err != nil {
			f.Fatal("GetSession:", err)
		}
		return s
	}
	if s := session(signedUp.Token); s == nil || s.User.ID != signedUp.User.ID || s.User.Email != email {
		f.Fatal("the sign-up session does not resolve to its user")
	}
	signedIn, err := a.SignInEmail(f.ctx, auth.SignInInput{Email: email, Password: "first password"}, auth.RequestMeta{})
	if err != nil || signedIn.User.ID != signedUp.User.ID {
		f.Fatal("SignInEmail:", err)
	}
	for _, in := range []auth.SignInInput{{Email: email, Password: "wrong password"}, {Email: "storetest-nobody-" + strings.ToLower(rand.Text()[:8]) + "@example.test", Password: "first password"}} {
		var apiErr *auth.APIError
		if _, err := a.SignInEmail(f.ctx, in, auth.RequestMeta{}); !errors.As(err, &apiErr) || apiErr.Status != 401 || apiErr.Code != "INVALID_EMAIL_OR_PASSWORD" {
			f.Fatal("a wrong password or unknown address was not refused with INVALID_EMAIL_OR_PASSWORD:", err)
		}
	}
	if err := a.RevokeOtherSessions(f.ctx, headers(signedIn.Token)); err != nil {
		f.Fatal("RevokeOtherSessions:", err)
	}
	if session(signedUp.Token) != nil {
		f.Fatal("a revoked session still resolves")
	}
	token := signedIn.Token
	if resettable {
		if err := a.RequestPasswordReset(f.ctx, strings.ToUpper(email), ""); err != nil {
			f.Fatal("RequestPasswordReset:", err)
		}
		mu.Lock()
		link := resetToken
		mu.Unlock()
		if link == "" {
			f.Fatal("no reset link was sent for an upper-cased address")
		}
		if err := a.ResetPassword(f.ctx, link, "second password"); err != nil {
			f.Fatal("ResetPassword:", err)
		}
		if _, err := a.SignInEmail(f.ctx, auth.SignInInput{Email: email, Password: "first password"}, auth.RequestMeta{}); err == nil {
			f.Fatal("the old password still signs in after a reset")
		}
		again, err := a.SignInEmail(f.ctx, auth.SignInInput{Email: email, Password: "second password"}, auth.RequestMeta{})
		if err != nil {
			f.Fatal("the new password does not sign in:", err)
		}
		token = again.Token
		var apiErr *auth.APIError
		if err := a.ResetPassword(f.ctx, link, "third password"); !errors.As(err, &apiErr) || apiErr.Code != "INVALID_TOKEN" {
			f.Fatal("a spent reset link was accepted:", err)
		}
	}
	if err := a.SignOut(f.ctx, headers(token)); err != nil {
		f.Fatal("SignOut:", err)
	}
	if session(token) != nil {
		f.Fatal("a signed-out session still resolves")
	}
}
