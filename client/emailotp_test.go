package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/memory"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlite"
	"github.com/Stonewrit/stonewrit-auth/client"
	"github.com/Stonewrit/stonewrit-auth/plugins/emailotp"
)

func TestNativeEmailOTPClient(t *testing.T) {
	t.Run("memory", func(t *testing.T) { runNativeEmailOTPClient(t, memory.New()) })
	t.Run("sqlite", func(t *testing.T) {
		s, err := sqlite.Open(":memory:")
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		runNativeEmailOTPClient(t, s)
	})
}
func runNativeEmailOTPClient(t *testing.T, s auth.Store) {
	var delivery emailotp.Message
	p, err := emailotp.New(emailotp.Options{StoreOTP: "encrypted", ChangeEmail: emailotp.ChangeOptions{Enabled: true, VerifyCurrentEmail: true}, Send: func(_ context.Context, m emailotp.Message) error { delivery = m; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://sdk.example.test"
	a, err := auth.New(auth.Options{Store: s, BaseURL: origin, Secret: "synthetic-sdk-private-mailbox-secret-001", Plugins: []auth.Plugin{p}, EmailAndPassword: true})
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(origin+"/api/auth", &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w.Result(), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	const email = "sdk@example.test"
	if err = c.SendEmailOTP(ctx, email, emailotp.SignIn); err != nil {
		t.Fatal(err)
	}
	login, err := c.SignInEmailOTP(ctx, auth.EmailOTPSignInInput{Email: email, OTP: delivery.OTP, Name: "Inbox"})
	if err != nil || login.Token == "" || !login.User.EmailVerified {
		t.Fatal("OTP login", err)
	}
	session, err := c.GetSession(ctx)
	if err != nil || session == nil || session.Session.Token != login.Token {
		t.Fatal("OTP login cookie jar", err)
	}
	if err = c.SendEmailOTP(ctx, email, emailotp.VerifyEmail); err != nil {
		t.Fatal(err)
	}
	if err = c.CheckEmailOTP(ctx, email, delivery.OTP, emailotp.VerifyEmail); err != nil {
		t.Fatal(err)
	}
	user, err := c.VerifyEmailOTP(ctx, email, delivery.OTP)
	if err != nil || user.ID != login.User.ID {
		t.Fatal("verify via native client", err)
	}
	if err = c.RequestPasswordResetEmailOTP(ctx, email); err != nil {
		t.Fatal(err)
	}
	if err = c.ResetPasswordEmailOTP(ctx, email, delivery.OTP, "new-mailbox-password"); err != nil {
		t.Fatal(err)
	}
	if err = c.ResetPasswordEmailOTP(ctx, email, delivery.OTP, "replayed-password"); err == nil {
		t.Fatal("client reset accepted a replay")
	}
	const updated = "updated-sdk@example.test"
	if err = c.SendEmailOTP(ctx, email, emailotp.VerifyEmail); err != nil {
		t.Fatal(err)
	}
	if err = c.RequestEmailChangeOTP(ctx, updated, delivery.OTP); err != nil {
		t.Fatal(err)
	}
	if delivery.Type != emailotp.ChangeEmail || delivery.Email != updated {
		t.Fatal("current mailbox verification failed to deliver to new address")
	}
	if err = c.ChangeEmailOTP(ctx, updated, delivery.OTP); err != nil {
		t.Fatal(err)
	}
	session, err = c.GetSession(ctx)
	if err != nil || session.User.Email != updated || session.Session.Token != login.Token {
		t.Fatal("changed mailbox login did not retain its session", err)
	}

}
