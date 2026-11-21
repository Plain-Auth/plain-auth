package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/nabuhadba/go-better-auth"
	"github.com/nabuhadba/go-better-auth/adapters/sqlstore"
	"github.com/nabuhadba/go-better-auth/client"
	"github.com/nabuhadba/go-better-auth/plugins/twofactor"
	"github.com/nabuhadba/go-better-auth/schema"
	"github.com/pquerna/otp/totp"
)

func TestAccountAndAuthenticatorClient(t *testing.T) {
	ctx := t.Context()
	ddl, err := schema.Generate("sqlite", []string{"two-factor"})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sqlstore.OpenWithSchema(ctx, "sqlite", ":memory:", ddl)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const origin = "https://app.example.test"
	var emailProof, resetToken string
	off := false
	api, err := auth.New(auth.Options{
		Store: db, BaseURL: origin, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		SendVerificationOnSignUp: &off, DeleteUserEnabled: true, ChangeEmailEnabled: true,
		RevokeSessionsOnPasswordReset: true,
		SendVerificationEmail:         func(_ context.Context, m auth.MailLink) error { emailProof = m.Token; return nil },
		SendResetPassword:             func(_ context.Context, m auth.MailLink) error { resetToken = m.Token; return nil },
		Plugins:                       []auth.Plugin{twofactor.New(twofactor.Options{Issuer: "Example"})},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(origin, &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w.Result(), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	const email = "person@example.test"
	const original = "original-password"
	if _, err := c.SignUpEmail(ctx, client.SignUpRequest{Email: email, Name: "First", Password: original}); err != nil {
		t.Fatal(err)
	}
	second := "Second"
	if err := c.UpdateUser(ctx, auth.ProfileUpdate{Name: &second, ClearImage: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.SendVerificationEmail(ctx, email, ""); err != nil || emailProof == "" {
		t.Fatal("verification email:", err)
	}
	if err := c.VerifyEmail(ctx, emailProof); err != nil {
		t.Fatal(err)
	}
	if s, err := c.GetSession(ctx); err != nil || s == nil || !s.User.EmailVerified || s.User.Name != second {
		t.Fatal("updated account:", s, err)
	}
	accounts, err := c.ListAccounts(ctx)
	if err != nil || len(accounts) != 1 || accounts[0].ProviderID != "credential" {
		t.Fatal("linked accounts:", accounts, err)
	}
	var apiErr *auth.APIError
	if err = c.UnlinkAccount(ctx, accounts[0].ID); !errors.As(err, &apiErr) || apiErr.Code != "FAILED_TO_UNLINK_LAST_ACCOUNT" {
		t.Fatal("expected the last credential to be protected:", err)
	}
	if err := c.VerifyPassword(ctx, original); err != nil {
		t.Fatal(err)
	}
	const changed = "changed-password"
	result, err := c.ChangePassword(ctx, auth.ChangePasswordInput{CurrentPassword: original, NewPassword: changed, RevokeOtherSessions: true})
	if err != nil || result.Token == nil {
		t.Fatal("change password:", result, err)
	}
	enroll, err := c.EnableTOTP(ctx, changed, "Example")
	if err != nil || len(enroll.BackupCodes) == 0 {
		t.Fatal("enroll:", err)
	}
	uri, err := c.TOTPURI(ctx, changed)
	if err != nil || uri != enroll.URI {
		t.Fatal("provisioning URI:", err)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(parsed.Query().Get("secret"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if factor, err := c.VerifyTOTP(ctx, code); err != nil || factor.Token == nil {
		t.Fatal("activate:", err)
	}
	backup, err := c.GenerateBackupCodes(ctx, changed)
	if err != nil || len(backup) != 10 || backup[0] == enroll.BackupCodes[0] {
		t.Fatal("regenerate backup codes:", err)
	}
	if err := c.SignOut(ctx); err != nil {
		t.Fatal(err)
	}
	login, err := c.SignInEmail(ctx, client.SignInRequest{Email: email, Password: changed})
	if err != nil || !login.TwoFactorRedirect || login.Token != nil {
		t.Fatal("second factor required:", err)
	}
	if factor, err := c.VerifyBackupCode(ctx, backup[0], false); err != nil || factor.User.Email != email || factor.Token == nil {
		t.Fatal("complete challenge:", err)
	}
	if err := c.DisableTOTP(ctx, changed); err != nil {
		t.Fatal(err)
	}
	if err := c.RequestPasswordReset(ctx, email, "/reset"); err != nil || resetToken == "" {
		t.Fatal("reset email:", err)
	}
	const recovered = "recovered-password"
	if err := c.ResetPassword(ctx, resetToken, recovered); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SignInEmail(ctx, client.SignInRequest{Email: email, Password: recovered}); err != nil {
		t.Fatal(err)
	}
	if err := c.ChangeEmail(ctx, "moved@example.test", ""); err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyEmail(ctx, emailProof); err != nil {
		t.Fatal(err)
	}
	if s, err := c.GetSession(ctx); err != nil || s == nil || s.User.Email != "moved@example.test" {
		t.Fatal("changed email:", s, err)
	}
	if result, err := c.DeleteAccount(ctx, auth.DeleteUserInput{Password: recovered}); err != nil || !result.Success {
		t.Fatal("delete account:", err)
	}
	if s, err := c.GetSession(ctx); err != nil || s != nil {
		t.Fatal("deleted session:", s, err)
	}
}
