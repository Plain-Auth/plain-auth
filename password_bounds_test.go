package plainauth_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
)

func TestPasswordBoundsBeforeCredentialCallbacks(t *testing.T) {
	ctx := t.Context()
	var hashes, checks int
	var proof string
	opts := auth.Options{
		BaseURL: "http://app.example", Secret: strings.Repeat("p", 40), Store: memory.New(),
		EmailAndPassword: true, MinPasswordLength: 10, MaxPasswordLength: 14,
		PasswordHash: func(ctx context.Context, raw string) (string, error) {
			hashes++
			return auth.HashPassword(ctx, raw)
		},
		PasswordVerify: func(ctx context.Context, encoded, raw string) (bool, error) {
			checks++
			return auth.VerifyPasswordHash(ctx, encoded, raw)
		},
		SendResetPassword: func(_ context.Context, link auth.MailLink) error {
			proof = link.Token
			return nil
		},
	}
	service, err := auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	requireCode := func(err error, code string) {
		t.Helper()
		var api *auth.APIError
		if !errors.As(err, &api) || api.Code != code {
			t.Fatalf("got %v, want %s", err, code)
		}
	}
	email := "member@example.test"
	valid := strings.Repeat("🔐", 5)
	long := strings.Repeat("🔐", 8)
	input := auth.SignUpInput{Name: "Member", Email: email, Password: valid}
	if _, err := service.SignUpEmail(ctx, input, auth.RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	input.Password = long
	_, err = service.SignUpEmail(ctx, input, auth.RequestMeta{})
	requireCode(err, "PASSWORD_TOO_LONG")
	_, err = service.SignInEmail(ctx, auth.SignInInput{Email: email, Password: long}, auth.RequestMeta{})
	requireCode(err, "PASSWORD_TOO_LONG")
	requireCode(service.ResetPassword(ctx, "", long), "INVALID_TOKEN")
	requireCode(service.ResetPassword(ctx, "unused-fixture-proof", long), "PASSWORD_TOO_LONG")
	if err := service.RequestPasswordReset(ctx, email, "/done"); err != nil || proof == "" {
		t.Fatalf("reset link was not delivered: %v", err)
	}
	requireCode(service.ResetPassword(ctx, proof, "short"), "PASSWORD_TOO_SHORT")
	requireCode(service.ResetPassword(ctx, proof, long), "PASSWORD_TOO_LONG")
	if hashes != 1 || checks != 0 {
		t.Fatalf("out-of-range inputs reached the password codec: hashes=%d checks=%d", hashes, checks)
	}
	if err := service.ResetPassword(ctx, proof, valid+"x"); err != nil {
		t.Fatal(err)
	}
	requireCode(service.ResetPassword(ctx, proof, valid), "INVALID_TOKEN")
	_, err = service.SignInEmail(ctx, auth.SignInInput{Email: email, Password: valid + "x"}, auth.RequestMeta{})
	if err != nil || hashes != 2 || checks != 1 {
		t.Fatalf("accepted replacement was not committed once: hashes=%d checks=%d err=%v", hashes, checks, err)
	}
}
