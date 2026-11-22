package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestPasswordCodecAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			ddl, err := schema.Generate(dialect, []string{"admin"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			var derived, checked, policy int
			var mail auth.MailLink
			opts := auth.Options{Store: store, BaseURL: "https://example.test", Secret: strings.Repeat("s", 32), EmailAndPassword: true,
				Plugins: []auth.Plugin{{ID: "password-policy", OnValidateNewPassword: func(context.Context, string, string) error { policy++; return nil }}},
				PasswordHash: func(ctx context.Context, raw string) (string, error) {
					derived++
					encoded, err := auth.HashPassword(ctx, raw)
					return "host-v1$" + encoded, err
				},
				PasswordVerify: func(ctx context.Context, encoded, raw string) (bool, error) {
					checked++
					return auth.VerifyPasswordHash(ctx, strings.TrimPrefix(encoded, "host-v1$"), raw)
				},
				SendResetPassword: func(_ context.Context, m auth.MailLink) error { mail = m; return nil },
			}
			service, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			const raw = "a nontrivial credential"
			u, err := service.BootstrapAdmin(ctx, "First", "first@example.test", raw)
			if err != nil {
				t.Fatal(err)
			}
			_, hash, err := store.Credential(ctx, u.Email)
			if err != nil || !strings.HasPrefix(hash, "host-v1$") {
				t.Fatalf("bootstrap credential %v", err)
			}
			if _, err := service.BootstrapAdmin(ctx, "Second", "second@example.test", raw); !errors.Is(err, auth.ErrAdminExists) {
				t.Fatalf("second bootstrap %v", err)
			}

			login := func(address, password string) (auth.AuthResult, error) {
				return service.SignInEmail(ctx, auth.SignInInput{Email: address, Password: password}, auth.RequestMeta{})
			}
			signed, err := login(u.Email, raw)
			if err != nil || signed.Token == "" {
				t.Fatalf("bootstrap login %v", err)
			}
			h := http.Header{"Cookie": {service.SessionCookie(signed.Token, true).String()}}
			if err = service.VerifyPassword(ctx, h, raw); err != nil {
				t.Fatal(err)
			}
			if _, err = service.ChangePassword(ctx, h, auth.ChangePasswordInput{CurrentPassword: raw, NewPassword: "changed password"}, auth.RequestMeta{}); err != nil {
				t.Fatal(err)
			}
			if err = service.RequestPasswordReset(ctx, u.Email, ""); err != nil || mail.Token == "" {
				t.Fatalf("request reset %v", err)
			}
			if err = service.ResetPassword(ctx, mail.Token, "reset password"); err != nil {
				t.Fatal(err)
			}
			if _, err = login(u.Email, "reset password"); err != nil {
				t.Fatal(err)
			}

			// Roll out a verifier that understands old and new encodings without
			// rewriting stored credentials or issuing sessions on failed attempts.
			opts.PasswordHash, opts.PasswordVerify = nil, nil
			old, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			legacy, err := old.SignUpEmail(ctx, auth.SignUpInput{Name: "Existing", Email: "existing@example.test", Password: raw}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = login(legacy.User.Email, raw); err != nil {
				t.Fatal(err)
			}
			beforeHash, beforeVerify, beforePolicy := derived, checked, policy
			var denial *auth.APIError
			if _, err = login("missing@example.test", raw); !errors.As(err, &denial) || denial.Code != "INVALID_EMAIL_OR_PASSWORD" {
				t.Fatalf("missing account %v", err)
			}
			if derived != beforeHash+1 || checked != beforeVerify || policy != beforePolicy {
				t.Fatal("missing login used a stored credential or ran a password-setting policy")
			}
			if _, err = login(u.Email, "wrong password"); !errors.As(err, &denial) || denial.Code != "INVALID_EMAIL_OR_PASSWORD" || checked != beforeVerify+1 {
				t.Fatalf("wrong password %v", err)
			}
		})
	}
}
