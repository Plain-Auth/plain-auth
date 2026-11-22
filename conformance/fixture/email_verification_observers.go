package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	auth "github.com/Plain-Auth/plain-auth"
)

func verificationHookFixture(opts *auth.Options, path string) {
	on := true
	opts.AutoSignInAfterVerification, opts.ChangeEmailEnabled = true, true
	opts.SendVerificationOnSignUp = &on
	saveLink := func(_ context.Context, m auth.MailLink) error {
		return os.WriteFile(path+".observer-link", []byte(m.Token), 0600)
	}
	opts.SendVerificationEmail, opts.SendChangeEmailConfirmation = saveLink, saveLink
	observe := func(stage string) auth.EmailVerificationHook {
		return func(ctx context.Context, u auth.User, r *http.Request) error {
			stored, err := opts.Store.(interface {
				FindAccountUser(context.Context, string) (auth.User, error)
			}).FindAccountUser(ctx, u.Email)
			if err != nil {
				return err
			}
			f, err := os.OpenFile(path+".verification-events", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			defer f.Close()
			err = json.NewEncoder(f).Encode(map[string]any{"stage": stage, "id": u.ID, "email": u.Email, "name": u.Name, "verified": u.EmailVerified, "stored": stored.EmailVerified, "method": r.Method, "path": r.URL.Path})
			if err == nil && r.Header.Get("X-Verify-Outcome") == stage {
				return errors.New("private observer fixture detail")
			}
			return err
		}
	}
	opts.BeforeEmailVerification, opts.AfterEmailVerification = observe("before"), observe("after")
}
