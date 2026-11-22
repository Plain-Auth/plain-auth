package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	auth "github.com/Plain-Auth/plain-auth"
)

func resetHookFixture(opts *auth.Options, path string) {
	opts.RevokeSessionsOnPasswordReset = true
	opts.SendResetPassword = func(_ context.Context, message auth.MailLink) error {
		return os.WriteFile(path+".reset-link", []byte(message.Token), 0600)
	}
	opts.OnPasswordReset = func(ctx context.Context, user auth.User, r *http.Request) error {
		stored, _, err := opts.Store.Credential(ctx, user.Email)
		if err != nil {
			return err
		}
		sessions, err := opts.Store.ListSessions(ctx, user.ID)
		if err != nil {
			return err
		}
		record := map[string]any{"id": user.ID, "email": user.Email, "verified": user.EmailVerified, "storedVerified": stored.EmailVerified, "sessions": len(sessions), "method": r.Method, "path": r.URL.Path}
		if user.PhoneNumberFields != nil && user.PhoneNumber != nil {
			record["phone"] = *user.PhoneNumber
		}
		f, err := os.OpenFile(path+".reset-events", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		err = json.NewEncoder(f).Encode(record)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if r.Header.Get("X-Reset-Outcome") == "fail" {
			return errors.New("private fixture notification failure")
		}
		return nil
	}
}
