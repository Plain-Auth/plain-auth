package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"

	auth "github.com/Stonewrit/stonewrit-auth"
)

func configureSignUpObserver(opts *auth.Options, mode, path string) {
	opts.RequireEmailVerification = mode == "verify" || mode == "both"
	opts.DisableAutoSignIn = mode == "no-session" || mode == "both"
	off := false
	opts.RateLimit = &off
	opts.SendVerificationOnSignUp = &off
	opts.OnExistingUserSignUp = func(ctx context.Context, u auth.User, r *http.Request) error {
		data, err := json.Marshal(map[string]any{"user": u, "path": r.URL.Path})
		if err != nil {
			return err
		}
		out, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = out.Write(append(data, '\n'))
		return err
	}
}
