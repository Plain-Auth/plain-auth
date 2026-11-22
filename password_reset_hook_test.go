package plainauth_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
)

func TestPasswordResetHookWithExistingAccountAdapter(t *testing.T) {
	ctx := t.Context()
	mem := memory.New()
	// Expose only the existing interface, as an independent custom adapter would.
	legacy := struct {
		auth.Store
		auth.AccountStore
	}{mem, mem}
	marker := errors.New("application observer failure")
	calls := 0
	var link auth.MailLink
	opts := auth.Options{Store: legacy, BaseURL: "https://auth.example.test", Secret: strings.Repeat("a", 40), EmailAndPassword: true, SendResetPassword: func(_ context.Context, m auth.MailLink) error { link = m; return nil },
		OnPasswordReset: func(_ context.Context, u auth.User, r *http.Request) error {
			calls++
			if r != nil || u.ID != link.User.ID || u.Email != link.User.Email {
				t.Error("incorrect custom-store callback binding")
			}
			return marker
		}}
	a, err := auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	const email = "adapter@example.test"
	if _, err = a.SignUpEmail(ctx, auth.SignUpInput{Name: "Owner", Email: email, Password: "before change"}, auth.RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	if err = a.RequestPasswordReset(ctx, email, ""); err != nil {
		t.Fatal(err)
	}
	if err = a.ResetPassword(ctx, link.Token, "after change"); !errors.Is(err, marker) {
		t.Fatal("native caller lost the observer error", err)
	}
	if err = a.ResetPassword(ctx, link.Token, "replay change"); err == nil || calls != 1 {
		t.Fatal("replayed post-commit callback", err, calls)
	}
	if _, err = a.SignInEmail(ctx, auth.SignInInput{Email: email, Password: "after change"}, auth.RequestMeta{}); err != nil {
		t.Fatal("credential rollback after callback", err)
	}
	opts.OnPasswordReset = func(context.Context, auth.User, *http.Request) error { panic("private callback detail") }
	panics, err := auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err = panics.RequestPasswordReset(ctx, email, ""); err != nil {
		t.Fatal(err)
	}
	if err = panics.ResetPassword(ctx, link.Token, "after observer panic"); err == nil || strings.Contains(err.Error(), "private callback detail") {
		t.Fatal("uncontained callback panic", err)
	}
	if _, err = panics.SignInEmail(ctx, auth.SignInInput{Email: email, Password: "after observer panic"}, auth.RequestMeta{}); err != nil {
		t.Fatal("credential rollback after observer panic", err)
	}
	mail, err := auth.NewEmailOTP(auth.EmailOTPOptions{Send: func(context.Context, auth.EmailOTPMessage) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	opts.Plugins = []auth.Plugin{mail}
	opts.SendResetPassword = nil
	opts.Store = struct {
		auth.Store
		auth.EmailOTPStore
	}{mem, mem}
	if _, err = auth.New(opts); err == nil {
		t.Fatal("legacy email OTP adapter cannot defer verification")
	}
	opts.OnPasswordReset = nil
	if _, err = auth.New(opts); err != nil {
		t.Fatal("a callback-free installation lost adapter compatibility", err)
	}
}
