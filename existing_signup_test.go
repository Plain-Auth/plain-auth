package stonewrit_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/memory"
)

// Wrappers model third-party stores with and without the optional mailbox lookup.
type signUpOnlyStore struct{ auth.Store }
type failingSignUpLookup struct {
	auth.Store
	err error
}

func (s failingSignUpLookup) FindAccountUser(context.Context, string) (auth.User, error) {
	return auth.User{}, s.err
}

func TestExistingSignUpOptionalStore(t *testing.T) {
	store := memory.New()
	ctx := t.Context()
	var calls int
	var diagnostics bytes.Buffer
	opts := auth.Options{
		Store: signUpOnlyStore{store}, BaseURL: "http://example.test", Secret: strings.Repeat("s", 40),
		EmailAndPassword: true, Logger: slog.New(slog.NewJSONHandler(&diagnostics, nil)),
		OnExistingUserSignUp: func(context.Context, auth.User, *http.Request) error { calls++; return nil },
	}
	input := auth.SignUpInput{Name: "Existing", Email: "existing@example.test", Password: "private-fixture-password"}
	a, err := auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.SignUpEmail(ctx, input, auth.RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	if _, err = a.SignUpEmail(ctx, input, auth.RequestMeta{}); err == nil || calls != 0 {
		t.Fatal("an ordinary store should keep its existing duplicate-signup behavior")
	}
	opts.DisableAutoSignIn = true
	if _, err := auth.New(opts); err == nil {
		t.Fatal("protected observer on a store without mailbox lookup accepted")
	}
	opts.OnExistingUserSignUp = nil
	a, err = auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.SignUpEmail(ctx, input, auth.RequestMeta{}); err != nil {
		t.Fatal("existing protected callers now require optional storage")
	}
	opts.OnExistingUserSignUp = func(context.Context, auth.User, *http.Request) error { calls++; return nil }
	for _, e := range []error{auth.ErrNotFound, errors.New("private database diagnostic")} {
		opts.Store = failingSignUpLookup{store, e}
		a, err = auth.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		result, err := a.SignUpEmail(ctx, input, auth.RequestMeta{})
		if err != nil || calls != 0 || result.Token != "" || result.User.ID == "" {
			t.Fatal("failure to obtain a trustworthy owner changed the opaque caller result")
		}
	}
	if !strings.Contains(diagnostics.String(), "Existing-user sign-up owner lookup failed") || strings.Contains(diagnostics.String(), "private database diagnostic") {
		t.Fatal("unredacted owner lookup diagnostic")
	}
}

func TestExistingSignUpObserverGetsProfileCopy(t *testing.T) {
	// A notification must not accidentally mutate a stored profile through its pointer fields.
	ctx := t.Context()
	store := memory.New()
	expiry := time.Now().UTC().Add(time.Hour)
	reason, method := "original reason", "social"
	enabled := true
	owner := auth.User{
		ID: "customer", Name: "A customer", Email: "customer@example.test", LastLoginMethod: &method, TwoFactorEnabled: &enabled,
		AdminUserFields: &auth.AdminUserFields{Role: "customer", Banned: true, BanReason: &reason, BanExpires: &expiry},
	}
	if err := store.CreateUser(ctx, owner, "", nil); err != nil {
		t.Fatal(err)
	}
	a, err := auth.New(auth.Options{
		Store: store, BaseURL: "http://example.test", Secret: strings.Repeat("k", 40), EmailAndPassword: true, DisableAutoSignIn: true,
		OnExistingUserSignUp: func(ctx context.Context, notice auth.User, r *http.Request) error {
			notice.Role = "admin"
			*notice.LastLoginMethod = "changed"
			*notice.BanReason = "changed"
			*notice.BanExpires = time.Time{}
			*notice.TwoFactorEnabled = false
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.SignUpEmail(ctx, auth.SignUpInput{Email: owner.Email, Name: "Attempt", Password: "sample private password"}, auth.RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	saved, err := store.FindAccountUser(ctx, owner.Email)
	if err != nil || saved.Role != "customer" || *saved.LastLoginMethod != "social" || *saved.BanReason != "original reason" || saved.BanExpires.IsZero() || !*saved.TwoFactorEnabled {
		t.Fatal("changes to the observer snapshot escaped into the memory store")
	}
}
