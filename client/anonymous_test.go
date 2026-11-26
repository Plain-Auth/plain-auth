package client_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/anonymous"
)

func TestGuestClientOnMemoryStore(t *testing.T) {
	emails := []string{"invalid", "custom@guest.test", ""}
	received := false
	// A generated address takes precedence over the domain.
	opts := anonymous.Options{EmailDomainName: "ignored.example", GenerateRandomEmail: func(context.Context) (string, error) { v := emails[0]; emails = emails[1:]; return v, nil }, OnLinkAccount: func(_ context.Context, e anonymous.Link) error {
		received = e.Request.URL.Path == "/api/auth/sign-up/email" && e.AnonymousUser.User.Email == "custom@guest.test" && e.NewUser.User.Email == "registered@example.test"
		return nil
	}}
	p, err := anonymous.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://app.example"
	s := memory.New()
	a, err := authn.New(authn.Options{Store: s, BaseURL: origin, Secret: strings.Repeat("z", 32), EmailAndPassword: true, Plugins: []authn.Plugin{p}})
	if err != nil {
		t.Fatal(err)
	}
	serve := func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w.Result(), nil
	}
	c, err := client.New(origin, &http.Client{Transport: transport(serve)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.SignInAnonymous(t.Context())
	var validation *authn.APIError
	if !errors.As(err, &validation) || validation.Code != "INVALID_EMAIL_FORMAT" {
		t.Fatal("invalid guest email accepted")
	}
	g, err := c.SignInAnonymous(t.Context())
	if err != nil || g.User.Name != "Anonymous" || g.User.Email != "custom@guest.test" {
		t.Fatalf("guest email or default name failed: %v", err)
	}
	_, err = c.SignUpEmail(t.Context(), client.SignUpRequest{Name: "Registered", Email: "registered@example.test", Password: "local fixture password"})
	if err != nil || !received {
		t.Fatalf("guest sign-up: %v", err)
	}
	if _, _, err := s.Session(t.Context(), g.Token); !errors.Is(err, authn.ErrNotFound) {
		t.Fatalf("guest session survived linking: %v", err)
	}
	// An empty generated address falls back to the configured domain.
	fresh, err := client.New(origin, &http.Client{Transport: transport(serve)})
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := fresh.SignInAnonymous(t.Context())
	if err != nil || !strings.HasPrefix(fallback.User.Email, "temp-") || !strings.HasSuffix(fallback.User.Email, "@ignored.example") {
		t.Fatalf("an empty generated address did not fall back to the domain: %v %v", err, fallback)
	}
}

type failingGuestStore struct{ *memory.Store }

var errGuestStoreDown = errors.New("guest store unavailable")

func (failingGuestStore) DeleteAnonymous(context.Context, string, string, time.Time) error {
	return errGuestStoreDown
}

// Each guest error Go returns answers with its status, code and message, and
// a store that cannot delete the guest answers 500 FAILED_TO_DELETE_ANONYMOUS_USER,
// keeps the guest signed in and hands the cause to OnAPIError.
func TestGuestErrorCodes(t *testing.T) {
	const origin = "https://guest-errors.example"
	var reported error
	browser := func(store authn.Store, o anonymous.Options, hooks authn.DatabaseHooks) *client.Client {
		t.Helper()
		p, err := anonymous.New(o)
		if err != nil {
			t.Fatal(err)
		}
		a, err := authn.New(authn.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("e", 32), EmailAndPassword: true, DatabaseHooks: hooks,
			Logger: slog.New(slog.DiscardHandler), OnAPIError: func(_ authn.ErrorContext, err error) error { reported = err; return nil }, Plugins: []authn.Plugin{p}})
		if err != nil {
			t.Fatal(err)
		}
		c, err := client.New(origin, &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			return w.Result(), nil
		})})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	want := func(err error, status int, code, message string) {
		t.Helper()
		var api *authn.APIError
		if !errors.As(err, &api) || api.Status != status || api.Code != code || api.Message != message {
			t.Fatalf("got %v, want %d %s %q", err, status, code, message)
		}
	}
	c := browser(memory.New(), anonymous.Options{GenerateRandomEmail: func(context.Context) (string, error) { return "not an address", nil }}, authn.DatabaseHooks{})
	_, err := c.SignInAnonymous(t.Context())
	want(err, 400, "INVALID_EMAIL_FORMAT", "Email was not generated in a valid format")
	c = browser(memory.New(), anonymous.Options{}, authn.DatabaseHooks{User: authn.ModelHooks[authn.UserRecord]{Create: authn.OperationHooks[authn.UserRecord]{
		Before: func(context.Context, *authn.UserRecord, *authn.HookContext) error { return authn.ErrSkipWrite }}}})
	_, err = c.SignInAnonymous(t.Context())
	want(err, 500, "FAILED_TO_CREATE_USER", "Failed to create user")
	c = browser(memory.New(), anonymous.Options{}, authn.DatabaseHooks{Session: authn.ModelHooks[authn.SessionRecord]{Create: authn.OperationHooks[authn.SessionRecord]{
		Before: func(context.Context, *authn.SessionRecord, *authn.HookContext) error { return authn.ErrSkipWrite }}}})
	_, err = c.SignInAnonymous(t.Context())
	want(err, 400, "COULD_NOT_CREATE_SESSION", "Could not create session")
	c = browser(memory.New(), anonymous.Options{}, authn.DatabaseHooks{})
	if _, err := c.SignInAnonymous(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, err = c.SignInAnonymous(t.Context())
	want(err, 400, "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY", "Anonymous users cannot sign in again anonymously")
	c = browser(memory.New(), anonymous.Options{}, authn.DatabaseHooks{})
	if _, err := c.SignUpEmail(t.Context(), client.SignUpRequest{Name: "Member", Email: "member@example.test", Password: "local fixture password"}); err != nil {
		t.Fatal(err)
	}
	want(c.DeleteAnonymousUser(t.Context()), 403, "USER_IS_NOT_ANONYMOUS", "User is not anonymous")
	c = browser(memory.New(), anonymous.Options{DisableDeleteAnonymousUser: true}, authn.DatabaseHooks{})
	if _, err := c.SignInAnonymous(t.Context()); err != nil {
		t.Fatal(err)
	}
	want(c.DeleteAnonymousUser(t.Context()), 400, "DELETE_ANONYMOUS_USER_DISABLED", "Deleting anonymous users is disabled")
	c = browser(failingGuestStore{memory.New()}, anonymous.Options{}, authn.DatabaseHooks{})
	g, err := c.SignInAnonymous(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	reported = nil
	want(c.DeleteAnonymousUser(t.Context()), 500, "FAILED_TO_DELETE_ANONYMOUS_USER", "Failed to delete anonymous user")
	if !errors.Is(reported, errGuestStoreDown) {
		t.Fatal("the store's failure did not reach OnAPIError:", reported)
	}
	if s, err := c.GetSession(t.Context()); err != nil || s == nil || s.User.ID != g.User.ID {
		t.Fatal("a failed guest deletion signed the guest out", err)
	}
}
