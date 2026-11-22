package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authn "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/plugins/anonymous"
)

func TestGuestClientOnMemoryStore(t *testing.T) {
	emails := []string{"invalid", "custom@guest.test"}
	received := false
	opts := anonymous.Options{GenerateRandomEmail: func(context.Context) (string, error) { v := emails[0]; emails = emails[1:]; return v, nil }, OnLinkAccount: func(_ context.Context, e anonymous.Link) error {
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
	c, err := client.New(origin, &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w.Result(), nil
	})})
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
}
