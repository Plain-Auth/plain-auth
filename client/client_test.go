package client_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authn "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/sqlite"
	"github.com/Plain-Auth/plain-auth/client"
)

type transport func(*http.Request) (*http.Response, error)

func (fn transport) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func TestNativeClientLifecycle(t *testing.T) {
	db, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	const origin = "https://client.example.test"
	limit := false
	auth, err := authn.New(authn.Options{
		BaseURL: origin, BasePath: "/identity", Store: db,
		Secret: "client-fixture-secret-0123456789-abcdefgh", EmailAndPassword: true, RateLimit: &limit,
	})
	if err != nil {
		t.Fatal(err)
	}
	wire := &http.Client{Transport: transport(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "client.example.test" || !strings.HasPrefix(req.URL.Path, "/identity/") {
			t.Fatalf("wrong endpoint %v", req.URL)
		}
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, req)
		return w.Result(), nil
	})}
	newClient := func() *client.Client {
		instance, err := client.New(origin+"/identity/", wire)
		if err != nil {
			t.Fatal(err)
		}
		return instance
	}
	first, second := newClient(), newClient()
	ctx := t.Context()
	const email = "client@example.test"
	const password = "local-signup-password"
	user, err := first.SignUpEmail(ctx, client.SignUpRequest{Name: "Fixture", Email: email, Password: password})
	if err != nil || user.User.Email != email || user.Token == nil {
		t.Fatalf("registration: %v, %v", user, err)
	}
	session, err := first.GetSession(ctx)
	if err != nil || session == nil || session.Session.Token != *user.Token {
		t.Fatalf("session: %v, %v", session, err)
	}
	if session, err = second.GetSession(ctx); err != nil || session != nil {
		t.Fatalf("cookies were not isolated: %v, %v", session, err)
	}
	_, err = second.SignInEmail(ctx, client.SignInRequest{Email: email, Password: "wrong-password"})
	var apiErr *authn.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 401 || apiErr.Code != "INVALID_EMAIL_OR_PASSWORD" {
		t.Fatalf("unexpected error: %v", err)
	}
	signed, err := second.SignInEmail(ctx, client.SignInRequest{Email: email, Password: password, CallbackURL: "/profile"})
	if err != nil || !signed.Redirect || signed.URL != "/profile" {
		t.Fatalf("login: %v, %v", signed, err)
	}
	sessions, err := second.ListSessions(ctx)
	if err != nil || len(sessions) != 2 {
		t.Fatalf("session list: %v, %v", sessions, err)
	}
	if err = second.RevokeOtherSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if session, err = first.GetSession(ctx); session != nil || err != nil {
		t.Fatalf("revoked session: %v, %v", session, err)
	}
	if err = second.RevokeSession(ctx, *signed.Token); err != nil {
		t.Fatal(err)
	}
	if session, err = second.GetSession(ctx); session != nil || err != nil {
		t.Fatalf("revoked current session: %v, %v", session, err)
	}
	if _, err = first.SignInEmail(ctx, client.SignInRequest{Email: email, Password: password}); err != nil {
		t.Fatal(err)
	}
	if err = first.RevokeSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = first.SignInEmail(ctx, client.SignInRequest{Email: email, Password: password}); err != nil {
		t.Fatal(err)
	}
	if err = first.SignOut(ctx); err != nil {
		t.Fatal(err)
	}
	if session, err = first.GetSession(ctx); session != nil || err != nil {
		t.Fatalf("signed-out session: %v, %v", session, err)
	}
	if wire.Jar != nil {
		t.Fatal("constructor modified supplied HTTP client")
	}
}

func TestTransportErrorsAndCancellation(t *testing.T) {
	httpClient := &http.Client{Transport: transport(func(req *http.Request) (*http.Response, error) {
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
		if req.URL.Path != "/api/auth/get-session" {
			t.Fatalf("unexpected request %v", req.URL)
		}
		return &http.Response{StatusCode: 502, Body: io.NopCloser(strings.NewReader("bad gateway")), Header: http.Header{}}, nil
	})}
	c, err := client.New("https://client.example.test", httpClient)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetSession(t.Context())
	var apiErr *authn.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 502 || apiErr.Message == "" {
		t.Fatalf("missing status: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.GetSession(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("context cancellation: %v", err)
	}
}
