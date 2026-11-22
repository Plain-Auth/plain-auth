package client_test

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/plugins/onetimetoken"
)

func TestOneTimeTokenGeneratorRequest(t *testing.T) {
	type invocation struct{ path, userID, sessionID string }
	var calls []invocation
	issue := func(_ context.Context, session auth.SessionResult, r *http.Request) (string, error) {
		path := ""
		if r != nil {
			if r.Body != http.NoBody || r.GetBody != nil || r.Header.Get("X-App") != "native test" {
				t.Fatal("generator received unexpected request metadata")
			}
			path = r.URL.Path
			r.Header.Set("X-App", "changed")
		}
		calls = append(calls, invocation{path, session.User.ID, session.Session.ID})
		return rand.Text(), nil
	}
	if _, err := onetimetoken.New(onetimetoken.Options{GenerateTokenWithRequest: issue, GenerateToken: func(context.Context, auth.SessionResult) (string, error) { return "unused", nil }}); err == nil {
		t.Fatal("ambiguous token generators accepted")
	}
	plugin, err := onetimetoken.New(onetimetoken.Options{SetHeaderOnNewSession: true, HashTokens: true, GenerateTokenWithRequest: issue})
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://transfer.example.test"
	opts := auth.Options{BaseURL: origin, Store: memory.New(), Secret: strings.Repeat("t", 40), EmailAndPassword: true, Plugins: []auth.Plugin{plugin}}
	issuer, err := auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	var headers http.Header
	var fromSignup string
	newClient := func(server *auth.Auth) *client.Client {
		t.Helper()
		c, err := client.New(origin, &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
			r.Header.Set("X-App", "native test")
			w := httptest.NewRecorder()
			server.ServeHTTP(w, r)
			if r.Header.Get("X-App") != "native test" {
				t.Fatal("generator mutated the caller's original request")
			}
			if strings.HasSuffix(r.URL.Path, "/sign-up/email") {
				fromSignup = w.Header().Get("Set-Ott")
			}
			if strings.HasSuffix(r.URL.Path, "/one-time-token/generate") {
				headers = r.Header.Clone()
			}
			return w.Result(), nil
		})})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ctx := t.Context()
	sender := newClient(issuer)
	owner, err := sender.SignUpEmail(ctx, client.SignUpRequest{Name: "Sender", Email: "sender@example.test", Password: "local-test-password"})
	if err != nil || fromSignup == "" {
		t.Fatal("signed-up session did not issue an optional header", err)
	}
	fromHTTP, err := sender.GenerateOneTimeToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fromNative, err := issuer.GenerateOneTimeToken(ctx, headers)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 {
		t.Fatal("incorrect number of generation callbacks", len(calls))
	}
	for i, path := range []string{"/api/auth/sign-up/email", "/api/auth/one-time-token/generate", ""} {
		if c := calls[i]; c.path != path || c.userID != owner.User.ID || c.sessionID == "" || c.sessionID != calls[0].sessionID {
			t.Fatal("generator received the wrong source session or route", i)
		}
	}
	receiver := newClient(peer)
	for _, token := range []string{fromSignup, fromHTTP, fromNative} {
		got, err := receiver.VerifyOneTimeToken(ctx, token)
		if err != nil || got.Session.ID != calls[0].sessionID || got.User.ID != owner.User.ID {
			t.Fatal("memory client did not receive original session", err)
		}
		if _, err := receiver.VerifyOneTimeToken(ctx, token); err == nil {
			t.Fatal("memory client reused transfer")
		}
	}
}
