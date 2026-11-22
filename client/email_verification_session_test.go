package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/client"
)

func TestClientSignInAfterEmailVerification(t *testing.T) {
	const origin = "https://accounts.example.test"
	store := memory.New()
	var link string
	failCache := false
	off := false
	opts := auth.Options{Store: store, BaseURL: origin, BasePath: "/identity", Secret: strings.Repeat("x", 48),
		EmailAndPassword: true, RequireEmailVerification: true, AutoSignInAfterVerification: true, RateLimit: &off,
		SendVerificationEmail: func(_ context.Context, m auth.MailLink) error { link = m.Token; return nil },
		SessionCookieCache: &auth.SessionCookieCacheOptions{VersionFor: func(context.Context, auth.Session, auth.User) (string, error) {
			if failCache {
				return "", errors.New("private revision failure")
			}
			return "1", nil
		}},
	}
	server, err := auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	newClient := func() *client.Client {
		c, err := client.New(origin+"/identity", &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
			w := httptest.NewRecorder()
			server.ServeHTTP(w, r)
			return w.Result(), nil
		})})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ctx := t.Context()
	owner, browser := newClient(), newClient()
	acct, err := owner.SignUpEmail(ctx, client.SignUpRequest{Email: "owner@example.test", Name: "Owner", Password: "local-verify-password"})
	if err != nil || acct.Token != nil {
		t.Fatal("verification-gated signup", err)
	}
	if err := browser.VerifyEmail(ctx, link); err != nil {
		t.Fatal(err)
	}
	session, err := browser.GetSession(ctx)
	if err != nil || session == nil || session.User.ID != acct.User.ID || !session.User.EmailVerified {
		t.Fatal("verification did not authenticate the browser", err)
	}
	if err := owner.VerifyEmail(ctx, link); err != nil {
		t.Fatal(err)
	}
	if s, err := owner.GetSession(ctx); err != nil || s != nil {
		t.Fatal("a second verification browser acquired a session", err)
	}

	// A cookie-publication failure cannot expose or strand a newly inserted token.
	pending, err := owner.SignUpEmail(ctx, client.SignUpRequest{Email: "retry@example.test", Name: "Pending", Password: "local-verify-password"})
	if err != nil {
		t.Fatal(err)
	}
	failCache = true
	if err := owner.VerifyEmail(ctx, link); err == nil {
		t.Fatal("version callback rejection reported success")
	}
	records, err := store.ListSessions(ctx, pending.User.ID)
	if err != nil || len(records) != 0 {
		t.Fatal("failed cookie publication stranded an authenticated session", err)
	}
	u, err := store.FindAccountUser(ctx, "retry@example.test")
	if err != nil || !u.EmailVerified {
		t.Fatal("failed cookie publication undid mailbox verification", err)
	}
	if err := owner.VerifyEmail(ctx, link); err != nil {
		t.Fatal(err)
	}
	if s, err := owner.GetSession(ctx); err != nil || s != nil {
		t.Fatal("a failed first browser session was replayable", err)
	}
	// If replacement cookies cannot be published for an already authenticated
	// owner, the old direct session still belongs to that browser.
	opts.RequireEmailVerification = false
	send := true
	opts.SendVerificationOnSignUp = &send
	server, err = auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	existing, err := server.SignUpEmail(ctx, auth.SignUpInput{Email: "existing@example.test", Name: "Original", Password: "local-verify-password"}, auth.RequestMeta{})
	if err != nil || existing.Token == "" {
		t.Fatal("native initial session", err)
	}
	req := httptest.NewRequest("GET", origin+"/identity/verify-email?token="+link, nil)
	req.AddCookie(server.SessionCookie(existing.Token, true))
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	if w.Code != 500 || len(w.Result().Cookies()) != 0 {
		t.Fatal("failed reissue published a browser credential", w.Code)
	}
	live, err := server.GetSession(ctx, req.Header)
	if err != nil || live == nil || live.Session.Token != existing.Token || !live.User.EmailVerified {
		t.Fatal("failed reissue revoked the owner's existing session", err)
	}
}
