package client_test

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	auth "github.com/nabuhadba/go-better-auth"
	"github.com/nabuhadba/go-better-auth/adapters/sqlite"
	"github.com/nabuhadba/go-better-auth/client"
	"github.com/nabuhadba/go-better-auth/plugins/onetimetoken"
)

func TestNativeOneTimeTokenClient(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	expected := rand.Text()
	hashCalls := 0
	p, err := onetimetoken.New(onetimetoken.Options{
		ExpiresIn: time.Minute,
		GenerateToken: func(_ context.Context, s auth.SessionResult) (string, error) {
			if s.User.Email != "sender@example.test" {
				t.Fatal("wrong session passed to generator")
			}
			return expected, nil
		},
		HashToken: func(_ context.Context, raw string) (string, error) {
			if raw != expected {
				t.Fatal("unexpected private token")
			}
			hashCalls++
			return "stored-" + raw, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mount = "https://transfer.test/api/auth"
	limit := false
	a, err := auth.New(auth.Options{Store: store, BaseURL: mount, Secret: "test-key-for-one-time-client-0000000", EmailAndPassword: true, RateLimit: &limit, Plugins: []auth.Plugin{p}})
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w.Result(), nil
	})}
	sender, err := client.New(mount, transport)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := client.New(mount, transport)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	login, err := sender.SignUpEmail(ctx, client.SignUpRequest{Email: "sender@example.test", Name: "Sender", Password: "example-transfer-login"})
	if err != nil {
		t.Fatal(err)
	}
	token, err := sender.GenerateOneTimeToken(ctx)
	if err != nil || token != expected {
		t.Fatal("token generation failed", err)
	}
	s, err := receiver.VerifyOneTimeToken(ctx, token)
	if err != nil || s.Session.Token != *login.Token || hashCalls != 2 {
		t.Fatal("native session transfer failed", err)
	}
	resolved, err := receiver.GetSession(ctx)
	if err != nil || resolved == nil || resolved.User.ID != login.User.ID {
		t.Fatal("receiver did not retain the bound cookie")
	}
	if _, err := sender.VerifyOneTimeToken(ctx, token); err == nil {
		t.Fatal("second verification succeeded")
	}
}
