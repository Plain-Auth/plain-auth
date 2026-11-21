package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	auth "github.com/FineStack/frost-auth"
	"github.com/FineStack/frost-auth/adapters/sqlite"
	"github.com/FineStack/frost-auth/client"
	"github.com/FineStack/frost-auth/plugins/magiclink"
)

func TestNativeMagicLinkClient(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var message magiclink.Message
	plugin, err := magiclink.New(magiclink.Options{Send: func(_ context.Context, m magiclink.Message) error { message = m; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://sdk.example.test"
	a, err := auth.New(auth.Options{Store: store, BaseURL: origin, Secret: "synthetic-sdk-login-secrets-0000000001", Plugins: []auth.Plugin{plugin}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(origin+"/api/auth", &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w.Result(), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if err = c.SignInMagicLink(ctx, client.MagicLinkRequest{Email: "sdk@example.test", Name: "SDK"}); err != nil {
		t.Fatal(err)
	}
	verified, err := c.VerifyMagicLink(ctx, message.Token)
	if err != nil || verified.Token == "" || verified.User.Email != message.Email || !verified.User.EmailVerified {
		t.Fatalf("mailbox sign-in: %v", err)
	}
	session, err := c.GetSession(ctx)
	if err != nil || session == nil || session.Session.Token != verified.Token {
		t.Fatal("cookie jar lost verified session")
	}
	if _, err = c.VerifyMagicLink(ctx, message.Token); err == nil {
		t.Fatal("duplicate verification succeeded")
	}
}
