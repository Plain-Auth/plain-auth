package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlstore"
	"github.com/Stonewrit/stonewrit-auth/client"
	"github.com/Stonewrit/stonewrit-auth/plugins/twofactor"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func TestNativeDeliveredFactorClient(t *testing.T) {
	ctx := t.Context()
	ddl, err := schema.Generate("sqlite", []string{"two-factor"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := sqlstore.OpenWithSchema(ctx, "sqlite", filepath.Join(t.TempDir(), "client.db"), ddl)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var delivery twofactor.OTPMessage
	plugin := twofactor.New(twofactor.Options{OTP: twofactor.OTPOptions{Store: "encrypted", Send: func(_ context.Context, m twofactor.OTPMessage) error { delivery = m; return nil }}})
	const origin = "https://factor-sdk.example.test"
	off := false
	a, err := auth.New(auth.Options{BaseURL: origin, Secret: "test-local-shared-credential-0123456789", Store: s, Plugins: []auth.Plugin{plugin}, EmailAndPassword: true, RateLimit: &off})
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
	const email = "inbox@example.test"
	const password = "local-SDK-factor-password"
	signup, err := c.SignUpEmail(ctx, client.SignUpRequest{Email: email, Password: password, Name: "SDK"})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.EnableDeliveredFactor(ctx, password); err != nil {
		t.Fatal(err)
	}
	if err = c.SignOut(ctx); err != nil {
		t.Fatal(err)
	}
	in := client.SignInRequest{Email: email, Password: password}
	pending, err := c.SignInEmail(ctx, in)
	if err != nil || !pending.TwoFactorRedirect || len(pending.TwoFactorMethods) != 1 || pending.TwoFactorMethods[0] != "otp" {
		t.Fatal("native challenge methods", err)
	}
	if err = c.SendFactorOTP(ctx); err != nil || delivery.User.ID != signup.User.ID {
		t.Fatal("native delivery", err)
	}
	proof, err := c.VerifyFactorOTP(ctx, delivery.Code, true)
	if err != nil || proof.Token == nil {
		t.Fatal("native factor proof", err)
	}
	if err = c.SignOut(ctx); err != nil {
		t.Fatal(err)
	}
	trusted, err := c.SignInEmail(ctx, in)
	if err != nil || trusted.TwoFactorRedirect || trusted.Token == nil {
		t.Fatal("native cookie jar lost remembered-browser grant", err)
	}
}
