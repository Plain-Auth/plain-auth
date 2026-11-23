package client_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/magiclink"
)

func TestNativeMagicLinkClient(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var message magiclink.Message
	plugin, err := magiclink.New(magiclink.Options{Send: func(_ context.Context, m magiclink.Message) error {
		message = m
		if m.Request == nil || m.Request.Method != http.MethodPost || m.Request.Header.Get("X-Delivery-Locale") != "sv-SE" {
			t.Fatal("sender lost its request metadata")
		}
		body, readErr := io.ReadAll(m.Request.Body)
		if readErr != nil || len(body) != 0 || m.Request.GetBody != nil {
			t.Fatal("delivery callback retained a request body", readErr)
		}
		serialized, err := json.Marshal(m)
		if err != nil || strings.Contains(string(serialized), "sv-SE") || strings.Contains(string(serialized), "Request") {
			t.Fatal("HTTP metadata entered the serializable delivery payload", err)
		}
		m.Request.Header.Set("X-Delivery-Locale", "callback mutation")
		return nil
	}})
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
		r.Header.Set("X-Delivery-Locale", "sv-SE")
		a.ServeHTTP(w, r)
		if r.Header.Get("X-Delivery-Locale") != "sv-SE" {
			t.Fatal("sender changed the host request headers")
		}
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
