package client_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	authn "github.com/FineStack/finestack-auth"
	"github.com/FineStack/finestack-auth/adapters/sqlstore"
	"github.com/FineStack/finestack-auth/client"
	"github.com/FineStack/finestack-auth/plugins/bearer"
	"github.com/FineStack/finestack-auth/plugins/deviceauthorization"
	"github.com/FineStack/finestack-auth/schema"
)

func TestNativeDeviceClient(t *testing.T) {
	ctx := t.Context()
	ddl, err := schema.Generate("sqlite", []string{"device-authorization"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := sqlstore.OpenWithSchema(ctx, "sqlite", filepath.Join(t.TempDir(), "device.db"), ddl)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, err := deviceauthorization.New(deviceauthorization.Options{})
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://device.example"
	off := false
	a, err := authn.New(authn.Options{Store: s, EmailAndPassword: true, BaseURL: origin, Secret: strings.Repeat("x", 32), RateLimit: &off, Plugins: []authn.Plugin{p, bearer.New(bearer.Options{})}})
	if err != nil {
		t.Fatal(err)
	}
	newClient := func() *client.Client {
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
	browser, machine := newClient(), newClient()
	owner, err := browser.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@test.example", Password: "safe test password"})
	if err != nil {
		t.Fatal(err)
	}
	for _, approve := range []bool{true, false} {
		grant, err := machine.RequestDeviceCode(ctx, client.DeviceCodeRequest{ClientID: "cli", Scope: "profile"})
		if err != nil {
			t.Fatal(err)
		}
		review, err := browser.VerifyDeviceCode(ctx, grant.UserCode)
		if err != nil || review.Status != "pending" || review.ClientID != "cli" {
			t.Fatalf("device review: %v", err)
		}
		if !approve {
			if err := browser.DenyDeviceCode(ctx, grant.UserCode); err != nil {
				t.Fatal(err)
			}
			_, err = machine.PollDeviceToken(ctx, "cli", grant.DeviceCode)
			var protocol *authn.APIError
			if !errors.As(err, &protocol) || protocol.Status != 400 || protocol.Code != "access_denied" || protocol.Message != "Access denied" {
				t.Fatalf("lost OAuth error: %v", err)
			}
			continue
		}
		if err := browser.ApproveDeviceCode(ctx, grant.UserCode); err != nil {
			t.Fatal(err)
		}
		token, err := machine.PollDeviceToken(ctx, "cli", grant.DeviceCode)
		if err != nil || token.Scope != "profile" || token.TokenType != "Bearer" {
			t.Fatalf("device token: %v", err)
		}
		h := make(http.Header)
		h.Set("Authorization", "Bearer "+token.AccessToken)
		session, err := a.GetSession(ctx, h)
		if err != nil || session == nil || session.User.ID != owner.User.ID {
			t.Fatalf("bearer identity: %v", err)
		}
		if leaked, err := machine.GetSession(ctx); err != nil || leaked != nil {
			t.Fatal("device token response attached browser cookies")
		}
	}
}
