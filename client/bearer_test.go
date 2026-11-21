package client_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/memory"
	"github.com/Stonewrit/stonewrit-auth/client"
	"github.com/Stonewrit/stonewrit-auth/plugins/bearer"
)

func TestSignedBearerClient(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	instance, err := stonewrit.New(stonewrit.Options{BaseURL: origin, Store: memory.New(), Secret: strings.Repeat("x", 32),
		EmailAndPassword: true, Plugins: []stonewrit.Plugin{bearer.New(bearer.Options{RequireSignature: true})}})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" && r.Header.Get("Cookie") != "" {
			t.Error("bearer request attached a cookie")
		}
		instance.ServeHTTP(w, r)
	})
	server.StartTLS()
	t.Cleanup(server.Close)
	browser, err := client.New(origin, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	register := func(email string) (string, string) {
		t.Helper()
		var result client.EmailResult
		h, err := browser.DoWithHeaders(t.Context(), "POST", "/sign-up/email", client.SignUpRequest{
			Email: email, Password: "fixture-password", Name: "User",
		}, &result)
		if err != nil || h.Get("Set-Auth-Token") == "" || result.User.ID == "" {
			t.Fatal("registration did not issue a signed credential", err)
		}
		return result.User.ID, h.Get("Set-Auth-Token")
	}
	alice, token := register("alice@example.test")
	bob, _ := register("bob@example.test")
	device, err := browser.WithBearerToken(token)
	if err != nil {
		t.Fatal(err)
	}
	get := func(c *client.Client) string {
		t.Helper()
		s, err := c.GetSession(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if s == nil {
			return ""
		}
		return s.User.ID
	}
	if get(device) != alice || get(browser) != bob {
		t.Fatal("bearer and cookie identities were mixed")
	}
	if err := device.SignOut(t.Context()); err != nil {
		t.Fatal(err)
	}
	if get(device) != "" || get(browser) != bob {
		t.Fatal("revoked bearer reused a browser identity")
	}
	for _, invalid := range []string{"", "a b", "x\r\ny", "a,b"} {
		if _, err := browser.WithBearerToken(invalid); err == nil {
			t.Fatal("accepted malformed bearer")
		}
	}
}
