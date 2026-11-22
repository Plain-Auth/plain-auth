package passkey_test

import (
	"strings"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/sqlstore"
	"github.com/Plain-Auth/plain-auth/plugins/passkey"
)

func TestRelyingPartyConfiguration(t *testing.T) {
	for _, origin := range []string{"https://*.example.test", "https://elsewhere.test", "http://login.example.test", "https://login.example.test/path", "https://user@login.example.test"} {
		if _, err := passkey.New(passkey.Options{RPID: "example.test", RPName: "Local", Origins: []string{origin}}); err == nil {
			t.Fatal("unexpectedly trusted origin", origin)
		}
	}
	p, err := passkey.New(passkey.Options{RPID: "localhost", RPName: "Local", Origins: []string{"http://localhost:9999"}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlstore.Open(t.Context(), "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = auth.New(auth.Options{Store: store, BaseURL: "http://localhost:9999", Secret: strings.Repeat("s", 32), Plugins: []auth.Plugin{p}}); err == nil {
		t.Fatal("missing passkey profile was accepted")
	}
}
