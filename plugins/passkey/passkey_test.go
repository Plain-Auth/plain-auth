package passkey_test

import (
	"maps"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/plugins/passkey"
	"github.com/go-webauthn/webauthn/protocol"
)

func TestRelyingPartyConfiguration(t *testing.T) {
	for _, origin := range []string{"https://*.example.test", "https://elsewhere.test", "http://login.example.test", "https://login.example.test/path", "https://user@login.example.test"} {
		if _, err := passkey.New(passkey.Options{RPID: "example.test", RPName: "Local", Origins: []string{origin}}); err == nil {
			t.Fatal("unexpectedly trusted origin", origin)
		}
	}
	if _, err := passkey.New(passkey.Options{RPID: "example.test", RPName: "Local"}); err == nil {
		t.Fatal("a configuration without browser origins was accepted")
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

// New refuses an unknown authenticator attachment or resident-key
// requirement and accepts the documented values.
func TestAuthenticatorSelectionConfiguration(t *testing.T) {
	base := passkey.Options{RPID: "localhost", RPName: "Local", Origins: []string{"http://localhost:9999"}}
	for _, sel := range []passkey.AuthenticatorSelection{{Attachment: "roaming"}, {ResidentKey: "always"}} {
		o := base
		o.AuthenticatorSelection = sel
		if _, err := passkey.New(o); err == nil {
			t.Fatalf("accepted authenticator selection %+v", sel)
		}
	}
	for _, sel := range []passkey.AuthenticatorSelection{{}, {Attachment: protocol.Platform, ResidentKey: protocol.ResidentKeyRequirementRequired}, {Attachment: protocol.CrossPlatform, ResidentKey: protocol.ResidentKeyRequirementDiscouraged}, {ResidentKey: protocol.ResidentKeyRequirementPreferred}} {
		o := base
		o.AuthenticatorSelection = sel
		if _, err := passkey.New(o); err != nil {
			t.Fatalf("refused authenticator selection %+v: %v", sel, err)
		}
	}
}

// AuthenticatorName resolves the built-in names, ignoring case and spaces,
// and AuthenticatorNames hands out a copy of exactly that list.
func TestAuthenticatorName(t *testing.T) {
	for in, want := range map[string]string{
		"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4":     "Google Password Manager",
		"fbfc3007-154e-4ecc-8c0b-6e020557d7bd":     "Apple Passwords",
		"bada5566-a7aa-401f-bd96-45619a55120d":     "1Password",
		"d548826e-79b4-db40-a3d8-11116f7e8349":     "Bitwarden",
		"53414d53-554e-4700-0000-000000000000":     "Samsung Pass",
		"08987058-cadc-4b81-b6e1-30de50dcbe96":     "Windows Hello",
		"9ddd1817-af5a-4672-a2b9-3e3dd95000a9":     "Windows Hello",
		"6028b017-b1d4-4c02-b4b3-afcdafc96bb2":     "Windows Hello",
		"  DD4EC289-E01D-41C9-BB89-70FA845D4BF2  ": "iCloud Keychain (Managed)",
		"00000000-0000-0000-0000-000000000000":     "",
		"11111111-1111-1111-1111-111111111111":     "",
		"":                                         "",
		"   ":                                      "",
	} {
		if got := passkey.AuthenticatorName(in); got != want {
			t.Fatalf("AuthenticatorName(%q) = %q, want %q", in, got, want)
		}
	}
	want := map[string]string{
		"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
		"fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "Apple Passwords",
		"dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "iCloud Keychain (Managed)",
		"08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
		"9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
		"6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
		"bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
		"d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
		"531126d6-e717-415c-9320-3d9aa6981239": "Dashlane",
		"b78a0a55-6ef8-d246-a042-ba0f6d55050c": "LastPass",
		"b84e4048-15dc-4dd0-8640-f4f60813c8af": "NordPass",
		"50726f74-6f6e-5061-7373-50726f746f6e": "Proton Pass",
		"0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6": "Keeper",
		"53414d53-554e-4700-0000-000000000000": "Samsung Pass",
	}
	if !maps.Equal(passkey.AuthenticatorNames(), want) {
		t.Fatal("the built-in authenticator names differ from the expected list")
	}
	names := passkey.AuthenticatorNames()
	names["00000000-0000-0000-0000-000000000000"] = "Spoofed Provider"
	names["11111111-1111-1111-1111-111111111111"] = "My Provider"
	if passkey.AuthenticatorName("00000000-0000-0000-0000-000000000000") != "" || passkey.AuthenticatorName("11111111-1111-1111-1111-111111111111") != "" || !maps.Equal(passkey.AuthenticatorNames(), want) {
		t.Fatal("extending a copy changed the built-in names")
	}
}
