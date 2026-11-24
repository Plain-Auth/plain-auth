package siwe

import (
	"strings"
	"testing"
	"time"
)

func TestSignedMessageContract(t *testing.T) {
	const address = "0x52908400098527886E0F7030069857D2E4169EE7"
	checked, ok := checksumAddress(strings.ToLower(address))
	if !ok || checked != address {
		t.Fatal("EIP-55 checksum mismatch", checked)
	}
	if _, ok := checksumAddress(strings.Replace(address, "E0F", "e0F", 1)); ok {
		t.Fatal("invalid mixed-case checksum accepted")
	}
	const text = "https://[::1]:8443 wants you to sign in with your Ethereum account:\n" + address +
		"\n\nSign in to the app.\n\nURI: https://[::1]:8443/login\nVersion: 1\nChain ID: 137\nNonce: A0b1C2d3\nIssued At: 2026-01-05T12:00:00Z" +
		"\nExpiration Time: 2026-01-05T12:05:00Z\nNot Before: 2026-01-05T11:55:00Z\nRequest ID: request-1\nResources:\n- urn:example:terms"
	now := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	parse := func(s string) (message, error) {
		return parseMessage(strings.Split(s, "\n"), "https", "[::1]:8443", now)
	}
	m, err := parse(text)
	if err != nil || m.address != address || m.chain != 137 || m.nonce != "A0b1C2d3" {
		t.Fatal("valid wallet signing fields", m, err)
	}
	for _, altered := range []string{
		strings.Replace(text, "https://[::1]:8443 wants", "https://user@[::1]:8443 wants", 1),
		strings.Replace(text, "[::1]:8443/login", "[::1]:443/login", 1),
		strings.Replace(text, "Chain ID: 137", "Chain ID: 137\nChain ID: 1", 1),
		strings.Replace(text, "Nonce: A0b1C2d3", "Nonce: A0b1C2d3\nNonce: Another1", 1),
		strings.Replace(text, "2026-01-05T12:00:00Z", "2026-01-05T12:10:00Z", 1),
		text + "\nURI: https://unrelated.test",
	} {
		if _, err := parse(altered); err == nil {
			t.Fatal("invalid signed fields accepted", altered)
		}
	}
	if n := nonceFrom([]string{"Nonce: A0b1C2d3", "Nonce: Another1"}); n != "" {
		t.Fatal("ambiguous challenge extracted")
	}
	for _, sig := range []string{"", "hello", "0x" + strings.Repeat("00", 65), "0x" + strings.Repeat("01", 64) + "04"} {
		if validSignature(text, sig, address) {
			t.Fatal("invalid signature accepted")
		}
	}
}

func TestWalletOptions(t *testing.T) {
	for _, opts := range []Options{{}, {Domain: "example.test/path"}, {Domain: "https://user@example.test"}, {Domain: "*.example.test"}, {Domain: "example.test", Chains: []int64{0}}, {Domain: "example.test", EmailDomainName: "a@b.test"}} {
		if _, err := New(opts); err == nil {
			t.Fatal("invalid wallet configuration accepted", opts)
		}
	}
	if _, err := New(Options{Domain: "example.test:8443", EmailDomainName: "wallet.invalid", Chains: []int64{1, 137}}); err != nil {
		t.Fatal(err)
	}
}

// A message whose domain folds into the configured ASCII domain only under
// Unicode case mapping names a different, Punycode domain to a wallet, so it
// never signs in.
func TestSignedMessageRefusesNonASCIIDomains(t *testing.T) {
	const address = "0x52908400098527886E0F7030069857D2E4169EE7"
	now := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	_, domain, ok := canonicalOrigin("wallet.bitbucket.example")
	if !ok {
		t.Fatal("the ASCII domain was refused")
	}
	for _, header := range []string{"wallet.b\u0130tbucket.example", "https://wallet.b%C4%B0tbucket.example"} {
		text := header + " wants you to sign in with your Ethereum account:\n" + address +
			"\n\nURI: https://wallet.bitbucket.example/login\nVersion: 1\nChain ID: 1\nNonce: A0b1C2d3\nIssued At: 2026-01-05T12:00:00Z"
		if _, err := parseMessage(strings.Split(text, "\n"), "https", domain, now); err == nil {
			t.Errorf("accepted the message domain %q", header)
		}
	}
	if _, _, ok := canonicalOrigin("wallet.b\u0130tbucket.example"); ok {
		t.Fatal("accepted a non-ASCII configured domain")
	}
}
