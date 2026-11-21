package betterauth

import (
	"strings"
	"testing"
	"time"
)

func TestFactorEncryptionAndRFC6238Vector(t *testing.T) {
	const oldKey = "fixture-encryption-key-for-authenticator-tests"
	const nextKey = "new-fixture-encryption-key-for-authenticator-tests"
	const rawSecret = "12345678901234567890"
	// Generated using the separately locked JavaScript crypto fixture.
	const ciphertext = "eab6bf51a56e338a34d96cf732d1dfbbd3ac6d0da134cd23d4a59d8910df017df0ccb7b01283d6560322de446aea7b784b38c2a06b56f85d15607a69"
	a := &Auth{legacySecret: oldKey, opts: Options{Secret: nextKey, Secrets: []VersionedSecret{{Version: 2, Value: nextKey}, {Version: 1, Value: oldKey}}}}
	for _, envelope := range []string{ciphertext, "$ba$1$" + ciphertext} {
		raw, err := a.openFactorData(envelope)
		if err != nil || string(raw) != rawSecret {
			t.Fatalf("fixture decryption: %v", err)
		}
		// RFC 6238, Appendix B, SHA-1 at 59 seconds, truncated to six digits.
		step, match, err := factorTOTPStep(raw, "287082", time.Unix(59, 0))
		if err != nil || !match || step != 1 {
			t.Fatal("RFC 6238 test vector failed")
		}
		for _, wrong := range []string{"", "12345", "12345x", "000000", "94287082"} {
			if _, valid, err := factorTOTPStep(raw, wrong, time.Unix(59, 0)); err != nil || valid {
				t.Fatal("accepted malformed or incorrect code")
			}
		}
	}
	fresh, err := a.sealFactorData([]byte(rawSecret))
	if err != nil || !strings.HasPrefix(fresh, "$ba$2$") {
		t.Fatalf("new material did not use active key: %v", err)
	}
	if raw, err := a.openFactorData(fresh); err != nil || string(raw) != rawSecret {
		t.Fatalf("unable to decrypt new material: %v", err)
	}
	a.opts.Secrets = a.opts.Secrets[:1]
	if _, err := a.openFactorData("$ba$1$" + ciphertext); err == nil {
		t.Fatal("removed key decrypted versioned material")
	}
}

func TestLegacyFactorEncryptionKeyUpgrade(t *testing.T) {
	cleanConfigEnv(t)
	t.Setenv("AUTH_URL", "https://auth.test")
	t.Setenv("AUTH_SECRET", strings.Repeat("a", 32))
	opts := Options{Store: &refreshFixture{}}
	legacy, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	data, err := legacy.sealFactorData([]byte("factor-secret"))
	if err != nil || strings.HasPrefix(data, "$ba$") {
		t.Fatal("legacy storage shape changed")
	}
	t.Setenv("AUTH_SECRETS", "2:"+strings.Repeat("b", 32))
	rotated, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := rotated.openFactorData(data); err != nil || string(raw) != "factor-secret" {
		t.Fatalf("legacy encryption key: %v", err)
	}
	newData, err := rotated.sealFactorData([]byte("new-factor"))
	if err != nil || !strings.HasPrefix(newData, "$ba$2$") {
		t.Fatal("new data was not versioned")
	}
	t.Setenv("AUTH_SECRET", "")
	retired, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retired.openFactorData(data); err == nil {
		t.Fatal("retired encryption key remained usable")
	}
	if raw, err := retired.openFactorData(newData); err != nil || string(raw) != "new-factor" {
		t.Fatal("versioned data lost during legacy retirement")
	}
}
