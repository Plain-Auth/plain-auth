package fineauth

import (
	"strings"
	"testing"
	"time"
)

func TestFactorEncryptionAndRFC6238Vector(t *testing.T) {
	const rawSecret = "12345678901234567890"
	step, match, err := factorTOTPStep([]byte(rawSecret), "287082", time.Unix(59, 0))
	if err != nil || !match || step != 1 {
		t.Fatal("RFC 6238 test vector failed")
	}
	for _, wrong := range []string{"", "12345", "12345x", "000000", "94287082"} {
		if _, valid, err := factorTOTPStep([]byte(rawSecret), wrong, time.Unix(59, 0)); err != nil || valid {
			t.Fatal("accepted malformed or incorrect code")
		}
	}
}

func TestEncryptedRecordsRequirePurposeAndExplicitKeyVersion(t *testing.T) {
	cleanConfigEnv(t)
	t.Setenv("AUTH_URL", "https://auth.test")
	oldKey, newKey := strings.Repeat("a", 32), strings.Repeat("b", 32)
	t.Setenv("AUTH_SECRET", oldKey)
	fresh := func() *Auth {
		t.Helper()
		a, err := New(Options{Store: &refreshFixture{}})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	seal := func(a *Auth) string {
		t.Helper()
		data, err := a.sealRecord("totp", []byte("secret payload"))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	a := fresh()
	data := seal(a)
	if !strings.HasPrefix(data, recordPrefix+"0.") || data == seal(a) {
		t.Fatal("single key must use version zero and a fresh nonce")
	}
	t.Setenv("AUTH_SECRETS", "2:"+newKey+",0:"+oldKey)
	a = fresh()
	if raw, err := a.openRecord("totp", data); err != nil || string(raw) != "secret payload" {
		t.Fatal("configured version zero failed to open record")
	}
	if _, err := a.openRecord("jwk", data); err == nil {
		t.Fatal("accepted different record purpose")
	}
	current := seal(a)
	if !strings.HasPrefix(current, recordPrefix+"2.") {
		t.Fatal("first key version must encrypt new records")
	}
	for _, invalid := range []string{"", "aabbcc", recordPrefix + "2.bad", strings.Replace(current, "v1", "v2", 1), strings.Replace(current, "2.", "0.", 1)} {
		if _, err := a.openRecord("totp", invalid); err == nil {
			t.Fatal("invalid encrypted record accepted")
		}
	}
	t.Setenv("AUTH_SECRETS", "2:"+newKey)
	a = fresh()
	if _, err := a.openRecord("totp", data); err == nil {
		t.Fatal("retired encryption version remained usable")
	}
	if raw, err := a.openRecord("totp", current); err != nil || string(raw) != "secret payload" {
		t.Fatal("active key failed to open record")
	}
}
