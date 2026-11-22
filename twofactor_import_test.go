package plainauth

import (
	"bytes"
	"encoding/base32"
	"strings"
	"testing"
)

func TestImportTOTPBase32(t *testing.T) {
	raw := []byte{0xff, 0x00, 0x11, 0x80, 0xbb, 0xfe}
	seed := base32.StdEncoding.EncodeToString(raw)
	for _, value := range []string{seed, strings.ToLower(seed), strings.TrimRight(seed, "=")} {
		got, err := importedTOTPSecret(value)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatal("valid Base32 seed did not preserve the authenticator key bytes")
		}
	}
	for _, value := range []string{"", "MY=SA", "MY=", "MZ", "MY\n", "M Y", "M0", "ſA", "otpauth://totp/Example", "base32:MY"} {
		if _, err := importedTOTPSecret(value); err == nil || strings.Contains(err.Error(), value) && value != "" {
			t.Fatalf("invalid seed at length %d was accepted or included in the error", len(value))
		}
	}
}
