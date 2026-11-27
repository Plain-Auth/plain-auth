package plainauth

import (
	"strings"
	"testing"
)

// A sealed record opens only for its purpose, with any configured secret
// version, and not once its version is retired.
func TestRecordEncryption(t *testing.T) {
	old := &Auth{opts: Options{Secrets: []VersionedSecret{{Version: 1, Value: strings.Repeat("o", 32)}}}}
	sealed, err := old.EncryptRecord("oauth-client-secret/app", []byte("raw secret"))
	if err != nil || !strings.HasPrefix(sealed, "authn.v1.1.") || strings.Contains(sealed, "raw secret") {
		t.Fatal("the record was not sealed", sealed, err)
	}
	if plain, err := old.DecryptRecord("oauth-client-secret/app", sealed); err != nil || string(plain) != "raw secret" {
		t.Fatal("the record did not round trip", plain, err)
	}
	if _, err := old.DecryptRecord("oauth-client-secret/other", sealed); err == nil {
		t.Fatal("a record opened for another purpose")
	}
	rotated := &Auth{opts: Options{Secrets: []VersionedSecret{{Version: 2, Value: strings.Repeat("n", 32)}, {Version: 1, Value: strings.Repeat("o", 32)}}}}
	if plain, err := rotated.DecryptRecord("oauth-client-secret/app", sealed); err != nil || string(plain) != "raw secret" {
		t.Fatal("an older key version no longer opened its record", plain, err)
	}
	if again, err := rotated.EncryptRecord("oauth-client-secret/app", []byte("raw secret")); err != nil || !strings.HasPrefix(again, "authn.v1.2.") {
		t.Fatal("a new record did not use the active key", again, err)
	}
	retired := &Auth{opts: Options{Secrets: []VersionedSecret{{Version: 2, Value: strings.Repeat("n", 32)}}}}
	if _, err := retired.DecryptRecord("oauth-client-secret/app", sealed); err == nil {
		t.Fatal("a record opened after its key was retired")
	}
}
