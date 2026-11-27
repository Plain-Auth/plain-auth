package plainauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const recordPrefix = "authn.v1."

var errEncryptedRecord = errors.New("authn: invalid encrypted record or unavailable key")

// recordKey separates storage encryption keys from session-signing keys.
func recordKey(secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("authn/v1/encryption-at-rest"))
	return mac.Sum(nil)
}

// EncryptRecord seals plaintext for storage with the active versioned
// secret, bound to purpose: DecryptRecord opens it only with the same
// purpose. Plugins use it for values they must read back, such as an
// encrypted OAuth client secret. The envelope is this library's own, so
// another runtime cannot read it.
func (a *Auth) EncryptRecord(purpose string, plaintext []byte) (string, error) {
	return a.sealRecord(purpose, plaintext)
}

// DecryptRecord opens a record EncryptRecord sealed for purpose, with any
// configured secret version. It fails for another purpose, a retired key
// that is no longer configured or a damaged record.
func (a *Auth) DecryptRecord(purpose, record string) ([]byte, error) {
	return a.openRecord(purpose, record)
}

func (a *Auth) sealRecord(purpose string, raw []byte) (string, error) {
	return sealSecretRecord(a.encryptionSecrets()[0], purpose, raw)
}

func (a *Auth) encryptionSecrets() []VersionedSecret {
	if len(a.opts.Secrets) > 0 {
		return a.opts.Secrets
	}
	return []VersionedSecret{{Value: a.opts.Secret}}
}

func sealSecretRecord(active VersionedSecret, purpose string, raw []byte) (string, error) {
	header := recordPrefix + strconv.Itoa(active.Version) + "."
	cipher, err := chacha20poly1305.NewX(recordKey(active.Value))
	if err != nil {
		return "", err
	}
	nonce := make([]byte, cipher.NonceSize())
	rand.Read(nonce)
	sealed := cipher.Seal(nonce, nonce, raw, []byte(header+purpose))
	return header + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (a *Auth) openRecord(purpose, record string) ([]byte, error) {
	return openSecretRecord(a.encryptionSecrets(), purpose, record)
}

func openSecretRecord(keys []VersionedSecret, purpose, record string) ([]byte, error) {
	rest, valid := strings.CutPrefix(record, recordPrefix)
	id, payload, found := strings.Cut(rest, ".")
	if !valid || !found {
		return nil, errEncryptedRecord
	}
	var secret string
	for _, key := range keys {
		if strconv.Itoa(key.Version) == id {
			secret = key.Value
			break
		}
	}
	if secret == "" {
		return nil, errEncryptedRecord
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(payload)
	if err != nil || len(raw) < chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, errEncryptedRecord
	}
	cipher, err := chacha20poly1305.NewX(recordKey(secret))
	if err != nil {
		return nil, err
	}
	plain, err := cipher.Open(nil, raw[:cipher.NonceSize()], raw[cipher.NonceSize():], []byte(recordPrefix+id+"."+purpose))
	if err != nil {
		return nil, errEncryptedRecord
	}
	return plain, nil
}
