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

func (a *Auth) sealRecord(purpose string, raw []byte) (string, error) {
	active := VersionedSecret{Value: a.opts.Secret}
	if len(a.opts.Secrets) > 0 {
		active = a.opts.Secrets[0]
	}
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
	rest, valid := strings.CutPrefix(record, recordPrefix)
	id, payload, found := strings.Cut(rest, ".")
	if !valid || !found {
		return nil, errEncryptedRecord
	}
	var secret string
	if len(a.opts.Secrets) == 0 && id == "0" {
		secret = a.opts.Secret
	}
	for _, key := range a.opts.Secrets {
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
