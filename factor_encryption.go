package betterauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

func (a *Auth) sealFactorData(raw []byte) (string, error) {
	key := sha256.Sum256([]byte(a.opts.Secret))
	cipher, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return "", err
	}
	nonce := make([]byte, cipher.NonceSize())
	rand.Read(nonce)
	data := hex.EncodeToString(cipher.Seal(nonce, nonce, raw, nil))
	if len(a.opts.Secrets) > 0 {
		return "$ba$" + strconv.Itoa(a.opts.Secrets[0].Version) + "$" + data, nil
	}
	return data, nil
}
func (a *Auth) openFactorData(data string) ([]byte, error) {
	keys := []string{a.opts.Secret}
	if strings.HasPrefix(data, "$ba$") {
		version, raw, ok := strings.Cut(strings.TrimPrefix(data, "$ba$"), "$")
		if !ok {
			return nil, errors.New("invalid encrypted factor envelope")
		}
		keys = nil
		data = raw
		for _, k := range a.opts.Secrets {
			if strconv.Itoa(k.Version) == version {
				keys = append(keys, k.Value)
			}
		}
	} else if len(a.opts.Secrets) > 0 {
		if a.legacySecret == "" {
			return nil, errors.New("legacy encryption key unavailable")
		}
		keys = []string{a.legacySecret}
	}
	buf, err := hex.DecodeString(data)
	if err != nil || len(buf) < chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, errors.New("invalid encrypted factor data")
	}
	for _, secret := range keys {
		key := sha256.Sum256([]byte(secret))
		cipher, err := chacha20poly1305.NewX(key[:])
		if err != nil {
			return nil, err
		}
		if raw, err := cipher.Open(nil, buf[:cipher.NonceSize()], buf[cipher.NonceSize():], nil); err == nil {
			return raw, nil
		}
	}
	return nil, errors.New("unable to decrypt factor data")
}
