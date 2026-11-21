package betterauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

// Match the NFKC normalization and ASCII-hex salt used by Better Auth.
func passwordKey(password, salt string) ([]byte, error) {
	return scrypt.Key([]byte(norm.NFKC.String(password)), []byte(salt), 16384, 16, 1, 64)
}

func hashPassword(password string) (string, error) {
	var raw [16]byte
	rand.Read(raw[:])
	salt := hex.EncodeToString(raw[:])
	key, err := passwordKey(password, salt)
	if err != nil {
		return "", err
	}
	return salt + ":" + hex.EncodeToString(key), nil
}

const dummyPasswordHash = "00000000000000000000000000000000:" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000"

func verifyPassword(hash, password string) (bool, error) {
	salt, encoded, ok := strings.Cut(hash, ":")
	if !ok || len(salt) != 32 || len(encoded) != 128 {
		return false, errors.New("betterauth: invalid stored credential")
	}
	want, err := hex.DecodeString(encoded)
	if err != nil {
		return false, err
	}
	got, err := passwordKey(password, salt)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// Scrypt uses about 32 MiB per operation. Limit simultaneous derivations and
// allow callers to cancel while waiting for a slot.
func (a *Auth) acquirePasswordSlot(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case a.passwordSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (a *Auth) hashCredential(ctx context.Context, password string) (string, error) {
	if err := a.acquirePasswordSlot(ctx); err != nil {
		return "", err
	}
	defer func() { <-a.passwordSlots }()
	return hashPassword(password)
}
func (a *Auth) checkCredential(ctx context.Context, hash, password string) (bool, error) {
	if err := a.acquirePasswordSlot(ctx); err != nil {
		return false, err
	}
	defer func() { <-a.passwordSlots }()
	return verifyPassword(hash, password)
}
