package stonewrit

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

// Use NFKC normalization and an ASCII-hex salt for credential interoperability.
func passwordKey(password, salt string) ([]byte, error) {
	return scrypt.Key([]byte(norm.NFKC.String(password)), []byte(salt), 16384, 16, 1, 64)
}

// HashPassword uses the built-in salted scrypt credential format. Hosts can
// delegate to it when adapting an existing password database.
func HashPassword(ctx context.Context, password string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var raw [16]byte
	rand.Read(raw[:])
	salt := hex.EncodeToString(raw[:])
	key, err := passwordKey(password, salt)
	if err != nil {
		return "", err
	}
	return salt + ":" + hex.EncodeToString(key), nil
}

// VerifyPasswordHash checks the built-in scrypt format. It returns false for
// an incorrect password and an error for a malformed stored credential.
func VerifyPasswordHash(ctx context.Context, hash, password string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	salt, encoded, ok := strings.Cut(hash, ":")
	if !ok || len(salt) != 32 || len(encoded) != 128 {
		return false, errors.New("authn: invalid stored credential")
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

// ValidateNewPassword runs configured plugin checks for a credential-setting
// operation. Custom server endpoints pass their stable path under the auth mount.
func (a *Auth) ValidateNewPassword(ctx context.Context, path, password string) error {
	for _, plugin := range a.opts.Plugins {
		if plugin.OnValidateNewPassword != nil {
			if err := plugin.OnValidateNewPassword(ctx, path, password); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *Auth) hashCredential(ctx context.Context, path, password string) (string, error) {
	if err := a.ValidateNewPassword(ctx, path, password); err != nil {
		return "", err
	}
	return a.derivePassword(ctx, password)
}

func (a *Auth) derivePassword(ctx context.Context, password string) (string, error) {
	if err := a.acquirePasswordSlot(ctx); err != nil {
		return "", err
	}
	defer func() { <-a.passwordSlots }()
	if a.opts.PasswordHash == nil {
		return HashPassword(ctx, password)
	}
	hash, err := a.opts.PasswordHash(ctx, password)
	if err == nil && hash == "" {
		return "", errors.New("authn: password hasher returned an empty credential")
	}
	return hash, err
}

func (a *Auth) checkCredential(ctx context.Context, hash, password string) (bool, error) {
	if err := a.acquirePasswordSlot(ctx); err != nil {
		return false, err
	}
	defer func() { <-a.passwordSlots }()
	if a.opts.PasswordVerify != nil {
		return a.opts.PasswordVerify(ctx, hash, password)
	}
	return VerifyPasswordHash(ctx, hash, password)
}
