package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// A second, versioned credential format for the shared SQLite test.
func fixturePasswordHash(_ context.Context, password string) (string, error) {
	var salt [16]byte
	rand.Read(salt[:])
	derived := pbkdf2.Key([]byte(password), salt[:], 600_000, 32, sha256.New)
	return "fixture-v1$" + hex.EncodeToString(salt[:]) + "$" + hex.EncodeToString(derived), nil
}

func fixturePasswordVerify(_ context.Context, encoded, password string) (bool, error) {
	fields := strings.Split(encoded, "$")
	if len(fields) != 3 || fields[0] != "fixture-v1" {
		return false, nil
	}
	salt, err := hex.DecodeString(fields[1])
	if err != nil || len(salt) != 16 {
		return false, nil
	}
	want, err := hex.DecodeString(fields[2])
	if err != nil || len(want) != 32 {
		return false, nil
	}
	derived := pbkdf2.Key([]byte(password), salt, 600_000, 32, sha256.New)
	return subtle.ConstantTimeCompare(derived, want) == 1, nil
}
