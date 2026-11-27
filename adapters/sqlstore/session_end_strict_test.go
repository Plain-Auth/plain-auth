package sqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// Every test in this package refuses a session end in an untracked
// transaction, so the suite checks that each path reports its ends.
func init() { strictSessionEnds = true }

// testPasswordHash and testPasswordVerify replace the password hash in
// tests that sign in many times, which would otherwise spend most of their
// race-detector time in scrypt; password hashing has its own tests.
func testPasswordHash(_ context.Context, password string) (string, error) {
	sum := sha256.Sum256([]byte(password))
	return "test$" + hex.EncodeToString(sum[:]), nil
}

func testPasswordVerify(ctx context.Context, encoded, password string) (bool, error) {
	want, _ := testPasswordHash(ctx, password)
	return encoded == want, nil
}
