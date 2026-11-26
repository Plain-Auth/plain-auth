package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"

	authn "github.com/Plain-Org/plain-auth"
)

// fixtureIdentifierStorage sets Options.StoreVerificationIdentifier for the
// cross-runtime comparison of stored verification identifiers.
func fixtureIdentifierStorage(opts *authn.Options, mode string) {
	switch mode {
	case "hashed":
		opts.StoreVerificationIdentifier = authn.VerificationIdentifierStorage{Hashed: true}
	case "custom":
		opts.StoreVerificationIdentifier = authn.VerificationIdentifierStorage{Hash: func(_ context.Context, identifier string) (string, error) {
			sum := sha256.Sum256([]byte(identifier))
			return hex.EncodeToString(sum[:]), nil
		}}
	case "reset-only":
		opts.StoreVerificationIdentifierOverrides = map[string]authn.VerificationIdentifierStorage{"reset-password": {Hashed: true}}
	default:
		log.Fatal("unknown verification identifier fixture")
	}
}
