package plainauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"
)

// The purpose prefixes of the verification identifiers that
// Options.StoreVerificationIdentifier applies to. The stores write each such
// identifier as its prefix followed by the key the core passes them; the SQL
// store spells them out in adapters/sqlstore, so keep the two in step.
const (
	resetPasswordPrefix = "reset-password:"
	deleteAccountPrefix = "delete-account-"
	magicLinkPrefix     = "magic-link:"
	oneTimeTokenPrefix  = "one-time-token:"
)

var verificationIdentifierPrefixes = []string{resetPasswordPrefix, deleteAccountPrefix, magicLinkPrefix, oneTimeTokenPrefix}

// VerificationIdentifierStorage sets how the token in a verification
// identifier is stored. The zero value stores the token as it is.
type VerificationIdentifierStorage struct {
	// Hashed stores, in place of the token, the SHA-256 of the whole
	// identifier, purpose prefix included, as unpadded URL-safe Base64: 43
	// characters. It uses no secret, so changing Secret does not change it.
	Hashed bool
	// Hash, when set, stores its result in place of the token. It receives
	// the whole identifier, such as "reset-password:" followed by the token,
	// and must return the same value for the same input: 1 to 240 bytes of
	// UTF-8 without NUL. Its error fails the request. Set Hashed or Hash, not
	// both.
	Hash func(ctx context.Context, identifier string) (string, error)
}

// prepareVerificationIdentifiers resolves the storage of each purpose: its
// override if a key matches it, else the default. A key matches a purpose
// when it starts the purpose's prefix, and a purpose takes at most one key,
// so one purpose never mixes plain and hashed records, which would let a
// stored hash redeem its link.
func prepareVerificationIdentifiers(opts Options) (map[string]VerificationIdentifierStorage, error) {
	both := func(s VerificationIdentifierStorage) bool { return s.Hashed && s.Hash != nil }
	if both(opts.StoreVerificationIdentifier) {
		return nil, errors.New("auth: StoreVerificationIdentifier sets Hashed or Hash, not both")
	}
	storage := make(map[string]VerificationIdentifierStorage, len(verificationIdentifierPrefixes))
	for _, prefix := range verificationIdentifierPrefixes {
		storage[prefix] = opts.StoreVerificationIdentifier
	}
	keys := map[string]string{}
	for _, key := range slices.Sorted(maps.Keys(opts.StoreVerificationIdentifierOverrides)) {
		s := opts.StoreVerificationIdentifierOverrides[key]
		if both(s) {
			return nil, fmt.Errorf("auth: StoreVerificationIdentifierOverrides[%q] sets Hashed or Hash, not both", key)
		}
		matched := false
		for _, prefix := range verificationIdentifierPrefixes {
			if key == "" || !strings.HasPrefix(prefix, key) {
				continue
			}
			if other, ok := keys[prefix]; ok {
				return nil, fmt.Errorf("auth: StoreVerificationIdentifierOverrides keys %q and %q both match %q", other, key, prefix)
			}
			matched, keys[prefix], storage[prefix] = true, key, s
		}
		if !matched {
			return nil, fmt.Errorf("auth: StoreVerificationIdentifierOverrides key %q is not the start of %s; email and phone codes, OAuth and SAML states, two-factor records and wallet nonces are not covered", key, strings.Join(verificationIdentifierPrefixes, ", "))
		}
	}
	return storage, nil
}

// verificationKey returns what a store keeps after prefix for the
// verification identifier prefix+key: key itself when that purpose is stored
// plain, else the hash of the whole identifier.
func (a *Auth) verificationKey(ctx context.Context, prefix, key string) (string, error) {
	s := a.identifierStorage[prefix]
	switch {
	case s.Hash != nil:
		stored, err := s.Hash(ctx, prefix+key)
		if err != nil {
			return "", err
		}
		if stored == "" || len(stored) > 240 || !utf8.ValidString(stored) || strings.ContainsRune(stored, 0) {
			return "", errors.New("auth: a StoreVerificationIdentifier hash must return 1 to 240 bytes of UTF-8 without NUL")
		}
		return stored, nil
	case s.Hashed:
		sum := sha256.Sum256([]byte(prefix + key))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	}
	return key, nil
}
