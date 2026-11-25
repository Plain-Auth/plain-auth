package sqlstore

import (
	"errors"

	authn "github.com/Plain-Org/plain-auth"
)

var _ authn.VerificationCleanupStore = (*Store)(nil)

const (
	cleanupUnset int32 = iota
	cleanupOn
	cleanupOff
)

// KeepExpiredVerifications stops writes from deleting expired verification
// rows of their kind. The first call fixes the setting for the store and
// every copy of it.
func (s *Store) KeepExpiredVerifications(keep bool) error {
	want := cleanupOn
	if keep {
		want = cleanupOff
	}
	if s.cleanup == nil {
		if keep {
			return errors.New("sqlstore: this store cannot keep expired verification rows")
		}
		return nil
	}
	if s.cleanup.CompareAndSwap(cleanupUnset, want) || s.cleanup.Load() == want {
		return nil
	}
	return errors.New("sqlstore: this store is already used with a different DisableVerificationCleanup setting")
}

// sweeping reports whether writes delete expired verification rows of their
// kind in passing. Deletes a write needs, of the one row it replaces, run
// either way.
func (s *Store) sweeping() bool {
	return s.cleanup == nil || s.cleanup.Load() != cleanupOff
}
