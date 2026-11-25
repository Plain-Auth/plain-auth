package memory

import (
	"errors"

	auth "github.com/Plain-Org/plain-auth"
)

var _ auth.VerificationCleanupStore = (*Store)(nil)

// KeepExpiredVerifications stops writes from deleting expired verification
// entries of their kind. The first call fixes the setting.
func (s *Store) KeepExpiredVerifications(keep bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleanupSet && s.keepExpired != keep {
		return errors.New("memory: this store is already used with a different DisableVerificationCleanup setting")
	}
	s.keepExpired, s.cleanupSet = keep, true
	return nil
}
