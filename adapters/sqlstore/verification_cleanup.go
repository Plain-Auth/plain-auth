package sqlstore

import (
	"context"
	"errors"
	"strings"
	"time"

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

// codeKinds are the identifier prefixes of verification rows whose writes
// replace only their own key: password reset and deletion links, and email
// and phone codes with their owner bindings.
var codeKinds = []string{"reset-password:", "delete-account-", "email-verification-otp-", "sign-in-otp-", "forget-password-otp-", "change-email-otp-", "email-otp-owner:", "phone-number-otp-", "phone-number-reset-", "phone-proof-sha256-", "phone-proof-owner:"}

var sweepCodesQuery = func() string {
	kinds := make([]string, len(codeKinds))
	for i, prefix := range codeKinds {
		kinds[i] = `"identifier" LIKE '` + prefix + `%'`
	}
	return `DELETE FROM "verification" WHERE "expiresAt"<=? AND (` + strings.Join(kinds, " OR ") + `)`
}()

// sweepCodes deletes the expired rows of codeKinds, at most once a minute
// per store, unless expired verification rows are kept.
func (s *Store) sweepCodes(ctx context.Context, now time.Time) error {
	if !s.sweeping() || s.codesNextSweep == nil {
		return nil
	}
	next := s.codesNextSweep.Load()
	if now.Unix() < next || !s.codesNextSweep.CompareAndSwap(next, now.Add(time.Minute).Unix()) {
		return nil
	}
	_, err := s.db.ExecContext(ctx, s.bind(sweepCodesQuery), s.date(now))
	return err
}

// sweeping reports whether writes delete expired verification rows of their
// kind in passing. Deletes a write needs, of the one row it replaces, run
// either way.
func (s *Store) sweeping() bool {
	return s.cleanup == nil || s.cleanup.Load() != cleanupOff
}
