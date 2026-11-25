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
// per store, unless expired verification rows are kept. It is best effort:
// it gives up after two seconds, for example behind a code transaction's
// locks, and a failure leaves the rows to the next sweep rather than failing
// the write that started it.
func (s *Store) sweepCodes(ctx context.Context, now time.Time) {
	if !s.sweeping() || s.codesNextSweep == nil {
		return
	}
	next := s.codesNextSweep.Load()
	if now.Unix() < next || !s.codesNextSweep.CompareAndSwap(next, now.Add(time.Minute).Unix()) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, _ = s.db.ExecContext(ctx, s.bind(sweepCodesQuery), s.date(now))
}

// sweeping reports whether writes delete expired verification rows of their
// kind in passing. Deletes a write needs, of the one row it replaces, run
// either way.
func (s *Store) sweeping() bool {
	return s.cleanup == nil || s.cleanup.Load() != cleanupOff
}
