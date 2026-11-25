package plainauth

import "errors"

// VerificationCleanupStore deletes expired verification records, such as
// OAuth states, passkey challenges and reset tokens, while it writes new
// ones. KeepExpiredVerifications(true) stops that. The first call fixes the
// setting for the store and every copy of it; the same value again does
// nothing, and the other value is an error.
type VerificationCleanupStore interface {
	KeepExpiredVerifications(keep bool) error
}

// prepareVerificationCleanup passes Options.DisableVerificationCleanup to
// the store. Both values are passed, so instances sharing a store must agree.
func prepareVerificationCleanup(opts *Options) error {
	if store, ok := opts.Store.(VerificationCleanupStore); ok {
		return store.KeepExpiredVerifications(opts.DisableVerificationCleanup)
	}
	if opts.DisableVerificationCleanup {
		return errors.New("auth: DisableVerificationCleanup requires a store implementing VerificationCleanupStore")
	}
	return nil
}
