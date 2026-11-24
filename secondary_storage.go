package plainauth

import (
	"context"
	"errors"
	"time"
)

// SecondaryStorage is a shared key-value store, such as Redis, that every
// replica reads. Implementations are safe for concurrent use. Get and
// GetAndDelete report whether the key was present. Set replaces the value
// and expiry, and a ttl of zero or less stores it without expiry. Increment
// adds one atomically and sets ttl only when it creates the key. Plain Auth
// passes whole seconds.
type SecondaryStorage interface {
	Get(ctx context.Context, key string) (string, bool, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	GetAndDelete(ctx context.Context, key string) (string, bool, error)
	Increment(ctx context.Context, key string, ttl time.Duration) (int64, error)
}

// SessionMirrorOptions configures how a store mirrors sessions into
// SecondaryStorage.
type SessionMirrorOptions struct{}

// SessionMirrorStore keeps a copy of each live session in SecondaryStorage,
// so a session read can skip the database. It writes the copy only while it
// holds the session's row locks, and deletes it before any revocation, user
// change or refresh of that session commits. Attaching the same storage
// again does nothing; a different storage is an error.
type SessionMirrorStore interface {
	MirrorSessions(SecondaryStorage, SessionMirrorOptions) error
}

// prepareSecondaryStorage attaches Options.SecondaryStorage to the store.
func prepareSecondaryStorage(opts *Options) error {
	if opts.SecondaryStorage == nil {
		if opts.StoreSessionInDatabase {
			return errors.New("auth: StoreSessionInDatabase requires SecondaryStorage")
		}
		return nil
	}
	// Sessions stay in the database; the storage holds a copy of each one.
	if !opts.StoreSessionInDatabase {
		return errors.New("auth: SecondaryStorage keeps a copy of each session and requires StoreSessionInDatabase")
	}
	mirror, ok := opts.Store.(SessionMirrorStore)
	if !ok {
		return errors.New("auth: SecondaryStorage requires a store implementing SessionMirrorStore")
	}
	return mirror.MirrorSessions(opts.SecondaryStorage, SessionMirrorOptions{})
}
