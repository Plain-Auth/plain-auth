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
	if err := mirror.MirrorSessions(opts.SecondaryStorage, SessionMirrorOptions{}); err != nil {
		return err
	}
	// Rate limits share the storage unless the host chose where they live.
	if opts.RateLimitStorage == nil {
		if limits, ok := opts.SecondaryStorage.(RateLimitStorage); ok {
			opts.RateLimitStorage = limits
		} else {
			opts.RateLimitStorage = secondaryRateLimits{opts.SecondaryStorage}
		}
	}
	return nil
}

// secondaryRateLimits counts requests with Increment, which opens a fixed
// window of whole seconds on a key's first request. A refused request is
// told to wait the whole window, since the storage does not report how much
// of it is left.
type secondaryRateLimits struct {
	storage SecondaryStorage
}

func (l secondaryRateLimits) ConsumeRateLimit(ctx context.Context, key string, maximum int, window time.Duration, _ time.Time) (time.Duration, error) {
	ttl := max(time.Second, (window+time.Second-1)/time.Second*time.Second)
	count, err := l.storage.Increment(ctx, key, ttl)
	if err != nil {
		return 0, err
	}
	if count > int64(maximum) {
		return window, nil
	}
	return 0, nil
}
