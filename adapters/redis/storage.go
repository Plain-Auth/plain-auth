// Package redisstore provides namespaced secondary storage and distributed
// rate limits on a standalone Redis or Valkey server.
package redisstore

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultPrefix is used when New is given an empty prefix.
const DefaultPrefix = "plainauth:"

type Store struct {
	client          *redis.Client
	prefix, pattern string
	useTakeScript   atomic.Bool
}

// New uses a caller-owned, single-node Redis client. Choose a distinct prefix
// for each application and environment sharing the database.
func New(client *redis.Client, prefix string) (*Store, error) {
	if client == nil {
		return nil, errors.New("redisstore: client is required")
	}
	if prefix == "" {
		prefix = DefaultPrefix
	}
	escaped := strings.NewReplacer(`\`, `\\`, "*", `\*`, "?", `\?`, "[", `\[`, "]", `\]`).Replace(prefix)
	return &Store{client: client, prefix: prefix, pattern: escaped + "*"}, nil
}

func optional(value string, err error) (string, bool, error) {
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	return value, err == nil, err
}

// Get distinguishes an absent key from a stored empty string.
func (s *Store) Get(ctx context.Context, key string) (string, bool, error) {
	return optional(s.client.Get(ctx, s.prefix+key).Result())
}

// Set replaces value and expiry. A nonpositive TTL leaves the key persistent.
// Positive TTLs are whole seconds.
func (s *Store) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if ttl > 0 && ttl%time.Second != 0 {
		return errors.New("redisstore: set TTL must be whole seconds")
	}
	return s.client.Set(ctx, s.prefix+key, value, max(ttl, 0)).Err()
}

func (s *Store) Delete(ctx context.Context, key string) error {
	return s.client.Del(ctx, s.prefix+key).Err()
}

var take = redis.NewScript(`
local value = redis.call('GET', KEYS[1])
if value then redis.call('DEL', KEYS[1]) end
return value`)

// GetAndDelete atomically consumes a value. Older servers can execute the
// equivalent single-key Lua operation when GETDEL is unavailable.
func (s *Store) GetAndDelete(ctx context.Context, key string) (string, bool, error) {
	key = s.prefix + key
	if !s.useTakeScript.Load() {
		value, err := s.client.GetDel(ctx, key).Result()
		if !redis.HasErrorPrefix(err, "unknown command") {
			return optional(value, err)
		}
		s.useTakeScript.Store(true)
	}
	return optional(take.Run(ctx, s.client, []string{key}).Text())
}

var increment = redis.NewScript(`
if redis.call('SET', KEYS[1], '1', 'NX', 'PX', ARGV[1]) then
  return '1'
end
redis.call('INCR', KEYS[1])
return redis.call('GET', KEYS[1])`)

// Increment returns the new count. Its positive, whole-second TTL applies
// only when this operation creates a key. An existing key keeps its expiry.
func (s *Store) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if ttl <= 0 || ttl%time.Second != 0 {
		return 0, errors.New("redisstore: increment TTL must be positive whole seconds")
	}
	return s.increment(ctx, key, ttl)
}

func (s *Store) increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	ms := int64((ttl-1)/time.Millisecond) + 1
	return increment.Run(ctx, s.client, []string{s.prefix + key}, ms).Int64()
}

// ConsumeRateLimit implements the auth handler's RateLimitStorage interface.
// Redis starts a fixed window on the first request. Over-budget requests
// return the configured retry window and keep the existing key expiry.
func (s *Store) ConsumeRateLimit(ctx context.Context, key string, maximum int, window time.Duration, _ time.Time) (time.Duration, error) {
	if key == "" || maximum < 1 || window <= 0 {
		return 0, errors.New("redisstore: invalid rate limit")
	}
	count, err := s.increment(ctx, "rate-limit:"+key, window)
	if err != nil {
		return 0, err
	}
	if count > int64(maximum) {
		return window, nil
	}
	return 0, nil
}

func (s *Store) scan(ctx context.Context, visit func([]string) error) error {
	var cursor uint64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		keys, next, err := s.client.Scan(ctx, cursor, s.pattern, 100).Result()
		if err != nil {
			return err
		}
		// Also bound deletion to the literal prefix locally.
		keys = slices.DeleteFunc(keys, func(key string) bool { return !strings.HasPrefix(key, s.prefix) })
		if len(keys) > 0 {
			if err := visit(keys); err != nil {
				return err
			}
		}
		if next == 0 {
			return nil
		}
		cursor = next
	}
}

// ListKeys lists unique keys, without the prefix. Concurrent writes can change
// the keyspace while SCAN is walking it.
func (s *Store) ListKeys(ctx context.Context) ([]string, error) {
	keys := map[string]struct{}{}
	err := s.scan(ctx, func(batch []string) error {
		for _, key := range batch {
			keys[strings.TrimPrefix(key, s.prefix)] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return slices.Sorted(maps.Keys(keys)), nil
}

// Clear deletes one SCAN page at a time. A cancelled or failed clear can be
// retried; earlier pages may already have been removed. Writers may add new keys.
func (s *Store) Clear(ctx context.Context) error {
	return s.scan(ctx, func(keys []string) error { return s.client.Del(ctx, keys...).Err() })
}
