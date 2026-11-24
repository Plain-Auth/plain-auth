// Package kvtest is an in-memory SecondaryStorage for tests, with expiry,
// a record of the operations and injected failures.
package kvtest

import (
	"context"
	"maps"
	"slices"
	"sync"
	"time"
)

type entry struct {
	value   string
	expires time.Time
}

// Storage implements plainauth.SecondaryStorage. It is safe for concurrent use.
type Storage struct {
	mu     sync.Mutex
	values map[string]entry
	fail   map[string]error
	ops    []string
}

// New returns an empty storage.
func New() *Storage { return &Storage{values: map[string]entry{}, fail: map[string]error{}} }

// Fail makes every later call of op ("get", "set", "delete", "getdel" or
// "incr") return err, or succeed again when err is nil.
func (s *Storage) Fail(op string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.fail, op)
		return
	}
	s.fail[op] = err
}

// Clear removes every key, as a flush of the server would.
func (s *Storage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.values)
}

// Keys returns the live keys in order.
func (s *Storage) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep()
	return slices.Sorted(maps.Keys(s.values))
}

// Lookup returns a live value and its remaining lifetime, zero for none.
func (s *Storage) Lookup(key string) (string, time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep()
	e, ok := s.values[key]
	if !ok {
		return "", 0, false
	}
	var ttl time.Duration
	if !e.expires.IsZero() {
		ttl = time.Until(e.expires)
	}
	return e.value, ttl, true
}

// Ops returns the operations made so far, such as "set <key>".
func (s *Storage) Ops() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.ops)
}

func (s *Storage) sweep() {
	now := time.Now()
	for k, e := range s.values {
		if !e.expires.IsZero() && !e.expires.After(now) {
			delete(s.values, k)
		}
	}
}

func (s *Storage) begin(op, key string) error {
	s.ops = append(s.ops, op+" "+key)
	s.sweep()
	return s.fail[op]
}

func (s *Storage) Get(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin("get", key); err != nil {
		return "", false, err
	}
	e, ok := s.values[key]
	return e.value, ok, nil
}

func (s *Storage) Set(_ context.Context, key, value string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin("set", key); err != nil {
		return err
	}
	e := entry{value: value}
	if ttl > 0 {
		e.expires = time.Now().Add(ttl)
	}
	s.values[key] = e
	return nil
}

func (s *Storage) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin("delete", key); err != nil {
		return err
	}
	delete(s.values, key)
	return nil
}

func (s *Storage) GetAndDelete(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin("getdel", key); err != nil {
		return "", false, err
	}
	e, ok := s.values[key]
	delete(s.values, key)
	return e.value, ok, nil
}

func (s *Storage) Increment(_ context.Context, key string, ttl time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin("incr", key); err != nil {
		return 0, err
	}
	e, ok := s.values[key]
	var n int64
	if ok {
		for _, c := range e.value {
			n = n*10 + int64(c-'0')
		}
	} else if ttl > 0 {
		e.expires = time.Now().Add(ttl)
	}
	n++
	e.value = itoa(n)
	s.values[key] = e
	return n, nil
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
