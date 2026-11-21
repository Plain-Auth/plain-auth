package memory

import (
	"context"
	"time"

	auth "github.com/nabuhadba/go-better-auth"
)

func (s *Store) SaveSessionLoginMethod(ctx context.Context, token, method string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	ss, ok := s.sessions[token]
	if !ok || !ss.ExpiresAt.After(now) {
		return nil
	}
	c, ok := s.users[ss.UserID]
	if !ok {
		return auth.ErrNotFound
	}
	c.lastLoginMethod = method
	s.users[ss.UserID] = c
	return nil
}

func (s *Store) UserLoginMethod(ctx context.Context, id string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	c, ok := s.users[id]
	if !ok {
		return "", auth.ErrNotFound
	}
	return c.lastLoginMethod, nil
}
