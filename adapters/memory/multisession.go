package memory

import (
	"context"
	"time"

	authn "github.com/Stonewrit/stonewrit-auth"
)

var _ authn.DeviceSessionStore = (*Store)(nil)

func (s *Store) DeviceSessions(ctx context.Context, tokens []string, now time.Time) (map[string]authn.SessionResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	found := make(map[string]authn.SessionResult)
	for _, token := range tokens {
		if row, ok := s.sessions[token]; ok && row.ExpiresAt.After(now) {
			found[token] = authn.SessionResult{Session: row.Session, User: copyUser(s.users[row.UserID].user)}
		}
	}
	return found, nil
}

func (s *Store) DeleteDeviceSessions(ctx context.Context, tokens []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, token := range tokens {
		delete(s.sessions, token)
	}
	return nil
}

func (s *Store) RevokeDeviceSession(ctx context.Context, active, target string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if row, ok := s.sessions[active]; !ok || !row.ExpiresAt.After(now) {
		return authn.ErrNotFound
	}
	delete(s.sessions, target)
	return nil
}
