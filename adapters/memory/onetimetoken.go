package memory

import (
	"context"
	"errors"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

var _ auth.OneTimeTokenStore = (*Store)(nil)

type sessionTransfer struct {
	token, sessionID, userID string
	expires                  time.Time
}

func (s *Store) SaveOneTimeToken(ctx context.Context, key string, source auth.Session, now, expires time.Time) error {
	started := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	now = now.Add(time.Since(started))
	row, ok := s.sessions[source.Token]
	owner, exists := s.users[source.UserID]
	if !ok || !exists || row.ID != source.ID || row.UserID != source.UserID || row.Token != source.Token || !row.ExpiresAt.After(now) {
		return auth.ErrNotFound
	}
	if row.RequireOwner() != nil || transferOwnerBanned(owner.user, now) {
		return auth.ErrNotFound
	}
	if !s.nextTransferExpiry.IsZero() && !s.nextTransferExpiry.After(now) {
		s.nextTransferExpiry = time.Time{}
		for k, p := range s.transfers {
			if !p.expires.After(now) {
				delete(s.transfers, k)
			} else if s.nextTransferExpiry.IsZero() || p.expires.Before(s.nextTransferExpiry) {
				s.nextTransferExpiry = p.expires
			}
		}
	}
	if _, exists := s.transfers[key]; exists {
		return errors.New("memory: duplicate one-time transfer key")
	}
	if s.transfers == nil {
		s.transfers = make(map[string]sessionTransfer)
	}
	if s.nextTransferExpiry.IsZero() || expires.Before(s.nextTransferExpiry) {
		s.nextTransferExpiry = expires
	}
	s.transfers[key] = sessionTransfer{token: row.Token, sessionID: row.ID, userID: row.UserID, expires: expires}
	return nil
}

func (s *Store) ConsumeOneTimeToken(ctx context.Context, key string, now time.Time) (auth.SessionResult, error) {
	started := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return auth.SessionResult{}, err
	}
	now = now.Add(time.Since(started))
	p, ok := s.transfers[key]
	delete(s.transfers, key)
	if !ok || !p.expires.After(now) {
		return auth.SessionResult{}, auth.ErrNotFound
	}
	row, present := s.sessions[p.token]
	owner, exists := s.users[p.userID]
	if !present || !exists || row.ID != p.sessionID || row.UserID != p.userID || row.Token != p.token || row.RequireOwner() != nil || transferOwnerBanned(owner.user, now) {
		return auth.SessionResult{}, auth.ErrTransferSessionMissing
	}
	if !row.ExpiresAt.After(now) {
		return auth.SessionResult{}, auth.ErrTransferSessionExpired
	}
	return auth.SessionResult{Session: row.Session, User: copyUser(owner.user)}, nil
}

func transferOwnerBanned(owner auth.User, now time.Time) bool {
	return owner.AdminUserFields != nil && owner.Banned && (owner.BanExpires == nil || owner.BanExpires.After(now))
}
