package memory

import (
	"context"
	"errors"
	"strings"
	"time"

	authn "github.com/Plain-Auth/plain-auth"
)

var _ authn.AnonymousStore = (*Store)(nil)

func (*Store) CheckAnonymousSchema(ctx context.Context) error { return ctx.Err() }
func (s *Store) IsAnonymous(ctx context.Context, id string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	rec, ok := s.users[id]
	if !ok {
		return false, authn.ErrNotFound
	}
	return rec.user.IsAnonymous != nil && *rec.user.IsAnonymous, nil
}
func (s *Store) CreateAnonymous(ctx context.Context, u authn.User, ss authn.StoredSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if u.IsAnonymous == nil || !*u.IsAnonymous || u.ID != ss.UserID {
		return errors.New("memory: invalid guest creation")
	}
	key := strings.ToLower(u.Email)
	if _, ok := s.emailToID[key]; ok {
		return authn.ErrEmailTaken
	}
	if _, ok := s.users[u.ID]; ok {
		return errors.New("memory: duplicate guest ID")
	}
	if err := s.insertSession(ss); err != nil {
		return err
	}
	s.users[u.ID] = credential{user: copyUser(u)}
	s.emailToID[key] = u.ID
	return nil
}
func (s *Store) DeleteAnonymous(ctx context.Context, id, token string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	src := s.sessions[token]
	rec, ok := s.users[id]
	if !ok || src.UserID != id || !src.ExpiresAt.After(now) {
		return authn.ErrNotFound
	}
	if rec.user.IsAnonymous == nil || !*rec.user.IsAnonymous {
		return authn.ErrNotAnonymous
	}
	s.deleteUserRecords(id, rec)
	return nil
}
func (s *Store) LinkAnonymous(ctx context.Context, source, target string, now time.Time, retain bool, callback func(context.Context, authn.AnonymousLink) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	src := s.sessions[source]
	from := s.users[src.UserID]
	if !src.ExpiresAt.After(now) || from.user.IsAnonymous == nil || !*from.user.IsAnonymous || from.guestLinked {
		return nil
	}
	dst := s.sessions[target]
	to, ok := s.users[dst.UserID]
	if !ok || !dst.ExpiresAt.After(now) {
		return authn.ErrNotFound
	}
	if dst.UserID == src.UserID || to.user.IsAnonymous != nil && *to.user.IsAnonymous {
		return nil
	}
	guest, permanent := copyUser(from.user), copyUser(to.user)
	flag := false
	permanent.IsAnonymous = &flag
	if callback != nil {
		if err := callback(ctx, authn.AnonymousLink{AnonymousUser: authn.SessionResult{Session: src.Session, User: guest}, NewUser: authn.SessionResult{Session: dst.Session, User: permanent}}); err != nil {
			return err
		}
	}
	if retain {
		from.guestLinked = true
		s.users[src.UserID] = from
	} else {
		s.deleteUserRecords(src.UserID, from)
	}
	return nil
}
