package memory

import (
	"context"
	"errors"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/sessionfields"
)

var _ auth.UserFieldStore = (*Store)(nil)

func (s *Store) ValidateUserFields(fields map[string]auth.UserField) error {
	_, err := sessionfields.NormalizeUser(fields)
	return err
}
func (s *Store) ReadUserFields(ctx context.Context, id string, fields map[string]auth.UserField) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fields, err := sessionfields.NormalizeUser(fields)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.users[id]
	if !ok {
		return nil, auth.ErrNotFound
	}
	out := make(map[string]any)
	for _, f := range fields {
		if f.Hidden {
			continue
		}
		raw, ok := rec.fields[f.Column]
		if !ok {
			raw = f.Default
		}
		out[f.Column] = raw
	}
	return out, nil
}
func (s *Store) UpdateUserFields(ctx context.Context, id string, actor *auth.Session, p auth.ProfileUpdate, now time.Time) error {
	if len(p.PhysicalUserFields()) == 0 {
		return errors.New("memory: empty user field update")
	}
	started := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	rec, ok := s.users[id]
	if !ok {
		return auth.ErrNotFound
	}
	if actor != nil {
		row, ok := s.sessions[actor.Token]
		observed := now.Add(time.Since(started))
		if !ok || actor.RequireOwner() != nil || row.Session.RequireOwner() != nil || actor.UserID != id || row.UserID != id || row.ID != actor.ID || !row.ExpiresAt.After(observed) {
			return auth.ErrNotFound
		}
		u := rec.user
		if u.AdminUserFields != nil && u.Banned && (u.BanExpires == nil || u.BanExpires.After(observed)) {
			return auth.ErrNotFound
		}
	}
	return s.applyProfile(id, rec, p, now)
}
