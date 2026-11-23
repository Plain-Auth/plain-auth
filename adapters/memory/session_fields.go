package memory

import (
	"context"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/sessionfields"
)

func (s *Store) ValidateSessionFields(fields map[string]auth.SessionField) error {
	_, err := sessionfields.Normalize(fields)
	return err
}
func (s *Store) ReadSessionFields(ctx context.Context, rows []auth.Session, fields map[string]auth.SessionField) (map[string]map[string]any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fields, err := sessionfields.Normalize(fields)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]any, len(rows))
	for _, want := range rows {
		row, ok := s.sessions[want.Token]
		if !ok || row.ID != want.ID || row.UserID != want.UserID {
			continue
		}
		values, err := row.PhysicalSessionFields()
		if err != nil {
			return nil, err
		}
		public := make(map[string]any)
		for name, f := range fields {
			if !f.Hidden {
				value, exists := values[f.Column]
				if !exists {
					value = f.StaticDefault()
				}
				public[name] = value
			}
		}
		out[row.Token] = public
	}
	return out, nil
}
func (s *Store) UpdateSessionFields(ctx context.Context, actor auth.Session, fields map[string]auth.SessionField, changes map[string]any, now time.Time) error {
	if err := actor.RequireOwner(); err != nil {
		return auth.ErrNotFound
	}
	started := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	row, ok := s.sessions[actor.Token]
	if !ok || row.ID != actor.ID || row.UserID != actor.UserID || !row.ExpiresAt.After(now.Add(time.Since(started))) || row.Session.RequireOwner() != nil {
		return auth.ErrNotFound
	}
	if u := s.users[row.UserID].user; u.AdminUserFields != nil && u.Banned && (u.BanExpires == nil || u.BanExpires.After(now)) {
		return auth.ErrNotFound
	}
	row, err := row.WithStoredSessionPatch(fields, changes)
	if err != nil {
		return err
	}
	row.UpdatedAt = now
	s.sessions[actor.Token] = row
	return nil
}
