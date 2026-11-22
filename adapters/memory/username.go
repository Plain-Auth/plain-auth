package memory

import (
	"context"
	"time"

	"github.com/Stonewrit/stonewrit-auth"
)

var _ stonewrit.UsernameStore = (*Store)(nil)

func (s *Store) CheckUsernameSchema(ctx context.Context, display bool) error { return ctx.Err() }

func cloneUsername(f *stonewrit.UsernameFields, display bool) *stonewrit.UsernameFields {
	n := &stonewrit.UsernameFields{}
	if f != nil {
		n.Username = copyPointer(f.Username)
	}
	if display {
		n.DisplayUsernameFields = &stonewrit.DisplayUsernameFields{}
		if f != nil && f.DisplayUsernameFields != nil {
			n.DisplayUsername = copyPointer(f.DisplayUsername)
		}
	}
	return n
}

// Scanning the in-process records also releases names immediately on account deletion.
func (s *Store) usernameOwner(name string) string {
	for id, rec := range s.users {
		f := rec.user.UsernameFields
		if f != nil && f.Username != nil && *f.Username == name {
			return id
		}
	}
	return ""
}

func (s *Store) UsernameExists(ctx context.Context, name string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.usernameOwner(name) != "", ctx.Err()
}

func (s *Store) UsernameCredential(ctx context.Context, name string) (stonewrit.User, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return stonewrit.User{}, "", err
	}
	rec, ok := s.users[s.usernameOwner(name)]
	if !ok || rec.hash == "" {
		return stonewrit.User{}, "", stonewrit.ErrNotFound
	}
	return copyUser(rec.user), rec.hash, nil
}

func (s *Store) ReadUsername(ctx context.Context, id string, display bool) (*stonewrit.UsernameFields, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rec, ok := s.users[id]
	if !ok {
		return nil, stonewrit.ErrNotFound
	}
	return cloneUsername(rec.user.UsernameFields, display), nil
}

func (s *Store) UpdateUsernameProfile(ctx context.Context, id, token string, p stonewrit.ProfileUpdate, now time.Time, immutable bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	rec, ok := s.users[id]
	ss := s.sessions[token]
	if !ok || ss.UserID != id || ss.ImpersonatedBy != nil || !ss.ExpiresAt.After(now) {
		return stonewrit.ErrNotFound
	}
	old := rec.user.UsernameFields
	if immutable && old != nil && old.Username != nil && *old.Username != "" && (p.ClearUsername || p.Username != nil && *old.Username != *p.Username) {
		return stonewrit.ErrUsernameImmutable
	}
	if p.Username != nil && !p.ClearUsername {
		if owner := s.usernameOwner(*p.Username); owner != "" && owner != id {
			return stonewrit.ErrUsernameTaken
		}
	}
	f := cloneUsername(old, p.ClearDisplayUsername || p.DisplayUsername != nil || old != nil && old.DisplayUsernameFields != nil)
	if p.ClearUsername {
		f.Username = nil
	} else if p.Username != nil {
		f.Username = copyPointer(p.Username)
	}
	if p.ClearDisplayUsername {
		f.DisplayUsername = nil
	} else if p.DisplayUsername != nil {
		f.DisplayUsername = copyPointer(p.DisplayUsername)
	}
	rec.user.UsernameFields = f
	return s.applyProfile(id, rec, p, now)
}
