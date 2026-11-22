package memory

import (
	"context"
	"errors"
	"strings"

	auth "github.com/Stonewrit/stonewrit-auth"
)

var _ auth.MagicLinkStore = (*Store)(nil)

type mailLink struct {
	auth.MagicLinkChallenge
	owner string
}

// SaveMagicLink binds a live link to the mailbox owner at issuance.
func (s *Store) SaveMagicLink(ctx context.Context, link auth.MagicLinkChallenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	for key, old := range s.magicLinks {
		if !old.ExpiresAt.After(link.CreatedAt) {
			delete(s.magicLinks, key)
		}
	}
	if _, exists := s.magicLinks[link.Key]; exists {
		return errors.New("memory: duplicate magic link storage key")
	}
	if s.magicLinks == nil {
		s.magicLinks = make(map[string]mailLink)
	}
	link.Email = strings.ToLower(link.Email)
	s.magicLinks[link.Key] = mailLink{link, s.emailToID[link.Email]}
	return nil
}

// CompleteMagicLink redeems a pending mailbox proof and creates the session
// under one lock. Operational errors leave the original proof available.
func (s *Store) CompleteMagicLink(ctx context.Context, key, newID string, session auth.StoredSession, allowSignup bool) (auth.User, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return auth.User{}, false, err
	}
	link, ok := s.magicLinks[key]
	if !ok || !link.ExpiresAt.After(session.CreatedAt) {
		delete(s.magicLinks, key)
		return auth.User{}, false, auth.ErrNotFound
	}
	id := s.emailToID[link.Email]
	if link.owner != "" && link.owner != id {
		delete(s.magicLinks, key)
		return auth.User{}, false, auth.ErrNotFound
	}
	rec, exists := s.users[id]
	if !exists {
		if !allowSignup {
			delete(s.magicLinks, key)
			return auth.User{}, false, auth.ErrMagicLinkSignUpDisabled
		}
		if _, inUse := s.users[newID]; inUse || newID == "" {
			return auth.User{}, false, errors.New("memory: invalid or duplicate user ID")
		}
		rec.user = auth.User{ID: newID, Email: link.Email, Name: link.Name, CreatedAt: session.CreatedAt}
	}
	session.UserID = rec.user.ID
	if err := s.insertSession(session); err != nil {
		return auth.User{}, false, err
	}
	if !rec.user.EmailVerified {
		if exists {
			s.revokeUnprovenAccess(&rec, session.Token)
		}
		rec.user.EmailVerified = true
		rec.user.UpdatedAt = session.CreatedAt
	}
	s.users[rec.user.ID] = rec
	s.emailToID[link.Email] = rec.user.ID
	delete(s.magicLinks, key)
	return copyUser(rec.user), !exists, nil
}
