package memory

import (
	"context"
	"crypto/rand"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

var _ auth.AccountLifecycleStore = (*Store)(nil)

func (s *Store) SetInitialPassword(ctx context.Context, userID, token, hash string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	record, ok := s.users[userID]
	row := s.sessions[token]
	if !ok || row.UserID != userID || !row.ExpiresAt.After(now) {
		return auth.ErrNotFound
	}
	if record.hash != "" {
		return auth.ErrPasswordAlreadySet
	}
	record.hash, record.accountID = hash, rand.Text()
	s.users[userID] = record
	return nil
}

func (s *Store) SaveDeletionToken(ctx context.Context, t auth.PasswordResetToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := s.users[t.UserID]; !ok {
		return auth.ErrNotFound
	}
	for key, row := range s.deletions {
		if !s.keepExpired && !row.ExpiresAt.After(t.CreatedAt) {
			delete(s.deletions, key)
		}
	}
	s.deletions[t.Token] = t
	return nil
}

// ConsumeDeletionToken spends an account deletion token, whoever presents
// it, and reports ErrNotFound unless it was issued to userID and is live.
func (s *Store) ConsumeDeletionToken(ctx context.Context, userID, token string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	t, ok := s.deletions[token]
	delete(s.deletions, token)
	if !ok || t.UserID != userID || !t.ExpiresAt.After(now) {
		return auth.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteAccount(ctx context.Context, id, token, expectedHash, deleteToken string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	rec, ok := s.users[id]
	row := s.sessions[token]
	if !ok || row.UserID != id || !row.ExpiresAt.After(now) || (expectedHash != "" && expectedHash != rec.hash) {
		return auth.ErrNotFound
	}
	if deleteToken != "" {
		t := s.deletions[deleteToken]
		if t.UserID != id || !t.ExpiresAt.After(now) {
			return auth.ErrNotFound
		}
	}
	s.deleteUserRecords(id, rec)
	return nil
}

// DeleteFixtureUser removes the supplied user and its dependent records in a test store.
func (s *Store) DeleteFixtureUser(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if rec, ok := s.users[id]; ok {
		s.deleteUserRecords(id, rec)
	}
	return nil
}

func (s *Store) deleteUserRecords(id string, rec credential) {
	s.deleteSessions(id, "")
	for key, transfer := range s.transfers {
		if transfer.userID == id {
			delete(s.transfers, key)
		}
	}
	for key, t := range s.resets {
		if t.UserID == id {
			delete(s.resets, key)
		}
	}
	for key, t := range s.deletions {
		if t.UserID == id {
			delete(s.deletions, key)
		}
	}
	for key, proof := range s.spentEmailProofs {
		if proof.owner == id {
			delete(s.spentEmailProofs, key)
		}
	}
	delete(s.users, id)
	delete(s.emailToID, strings.ToLower(rec.user.Email))
}

func (s *Store) ChangeAccountEmail(ctx context.Context, id, oldEmail, newEmail string, verified bool, now time.Time) (auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return auth.User{}, err
	}
	rec, ok := s.users[id]
	if !ok || strings.ToLower(oldEmail) != strings.ToLower(rec.user.Email) || rec.user.EmailVerified != verified {
		return auth.User{}, auth.ErrNotFound
	}
	key := strings.ToLower(newEmail)
	if owner, found := s.emailToID[key]; found && owner != id {
		return auth.User{}, auth.ErrEmailTaken
	}
	delete(s.emailToID, strings.ToLower(oldEmail))
	s.emailToID[key] = id
	rec.user.Email, rec.user.UpdatedAt = key, now
	s.users[id] = rec
	return copyUser(rec.user), nil
}
