package memory

import (
	"context"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

var _ auth.AccountStore = (*Store)(nil)

func (s *Store) FindAccountUser(ctx context.Context, email string) (auth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return auth.User{}, err
	}
	rec, ok := s.users[s.emailToID[strings.ToLower(email)]]
	if !ok {
		return auth.User{}, auth.ErrNotFound
	}
	return copyUser(rec.user), nil
}

func (s *Store) UpdateProfile(ctx context.Context, id string, in auth.ProfileUpdate, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	record, ok := s.users[id]
	if !ok {
		return auth.ErrNotFound
	}
	return s.applyProfile(id, record, in, now)
}
func (s *Store) applyProfile(id string, record credential, in auth.ProfileUpdate, now time.Time) error {
	if in.ClearPhoneNumber {
		verified := false
		record.user.PhoneNumberFields = &auth.PhoneNumberFields{PhoneNumberVerified: &verified}
	}
	if in.Name != nil {
		record.user.Name = *in.Name
	}
	if in.ClearImage {
		record.user.Image = nil
	} else if in.Image != nil {
		image := *in.Image
		record.user.Image = &image
	}
	for k, v := range in.PhysicalUserFields() {
		if record.fields == nil {
			record.fields = map[string]any{}
		}
		record.fields[k] = v
	}
	record.user.UpdatedAt = now
	s.users[id] = record
	return nil
}

func (s *Store) CreateCredentialSession(ctx context.Context, expectedHash string, row auth.StoredSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	u, ok := s.users[row.UserID]
	if !ok || u.hash != expectedHash {
		return auth.ErrNotFound
	}
	if binding, ok := auth.PhoneLoginFrom(ctx); ok && !binding.Matches(u.user.PhoneNumberFields) {
		return auth.ErrNotFound
	}
	return s.insertSession(row)
}

func (s *Store) ChangeCredential(ctx context.Context, id, oldHash, newHash string, replacement *auth.StoredSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	record, ok := s.users[id]
	if !ok || record.hash != oldHash {
		return auth.ErrNotFound
	}
	if replacement != nil {
		if replacement.UserID != id {
			return auth.ErrNotFound
		}
		if err := s.insertSession(*replacement); err != nil {
			return err
		}
		s.deleteSessions(id, replacement.Token)
	}
	record.hash = newHash
	s.users[id] = record
	return nil
}

func (s *Store) SavePasswordResetToken(ctx context.Context, row auth.PasswordResetToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	rec, ok := s.users[row.UserID]
	if !ok || !strings.EqualFold(rec.user.Email, row.Email) {
		return auth.ErrNotFound
	}
	// Lazy expiry keeps abandoned reset requests from accumulating indefinitely.
	for key, existing := range s.resets {
		if !existing.ExpiresAt.After(row.CreatedAt) {
			delete(s.resets, key)
		}
	}
	s.resets[row.Token] = row
	return nil
}

func (s *Store) FindPasswordResetToken(ctx context.Context, token string, now time.Time) (auth.PasswordResetToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return auth.PasswordResetToken{}, err
	}
	row, ok := s.resets[token]
	if !ok || !row.ExpiresAt.After(now) {
		return auth.PasswordResetToken{}, auth.ErrNotFound
	}
	return row, nil
}

func (s *Store) FinishPasswordReset(ctx context.Context, token, newHash string, now time.Time, revoke bool) error {
	return s.finishPasswordReset(ctx, token, newHash, now, revoke, nil)
}

// FinishPasswordResetWithUser returns the owner selected by the winning reset.
func (s *Store) FinishPasswordResetWithUser(ctx context.Context, token, newHash string, now time.Time, revoke bool) (auth.User, error) {
	var owner auth.User
	err := s.finishPasswordReset(ctx, token, newHash, now, revoke, &owner)
	return owner, err
}

func (s *Store) finishPasswordReset(ctx context.Context, token, newHash string, now time.Time, revoke bool, owner *auth.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	row, ok := s.resets[token]
	if !ok || !row.ExpiresAt.After(now) {
		return auth.ErrNotFound
	}
	rec, ok := s.users[row.UserID]
	if !ok || !strings.EqualFold(rec.user.Email, row.Email) {
		return auth.ErrNotFound
	}
	if owner != nil {
		*owner = copyUser(rec.user)
	}
	rec.hash = newHash
	s.users[row.UserID] = rec
	delete(s.resets, token)
	if revoke {
		s.deleteSessions(row.UserID, "")
	}
	return nil
}

func (s *Store) VerifyAccountEmail(ctx context.Context, id, email string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	rec, ok := s.users[id]
	if !ok || strings.ToLower(rec.user.Email) != strings.ToLower(email) {
		return auth.ErrNotFound
	}
	rec.user.EmailVerified = true
	rec.user.UpdatedAt = now
	s.users[id] = rec
	return nil
}

func (s *Store) ListUserAccounts(ctx context.Context, userID string) ([]auth.LinkedAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rec := s.users[userID]
	if rec.hash == "" {
		return []auth.LinkedAccount{}, nil
	}
	return []auth.LinkedAccount{{ID: rec.accountID, UserID: userID, AccountID: userID, ProviderID: "credential", Scopes: []string{}, CreatedAt: rec.user.CreatedAt, UpdatedAt: rec.user.UpdatedAt}}, nil
}
func (s *Store) UnlinkAccount(ctx context.Context, userID, recordID string, allowLast bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	rec := s.users[userID]
	if rec.hash == "" {
		return auth.ErrNotFound
	}
	if !allowLast {
		return auth.ErrLastAccount
	}
	if rec.accountID != recordID {
		return auth.ErrNotFound
	}
	rec.hash = ""
	rec.accountID = ""
	s.users[userID] = rec
	return nil
}

// revokeUnprovenAccess drops the credentials created before mailbox ownership
// was proven. The caller holds the store lock and has inserted the new session.
func (s *Store) revokeUnprovenAccess(rec *credential, keepToken string) {
	s.deleteSessions(rec.user.ID, keepToken)
	rec.hash = ""
	rec.accountID = ""
	for token, row := range s.resets {
		if row.UserID == rec.user.ID {
			delete(s.resets, token)
		}
	}
	for token, row := range s.deletions {
		if row.UserID == rec.user.ID {
			delete(s.deletions, token)
		}
	}
}
