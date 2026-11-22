package memory

import (
	"context"
	"strings"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
)

type spentEmailProof struct {
	owner          string
	spent, expires time.Time
}

func (s *Store) CompleteEmailVerification(ctx context.Context, v auth.EmailVerificationAttempt) (string, error) {
	return s.completeEmailVerification(ctx, v, nil)
}

func (s *Store) InspectEmailVerification(ctx context.Context, v auth.EmailVerificationAttempt) (auth.User, error) {
	started := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return auth.User{}, err
	}
	u, ok := s.users[v.OwnerID]
	if !ok || !v.ExpiresAt.After(v.Now.Add(time.Since(started))) || strings.ToLower(u.user.Email) != strings.ToLower(v.Email) {
		return auth.User{}, auth.ErrNotFound
	}
	if !u.user.EmailVerified && s.emailProofSpent(v) {
		return auth.User{}, auth.ErrNotFound
	}
	return copyUser(u.user), nil
}

func (s *Store) emailProofSpent(v auth.EmailVerificationAttempt) bool {
	for id, previous := range s.spentEmailProofs {
		if previous.expires.After(v.Now) && previous.owner == v.OwnerID && (id == v.ProofID || !previous.spent.Before(v.IssuedAt)) {
			return true
		}
	}
	return false
}

func (s *Store) CompleteObservedEmailVerification(ctx context.Context, v auth.EmailVerificationAttempt) (auth.VerifiedEmailChange, error) {
	var change auth.VerifiedEmailChange
	_, err := s.completeEmailVerification(ctx, v, &change)
	return change, err
}

func (s *Store) completeEmailVerification(ctx context.Context, v auth.EmailVerificationAttempt, change *auth.VerifiedEmailChange) (string, error) {
	started := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	rec, found := s.users[v.OwnerID]
	if !found || v.Email == "" || v.ProofID == "" || !v.ExpiresAt.After(v.Now.Add(time.Since(started))) || strings.ToLower(rec.user.Email) != strings.ToLower(v.Email) ||
		v.NewSession != nil && (v.NewSession.UserID != v.OwnerID || v.NewSession.ID == "" || v.NewSession.Token == "" || v.NewSession.Session.RequireOwner() != nil || !v.NewSession.ExpiresAt.After(v.Now)) {
		return "", auth.ErrNotFound
	}
	if rec.user.EmailVerified {
		return "", nil
	}
	for id, previous := range s.spentEmailProofs {
		if !previous.expires.After(v.Now) {
			delete(s.spentEmailProofs, id)
		}
	}
	if s.emailProofSpent(v) {
		return "", auth.ErrNotFound
	}
	u := rec.user
	var token string
	allowed := false
	if v.NewSession != nil && v.MatchesProfileRevision(u.CreatedAt, u.UpdatedAt) {
		token, allowed = s.verificationSessionPolicy(v, u)
	}
	if change != nil {
		change.SessionEligible = allowed
		allowed, token = false, ""
	}
	if allowed && token == "" {
		if err := s.insertSession(*v.NewSession); err != nil {
			return "", err
		}
		token = v.NewSession.Token
	}
	u.EmailVerified, u.UpdatedAt = true, v.Now
	rec.user = u
	s.users[v.OwnerID] = rec
	if change != nil {
		change.User = copyUser(u)
		if change.SessionEligible {
			s.saveVerificationReceipt(v.SessionReceipt(u), v.Now)
		}
	}
	if s.spentEmailProofs == nil {
		s.spentEmailProofs = make(map[string]spentEmailProof)
	}
	s.spentEmailProofs[v.ProofID] = spentEmailProof{owner: v.OwnerID, spent: v.Now, expires: v.ExpiresAt}
	return token, nil
}

func (s *Store) FinishObservedEmailSession(ctx context.Context, v auth.EmailVerificationAttempt, owner auth.User) (string, error) {
	started := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if v.NewSession == nil || v.OwnerID != owner.ID || v.NewSession.UserID != owner.ID || v.NewSession.ID == "" || v.NewSession.Token == "" || v.NewSession.Session.RequireOwner() != nil || !v.NewSession.ExpiresAt.After(v.Now) || !v.ExpiresAt.After(v.Now.Add(time.Since(started))) || !owner.EmailVerified {
		return "", nil
	}
	u := s.users[owner.ID].user
	if u.ID != owner.ID || u.Email != owner.Email || !u.EmailVerified || !u.UpdatedAt.Equal(owner.UpdatedAt) {
		return "", nil
	}
	if !s.takeVerificationReceipt(v.SessionReceipt(owner), v.Now.Add(time.Since(started))) {
		return "", nil
	}
	token, allowed := s.verificationSessionPolicy(v, u)
	if !allowed || token != "" {
		return token, nil
	}
	if err := s.insertSession(*v.NewSession); err != nil {
		return "", err
	}
	return v.NewSession.Token, nil
}

func (s *Store) verificationSessionPolicy(v auth.EmailVerificationAttempt, u auth.User) (string, bool) {
	if u.TwoFactorEnabled != nil && *u.TwoFactorEnabled || u.AdminUserFields != nil && u.Banned && (u.BanExpires == nil || u.BanExpires.After(v.Now)) {
		return "", false
	}
	if v.ExistingToken != "" {
		old, ok := s.sessions[v.ExistingToken]
		if !ok || !old.ExpiresAt.After(v.Now) || old.Session.RequireOwner() != nil {
			return "", false
		}
		if old.UserID == u.ID && !v.AlwaysCreateSession {
			return old.Token, true
		}
	}
	return "", true
}

func (s *Store) saveVerificationReceipt(receipt auth.EmailVerificationReceipt, now time.Time) {
	if s.verificationReceipts == nil {
		s.verificationReceipts = make(map[string]auth.EmailVerificationReceipt)
	}
	for key, r := range s.verificationReceipts {
		if !r.ExpiresAt.After(now) {
			delete(s.verificationReceipts, key)
		}
	}
	s.verificationReceipts[receipt.Value] = receipt
}

func (s *Store) takeVerificationReceipt(receipt auth.EmailVerificationReceipt, now time.Time) bool {
	stored, ok := s.verificationReceipts[receipt.Value]
	if !ok || stored.Identifier != receipt.Identifier || !stored.ExpiresAt.After(now) {
		return false
	}
	delete(s.verificationReceipts, receipt.Value)
	return true
}

func (s *Store) DiscardEmailVerificationReceipt(ctx context.Context, r auth.EmailVerificationReceipt) error {
	if !r.ValidScope() {
		return auth.ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if stored, ok := s.verificationReceipts[r.Value]; ok && stored.Identifier == r.Identifier {
		delete(s.verificationReceipts, r.Value)
	}
	return nil
}
