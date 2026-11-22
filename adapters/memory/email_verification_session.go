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
			continue
		}
		if previous.owner == v.OwnerID && (id == v.ProofID || !previous.spent.Before(v.IssuedAt)) {
			return "", auth.ErrNotFound
		}
	}
	u := rec.user
	allowed := v.NewSession != nil && v.MatchesProfileRevision(u.CreatedAt, u.UpdatedAt) && (u.TwoFactorEnabled == nil || !*u.TwoFactorEnabled) &&
		(u.AdminUserFields == nil || !u.Banned || u.BanExpires != nil && !u.BanExpires.After(v.Now))
	var token string
	if allowed && v.ExistingToken != "" {
		current, ok := s.sessions[v.ExistingToken]
		allowed = ok && current.ExpiresAt.After(v.Now) && current.Session.RequireOwner() == nil
		if allowed && current.UserID == v.OwnerID {
			token = current.Token
		}
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
	if s.spentEmailProofs == nil {
		s.spentEmailProofs = make(map[string]spentEmailProof)
	}
	s.spentEmailProofs[v.ProofID] = spentEmailProof{owner: v.OwnerID, spent: v.Now, expires: v.ExpiresAt}
	return token, nil
}
