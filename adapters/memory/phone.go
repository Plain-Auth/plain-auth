package memory

import (
	"context"

	auth "github.com/Plain-Org/plain-auth"
)

type phoneKey struct {
	number  string
	purpose auth.PhoneOTPPurpose
}

func (*Store) CheckPhoneNumberSchema(context.Context) error { return nil }
func (s *Store) SavePhoneOTP(ctx context.Context, r auth.PhoneOTPRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	s.savePhoneLocked(r)
	return nil
}
func (s *Store) savePhoneLocked(r auth.PhoneOTPRecord) {
	for key, old := range s.phoneOTPs {
		if !s.keepExpired && !old.ExpiresAt.After(r.CreatedAt) {
			delete(s.phoneOTPs, key)
		}
	}
	_, owner := s.phoneHolder(r.PhoneNumber)
	r.OwnerBound = true
	r.BoundOwner = owner.user.ID
	if s.phoneOTPs == nil {
		s.phoneOTPs = map[phoneKey]auth.PhoneOTPRecord{}
	}
	s.phoneOTPs[phoneKey{r.PhoneNumber, r.Purpose}] = r
}

var _ auth.PhoneOTPReporter = (*Store)(nil)

// ReportsPhoneOTPDecisions marks the store as reporting, through
// PhoneOTPUse.Decided, what it commits to a phone code.
func (*Store) ReportsPhoneOTPDecisions() {}

func (s *Store) ConsumePhoneOTP(ctx context.Context, u auth.PhoneOTPUse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	_, decision, err := s.consumePhoneLocked(u)
	reportCode(u.Decided, decision)
	return err
}

// consumePhoneLocked judges u against the stored code and applies the decision.
func (s *Store) consumePhoneLocked(u auth.PhoneOTPUse) (auth.PhoneOTPRecord, auth.PhoneOTPDecision, error) {
	key := phoneKey{u.PhoneNumber, u.Purpose}
	r, ok := s.phoneOTPs[key]
	var record *auth.PhoneOTPRecord
	if ok {
		record = &r
	}
	decision, err := u.Check(record)
	switch decision {
	case auth.PhoneCountAttempt:
		r.Attempts++
		s.phoneOTPs[key] = r
	case auth.PhoneRemoveProof:
		delete(s.phoneOTPs, key)
	}
	return r, decision, err
}
