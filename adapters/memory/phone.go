package memory

import (
	"context"

	auth "github.com/Stonewrit/stonewrit-auth"
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
	if s.phoneOTPs == nil {
		s.phoneOTPs = map[phoneKey]auth.PhoneOTPRecord{}
	}
	s.phoneOTPs[phoneKey{r.PhoneNumber, r.Purpose}] = r
	return nil
}
func (s *Store) ConsumePhoneOTP(ctx context.Context, u auth.PhoneOTPUse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
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
	return err
}
