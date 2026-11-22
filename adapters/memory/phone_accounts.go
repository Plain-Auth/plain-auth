package memory

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

var _ auth.PhoneAccountStore = (*Store)(nil)

func clonePhone(in *auth.PhoneNumberFields) *auth.PhoneNumberFields {
	out := &auth.PhoneNumberFields{}
	if in != nil {
		if in.PhoneNumber != nil {
			n := *in.PhoneNumber
			out.PhoneNumber = &n
		}
		if in.PhoneNumberVerified != nil {
			v := *in.PhoneNumberVerified
			out.PhoneNumberVerified = &v
		}
	}
	return out
}

func (s *Store) phoneHolder(number string) (string, credential) {
	for id, r := range s.users {
		if f := r.user.PhoneNumberFields; f != nil && f.PhoneNumber != nil && *f.PhoneNumber == number {
			return id, r
		}
	}
	return "", credential{}
}
func (s *Store) ReadPhoneOTP(ctx context.Context, n string, p auth.PhoneOTPPurpose) (*auth.PhoneOTPRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, ok := s.phoneOTPs[phoneKey{n, p}]
	if !ok {
		return nil, nil
	}
	return &r, nil
}
func (s *Store) ReadPhoneNumber(ctx context.Context, id string) (*auth.PhoneNumberFields, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, ok := s.users[id]
	if !ok {
		return nil, auth.ErrNotFound
	}
	return clonePhone(r.user.PhoneNumberFields), nil
}
func (s *Store) PhoneCredential(ctx context.Context, n string) (auth.User, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return auth.User{}, "", err
	}
	_, rec := s.phoneHolder(n)
	if rec.hash == "" {
		return copyUser(rec.user), "", auth.ErrNotFound
	}
	return copyUser(rec.user), rec.hash, nil
}
func (s *Store) SavePhoneReset(ctx context.Context, r auth.PhoneOTPRecord, verified bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	_, owner := s.phoneHolder(r.PhoneNumber)
	s.savePhoneLocked(r)
	return owner.user.ID != "" && (!verified || owner.user.PhoneNumberVerified != nil && *owner.user.PhoneNumberVerified), nil
}
func (s *Store) currentPhoneOwner(id, token string, now time.Time) bool {
	ss, exists := s.sessions[token]
	return exists && ss.UserID == id && ss.ImpersonatedBy == nil && ss.ExpiresAt.After(now)
}
func (s *Store) ClearPhoneProfile(ctx context.Context, id, token string, p auth.ProfileUpdate, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.currentPhoneOwner(id, token, now) {
		return auth.ErrNotFound
	}
	return s.applyProfile(id, s.users[id], p, now)
}
func (s *Store) ApplyPhoneOTP(ctx context.Context, act auth.PhoneAccountAction) (auth.PhoneAccountResult, error) {
	return s.ApplyPhoneRegistration(ctx, act, auth.RegistrationUserFields{})
}
func (s *Store) ApplyPhoneRegistration(ctx context.Context, act auth.PhoneAccountAction, registration auth.RegistrationUserFields) (auth.PhoneAccountResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out auth.PhoneAccountResult
	if err := ctx.Err(); err != nil {
		return out, err
	}
	proof, err := s.consumePhoneLocked(act.Use)
	if err != nil {
		return out, err
	}
	number := act.Use.PhoneNumber
	id, r := s.phoneHolder(number)
	if proof.OwnerBound && proof.BoundOwner != id {
		return out, &auth.APIError{Status: 400, Code: "INVALID_OTP", Message: "Invalid OTP"}
	}
	if act.SourceID != "" {
		if !s.currentPhoneOwner(act.SourceID, act.SourceToken, act.Use.Now) {
			return out, &auth.APIError{Status: 401, Code: "USER_NOT_FOUND", Message: "User not found"}
		}
		if id != "" {
			return out, auth.ErrPhoneNumberExists
		}
		id = act.SourceID
		r = s.users[id]
	}
	if act.Use.Purpose == auth.PhonePasswordReset {
		if id == "" {
			return out, &auth.APIError{Status: 400, Code: "UNEXPECTED_ERROR", Message: "Unexpected error"}
		}
		if act.RequireVerification && (r.user.PhoneNumberVerified == nil || !*r.user.PhoneNumberVerified) {
			return out, &auth.APIError{Status: 400, Code: "PHONE_NUMBER_PENDING_VERIFICATION", Message: "Phone number requires account ownership proof"}
		}
		r.hash = act.PasswordHash
		if r.accountID == "" {
			r.accountID = rand.Text()
		}
		s.users[id] = r
		if act.RevokeSessions {
			s.deleteSessions(id, "")
		}
		out.User = copyUser(r.user)
		return out, nil
	}
	if id == "" {
		columns, err := registration.Columns()
		if err != nil {
			return out, err
		}
		if act.Create == nil {
			return out, &auth.APIError{Status: 500, Code: "FAILED_TO_UPDATE_USER", Message: "Failed to update user"}
		}
		r.fields = columns
		if _, ok := s.emailToID[strings.ToLower(act.Create.Email)]; ok {
			s.phoneOTPs[phoneKey{number, act.Use.Purpose}] = proof
			return out, auth.ErrEmailTaken
		}
		if _, ok := s.users[act.Create.ID]; ok {
			s.phoneOTPs[phoneKey{number, act.Use.Purpose}] = proof
			return out, errors.New("memory: duplicate user ID")
		}
		r.user = copyUser(*act.Create)
		id = r.user.ID
	}
	if act.Session != nil {
		row := *act.Session
		row.UserID = id
		if err = s.insertSession(row); err != nil {
			s.phoneOTPs[phoneKey{number, act.Use.Purpose}] = proof
			return out, err
		}
	}
	verified := true
	r.user.PhoneNumberFields = &auth.PhoneNumberFields{PhoneNumber: &number, PhoneNumberVerified: &verified}
	r.user.UpdatedAt = act.Use.Now
	s.users[id] = r
	s.emailToID[strings.ToLower(r.user.Email)] = id
	out.User = copyUser(r.user)
	return out, nil
}
