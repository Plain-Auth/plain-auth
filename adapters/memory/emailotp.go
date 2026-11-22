package memory

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

var _ auth.EmailOTPStore = (*Store)(nil)

type mailKey struct {
	purpose      auth.EmailOTPPurpose
	email, scope string
}
type mailProof struct {
	auth.EmailOTPRecord
	owner      string
	generation uint64
}

func keyForMail(req auth.EmailOTPRequest) mailKey {
	key := mailKey{purpose: req.Purpose, email: req.Email}
	if req.Source != nil {
		key.scope = req.Source.UserID
	}
	return key
}
func invalidMailOTP() error {
	return &auth.APIError{Status: 400, Code: "INVALID_OTP", Message: "Invalid OTP"}
}

func (s *Store) ReadEmailOTP(ctx context.Context, req auth.EmailOTPRequest) (*auth.EmailOTPRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p := s.emailOTPs[keyForMail(req)]
	if !p.ExpiresAt.After(req.Now) {
		return nil, nil
	}
	return &p.EmailOTPRecord, nil
}

type mailSnapshot struct {
	primary, current mailProof
	owner            string
	suppress         bool
}

func (s *Store) snapshotMail(req auth.EmailOTPRequest, allowNew bool) (mailSnapshot, error) {
	state := mailSnapshot{primary: s.emailOTPs[keyForMail(req)]}
	owner := s.emailToID[req.Email]
	if req.Source == nil {
		state.owner = owner
		state.suppress = owner == "" && !allowNew
		return state, nil
	}
	src := req.Source
	row := s.sessions[src.SessionToken]
	if row.UserID != src.UserID || !row.ExpiresAt.After(req.Now) {
		return state, &auth.APIError{Status: 401, Code: "UNAUTHORIZED", Message: "Invalid session"}
	}
	if s.users[src.UserID].user.Email != src.Email {
		return state, invalidMailOTP()
	}
	state.owner = src.UserID + ":" + src.Email
	state.suppress = owner != ""
	state.current = s.emailOTPs[mailKey{purpose: auth.OTPVerifyEmail, email: src.Email}]
	return state, nil
}

// Return the new attempt count on a mismatch or -1 to discard a spent proof.
func evaluateMailProof(p mailProof, now time.Time, max int, matches func(string) (bool, error)) (int, error) {
	if p.generation == 0 {
		return -1, invalidMailOTP()
	}
	if !p.ExpiresAt.After(now) {
		return -1, &auth.APIError{Status: 400, Code: "OTP_EXPIRED", Message: "OTP expired"}
	}
	if p.Attempts >= max {
		return -1, &auth.APIError{Status: 403, Code: "TOO_MANY_ATTEMPTS", Message: "Too many attempts"}
	}
	valid, err := matches(p.Stored)
	if err != nil {
		return p.Attempts, err
	}
	if !valid {
		return p.Attempts + 1, invalidMailOTP()
	}
	return p.Attempts, nil
}
func (s *Store) applyMailAttempts(key mailKey, p mailProof, attempts int) {
	if attempts < 0 {
		delete(s.emailOTPs, key)
		return
	}
	if attempts != p.Attempts {
		p.Attempts = attempts
		s.emailOTPs[key] = p
	}
}

func (s *Store) SaveEmailOTP(ctx context.Context, req auth.EmailOTPRequest, allowNew bool, expires time.Time, prepare func(*auth.EmailOTPRecord) (string, string, int, error)) (string, error) {
	if req.CurrentMatches != nil && req.Source == nil {
		return "", errors.New("memory: current mailbox proof needs a source account")
	}
	key := keyForMail(req)
	// Application-provided transforms run outside the mutex. Revalidate the
	// observed generation, owner and current-mailbox proof before committing.
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		s.mu.RLock()
		before, err := s.snapshotMail(req, allowNew)
		s.mu.RUnlock()
		if err != nil {
			return "", err
		}
		var currentKey mailKey
		var remaining int
		var denied error
		if req.CurrentMatches != nil {
			currentKey = mailKey{purpose: auth.OTPVerifyEmail, email: req.Source.Email}
			remaining, denied = evaluateMailProof(before.current, req.Now, req.MaxAttempts, req.CurrentMatches)
			if denied == nil && before.current.owner != "" && before.current.owner != req.Source.UserID {
				remaining, denied = -1, invalidMailOTP()
			}
		}
		var raw, stored string
		var attempts int
		if denied == nil && !before.suppress {
			var previous *auth.EmailOTPRecord
			if before.primary.generation != 0 && (before.primary.owner == "" || before.primary.owner == before.owner) {
				v := before.primary.EmailOTPRecord
				previous = &v
			}
			raw, stored, attempts, err = prepare(previous)
			if err != nil {
				return "", err
			}
		}
		s.mu.Lock()
		after, err := s.snapshotMail(req, allowNew)
		if err != nil {
			s.mu.Unlock()
			return "", err
		}
		if after != before {
			s.mu.Unlock()
			continue
		}
		if err = ctx.Err(); err != nil {
			s.mu.Unlock()
			return "", err
		}
		if denied != nil {
			s.applyMailAttempts(currentKey, before.current, remaining)
			s.mu.Unlock()
			return "", denied
		}
		if req.CurrentMatches != nil {
			delete(s.emailOTPs, currentKey)
		}
		if before.suppress {
			delete(s.emailOTPs, key)
			s.mu.Unlock()
			return "", nil
		}
		for old, p := range s.emailOTPs {
			if !p.ExpiresAt.After(req.Now) {
				delete(s.emailOTPs, old)
			}
		}
		s.nextProof++
		s.emailOTPs[key] = mailProof{EmailOTPRecord: auth.EmailOTPRecord{Stored: stored, Attempts: attempts, ExpiresAt: expires}, owner: before.owner, generation: s.nextProof}
		s.mu.Unlock()
		return raw, nil
	}
}

func (s *Store) UseEmailOTPRegistration(ctx context.Context, act auth.EmailOTPAction, matches func(string) (bool, error), fields auth.EmailOTPRegistrationFields) (auth.User, error) {
	if fields == nil || act.Purpose != auth.OTPSignIn || act.Source != nil || act.CheckOnly || act.Session.Token == "" || !act.AllowSignUp {
		return auth.User{}, errors.New("invalid email OTP registration action")
	}
	return s.useEmailOTP(ctx, act, matches, false, fields)
}

func (s *Store) UseEmailOTP(ctx context.Context, act auth.EmailOTPAction, matches func(string) (bool, error)) (auth.User, error) {
	return s.useEmailOTP(ctx, act, matches, false, nil)
}

// ConsumeObservedEmailOTP spends a valid code without verifying the address.
func (s *Store) ConsumeObservedEmailOTP(ctx context.Context, req auth.EmailOTPRequest, matches func(string) (bool, error)) (auth.User, error) {
	if req.Observation == nil || req.Observation.ID == "" || !req.Observation.ExpiresAt.After(req.Now) || !(req.Purpose == auth.OTPVerifyEmail && req.Source == nil || req.Purpose == auth.OTPChangeEmail && req.Source != nil) || req.CurrentMatches != nil {
		return auth.User{}, errors.New("invalid observed email OTP verification")
	}
	return s.useEmailOTP(ctx, auth.EmailOTPAction{EmailOTPRequest: req, MaxAttempts: req.MaxAttempts}, matches, true, nil)
}

// UseEmailOTPBeforeVerification commits one recovery proof, the new password,
// and requested session revocation, leaving mailbox verification to the caller.
func (s *Store) UseEmailOTPBeforeVerification(ctx context.Context, act auth.EmailOTPAction, matches func(string) (bool, error)) (auth.User, error) {
	if act.Purpose != auth.OTPResetPassword || act.PasswordHash == "" || act.Source != nil || act.CheckOnly || act.Session.Token != "" {
		return auth.User{}, errors.New("invalid email OTP password reset action")
	}
	return s.useEmailOTP(ctx, act, matches, true, nil)
}

func (s *Store) useEmailOTP(ctx context.Context, act auth.EmailOTPAction, matches func(string) (bool, error), deferVerification bool, fields auth.EmailOTPRegistrationFields) (auth.User, error) {
	key := keyForMail(act.EmailOTPRequest)
	for {
		if err := ctx.Err(); err != nil {
			return auth.User{}, err
		}
		s.mu.RLock()
		p := s.emailOTPs[key]
		s.mu.RUnlock()
		attempts, denied := evaluateMailProof(p, act.Now, act.MaxAttempts, matches)
		s.mu.Lock()
		if s.emailOTPs[key] != p {
			s.mu.Unlock()
			continue
		}
		if err := ctx.Err(); err != nil {
			s.mu.Unlock()
			return auth.User{}, err
		}
		if denied != nil {
			s.applyMailAttempts(key, p, attempts)
			s.mu.Unlock()
			return auth.User{}, denied
		}
		u, err := s.finishMailProof(key, p, act, deferVerification, fields)
		s.mu.Unlock()
		return u, err
	}
}
func (s *Store) finishMailProof(key mailKey, p mailProof, act auth.EmailOTPAction, deferVerification bool, fields auth.EmailOTPRegistrationFields) (auth.User, error) {
	state, err := s.snapshotMail(act.EmailOTPRequest, true)
	if err != nil {
		return auth.User{}, err
	}
	if p.owner != "" && p.owner != state.owner {
		delete(s.emailOTPs, key)
		return auth.User{}, invalidMailOTP()
	}
	if act.Source != nil {
		delete(s.emailOTPs, key)
		if state.suppress {
			return auth.User{}, &auth.APIError{Status: 400, Code: "BAD_REQUEST", Message: "Email already in use"}
		}
		id := act.Source.UserID
		rec := s.users[id]
		if deferVerification {
			s.saveVerificationReceipt(act.ObservationReceipt(rec.user), act.Now)
			return copyUser(rec.user), nil
		}
		delete(s.emailToID, rec.user.Email)
		rec.user.Email, rec.user.EmailVerified, rec.user.UpdatedAt = act.Email, true, act.Now
		s.emailToID[act.Email] = id
		s.users[id] = rec
		return copyUser(rec.user), nil
	}
	rec, exists := s.users[state.owner]
	if !exists && (act.CheckOnly || act.Purpose != auth.OTPSignIn) {
		if !act.CheckOnly {
			delete(s.emailOTPs, key)
		}
		return auth.User{}, &auth.APIError{Status: 400, Code: "USER_NOT_FOUND", Message: "User not found"}
	}
	if act.CheckOnly {
		return copyUser(rec.user), nil
	}
	switch act.Purpose {
	case auth.OTPSignIn:
		if !exists {
			if !act.AllowSignUp {
				delete(s.emailOTPs, key)
				return auth.User{}, invalidMailOTP()
			}
			if _, taken := s.users[act.NewUser.ID]; taken {
				return auth.User{}, errors.New("memory: duplicate user ID")
			}
			if fields != nil {
				values, err := fields()
				if err != nil {
					delete(s.emailOTPs, key)
					return auth.User{}, err
				}
				rec.fields = values.Columns()
			}
			rec.user = copyUser(act.NewUser)
			rec.user.Email = act.Email
			rec.user.CreatedAt = act.Now
		}
	case auth.OTPResetPassword:
		if act.PasswordHash == "" {
			return auth.User{}, errors.New("memory: empty password reset hash")
		}
	case auth.OTPVerifyEmail:
		if deferVerification {
			s.saveVerificationReceipt(act.ObservationReceipt(rec.user), act.Now)
		}
	default:
		return auth.User{}, errors.New("memory: unsupported email OTP action")
	}
	if act.Session.Token != "" {
		row := act.Session
		row.UserID = rec.user.ID
		if err = s.insertSession(row); err != nil {
			return auth.User{}, err
		}
	}
	if act.Purpose == auth.OTPSignIn && exists && !rec.user.EmailVerified {
		s.revokeUnprovenAccess(&rec, act.Session.Token)
	}
	if act.Purpose == auth.OTPResetPassword {
		rec.hash = act.PasswordHash
		if rec.accountID == "" {
			rec.accountID = rand.Text()
		}
		if act.RevokeSessions {
			s.deleteSessions(rec.user.ID, "")
		}
	}
	if !deferVerification && !rec.user.EmailVerified {
		rec.user.EmailVerified = true
		rec.user.UpdatedAt = act.Now
	}
	s.emailToID[rec.user.Email] = rec.user.ID
	s.users[rec.user.ID] = rec
	delete(s.emailOTPs, key)
	return copyUser(rec.user), nil
}

func (s *Store) FinishObservedEmailOTP(ctx context.Context, req auth.EmailOTPRequest, before auth.User) (auth.User, error) {
	started := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return auth.User{}, err
	}
	rec := s.users[before.ID]
	if req.Observation == nil || req.Observation.ID == "" || before.ID == "" || rec.user.ID != before.ID || rec.user.Email != before.Email || !rec.user.UpdatedAt.Equal(before.UpdatedAt) {
		return auth.User{}, invalidMailOTP()
	}
	if req.Source == nil {
		if req.Purpose != auth.OTPVerifyEmail || req.Email != before.Email {
			return auth.User{}, invalidMailOTP()
		}
	} else {
		if req.Purpose != auth.OTPChangeEmail || req.Source.Email != before.Email || req.Source.UserID != before.ID || req.CurrentMatches != nil {
			return auth.User{}, invalidMailOTP()
		}
		state, err := s.snapshotMail(req, true)
		if err != nil {
			return auth.User{}, err
		}
		if state.suppress {
			return auth.User{}, &auth.APIError{Status: 400, Code: "BAD_REQUEST", Message: "Email already in use"}
		}
	}
	if !s.takeVerificationReceipt(req.ObservationReceipt(before), req.Now.Add(time.Since(started))) {
		return auth.User{}, invalidMailOTP()
	}
	if req.Source != nil {
		delete(s.emailToID, before.Email)
		s.emailToID[req.Email] = before.ID
	}
	rec.user.Email, rec.user.EmailVerified, rec.user.UpdatedAt = req.Email, true, req.Now
	s.users[before.ID] = rec
	if v := req.ObservationAttempt(rec.user); v.NewSession != nil {
		if _, allowed := s.verificationSessionPolicy(v, rec.user); allowed {
			s.saveVerificationReceipt(v.SessionReceipt(rec.user), req.Now)
		}
	}
	return copyUser(rec.user), nil
}
