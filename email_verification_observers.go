package plainauth

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"time"
)

// EmailVerificationHook receives the account before or after the verified
// mailbox transition. The request is a metadata-only copy for HTTP calls.
type EmailVerificationHook func(context.Context, User, *http.Request) error

// VerifiedEmailChange is returned only for the transaction that changed the
// verified state. A zero User indicates an already-verified link replay.
type VerifiedEmailChange struct {
	User            User
	SessionEligible bool
}

// EmailVerificationObserverStore splits the verified mailbox commit from
// optional session issuance. Finish rechecks the committed user and current
// session restrictions after the host's callback, before granting a session.
type EmailVerificationObserverStore interface {
	InspectEmailVerification(context.Context, EmailVerificationAttempt) (User, error)
	CompleteObservedEmailVerification(context.Context, EmailVerificationAttempt) (VerifiedEmailChange, error)
	FinishObservedEmailSession(context.Context, EmailVerificationAttempt, User) (string, error)
	DiscardEmailVerificationReceipt(context.Context, EmailVerificationReceipt) error
}

func (a *Auth) hasVerificationObservers() bool {
	return a.opts.BeforeEmailVerification != nil || a.opts.AfterEmailVerification != nil
}

func runEmailVerificationHook(ctx context.Context, hook EmailVerificationHook, u User, r *http.Request) (err error) {
	if hook == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			err = errors.New("auth: email verification callback panicked")
		}
	}()
	if u.Image != nil {
		value := *u.Image
		u.Image = &value
	}
	metadata := accountObserverRequest(ctx, r)
	if metadata != nil && metadata.URL.Query().Has("token") {
		query := metadata.URL.Query()
		query.Del("token")
		metadata.URL.RawQuery = query.Encode()
		metadata.RequestURI = metadata.URL.RequestURI()
	}
	return hook(ctx, u, metadata)
}

func (a *Auth) observeAddressVerification(ctx context.Context, v EmailVerificationAttempt, r *http.Request) (string, error) {
	store := a.opts.Store.(EmailVerificationObserverStore)
	before, err := store.InspectEmailVerification(ctx, v)
	if err != nil {
		return "", err
	}
	if before.ID != v.OwnerID || strings.ToLower(before.Email) != strings.ToLower(v.Email) {
		return "", ErrNotFound
	}
	if before.EmailVerified {
		return "", nil
	}
	if err := runEmailVerificationHook(ctx, a.opts.BeforeEmailVerification, before, r); err != nil {
		return "", err
	}
	v.Now = a.now().UTC()
	change, err := store.CompleteObservedEmailVerification(ctx, v)
	if err != nil || change.User.ID == "" {
		return "", err
	}
	if err := runEmailVerificationHook(ctx, a.opts.AfterEmailVerification, change.User, r); err != nil {
		if change.SessionEligible {
			return "", a.discardVerificationReceipt(ctx, v.SessionReceipt(change.User), err)
		}
		return "", err
	}
	if !change.SessionEligible {
		return "", nil
	}
	v.Now = a.now().UTC()
	return store.FinishObservedEmailSession(ctx, v, change.User)
}

// EmailOTPVerificationObserverStore consumes an email verification or change
// proof before calling the host. Finish must reauthorize the exact original
// account, address and (for changes) direct session when committing the update.
type EmailOTPVerificationObserverStore interface {
	ConsumeObservedEmailOTP(context.Context, EmailOTPRequest, func(string) (bool, error)) (User, error)
	FinishObservedEmailOTP(context.Context, EmailOTPRequest, User) (User, error)
}

func (a *Auth) observeEmailOTP(ctx context.Context, req EmailOTPRequest, code string, session StoredSession, r *http.Request) (AuthResult, error) {
	// The guess's before hooks run first, so the observation uses the fresh Now.
	g, err := a.beforeEmailGuess(ctx, &req, code)
	if err != nil {
		return AuthResult{}, err
	}
	s := a.opts.Store.(EmailOTPVerificationObserverStore)
	req.MaxAttempts = a.emailOTP.AllowedAttempts
	observation := &EmailOTPObservation{ID: rand.Text(), ExpiresAt: req.Now.Add(a.emailOTP.ExpiresIn)}
	if session.Token != "" {
		if r == nil {
			observation.NewSession = &session
		} else if token, ok := a.verificationBrowserCredential(ctx, r); ok {
			observation.ExistingToken, observation.NewSession = token, &session
		}
	}
	req.Observation = observation
	before, err := s.ConsumeObservedEmailOTP(ctx, req, a.matchEmailOTP(ctx, code))
	// The code's after hooks run before BeforeEmailVerification; their error
	// discards the receipt the spend saved.
	if hookErr := a.afterCodeGuess(ctx, g); hookErr != nil {
		if err == nil {
			return AuthResult{}, a.discardVerificationReceipt(ctx, req.ObservationReceipt(before), hookErr)
		}
		return AuthResult{}, hookErr
	}
	if err != nil {
		return AuthResult{}, err
	}
	if err := runEmailVerificationHook(ctx, a.opts.BeforeEmailVerification, before, r); err != nil {
		return AuthResult{}, a.discardVerificationReceipt(ctx, req.ObservationReceipt(before), err)
	}
	// The consumed code has already established proof of this address. Recheck
	// its owner and the original change-email session after the host returns.
	req.Now = a.now().UTC()
	after, err := s.FinishObservedEmailOTP(ctx, req, before)
	if err != nil {
		return AuthResult{}, a.discardVerificationReceipt(ctx, req.ObservationReceipt(before), err)
	}
	v := req.ObservationAttempt(after)
	if err := runEmailVerificationHook(ctx, a.opts.AfterEmailVerification, after, r); err != nil {
		if v.NewSession != nil {
			return AuthResult{}, a.discardVerificationReceipt(ctx, v.SessionReceipt(after), err)
		}
		return AuthResult{}, err
	}
	result := AuthResult{User: after}
	if v.NewSession == nil {
		return result, nil
	}
	v.Now = a.now().UTC()
	result.Token, err = a.opts.Store.(EmailVerificationObserverStore).FinishObservedEmailSession(ctx, v, after)
	return result, err
}

func (a *Auth) discardVerificationReceipt(ctx context.Context, r EmailVerificationReceipt, cause error) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err := a.opts.Store.(EmailVerificationObserverStore).DiscardEmailVerificationReceipt(cleanup, r)
	return errors.Join(cause, err)
}
