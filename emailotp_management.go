package plainauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"
)

func (a *Auth) encodeEmailOTP(ctx context.Context, code string) (string, error) {
	o := a.emailOTP
	switch o.StoreOTP {
	case "encrypted":
		if o.Encrypt != nil {
			return o.Encrypt(ctx, code)
		}
		return a.sealRecord("email-otp", []byte(code))
	case "hashed":
		if o.Hash != nil {
			return o.Hash(ctx, code)
		}
		return hashEmailOTP(code), nil
	default:
		return code, nil
	}
}
func (a *Auth) recoverEmailOTP(ctx context.Context, stored string) (string, error) {
	o := a.emailOTP
	switch o.StoreOTP {
	case "hashed":
		return "", &APIError{400, "BAD_REQUEST", "OTP is hashed, cannot return the plain text OTP"}
	case "encrypted":
		if o.Decrypt != nil {
			return o.Decrypt(ctx, stored)
		}
		raw, err := a.openRecord("email-otp", stored)
		return string(raw), err
	default:
		return stored, nil
	}
}
func (a *Auth) matchEmailOTP(ctx context.Context, code string) func(string) (bool, error) {
	return func(stored string) (bool, error) {
		var err error
		want := code
		if a.emailOTP.StoreOTP == "hashed" {
			want, err = a.encodeEmailOTP(ctx, code)
		} else {
			stored, err = a.recoverEmailOTP(ctx, stored)
		}
		if err != nil {
			return false, err
		}
		return subtle.ConstantTimeCompare([]byte(stored), []byte(want)) == 1, nil
	}
}

// saveEmailOTP stores a code for req and returns it, or "" when the store
// withholds it. With verification create hooks the code gets its ID first
// and the hooks run around the store call; declined reports a code a hook
// declined, which stores and spends nothing. current is the guess at the
// current address's code that an email change request makes in the same
// store call.
func (a *Auth) saveEmailOTP(ctx context.Context, req EmailOTPRequest, allowNew, reuse bool, current *codeGuess) (raw string, declined bool, err error) {
	o := a.emailOTP
	prepare := func(prev *EmailOTPRecord) (string, string, int, error) {
		if reuse && prev != nil && o.ResendStrategy == "reuse" && o.StoreOTP != "hashed" && prev.Attempts < o.AllowedAttempts && prev.ExpiresAt.After(req.Now) {
			raw, err := a.recoverEmailOTP(ctx, prev.Stored)
			return raw, prev.Stored, prev.Attempts, err
		}
		raw, err := a.newEmailOTP(ctx, req)
		if err != nil {
			return "", "", 0, err
		}
		stored, err := a.encodeEmailOTP(ctx, raw)
		if err == nil && stored == "" {
			err = errors.New("email OTP storage transform returned an empty result")
		}
		return raw, stored, 0, err
	}
	expires := req.Now.Add(o.ExpiresIn)
	chain := a.dbHooks.verification.create
	var rec VerificationRecord
	if chain.set() {
		req.ProofID = randomID()
		rec = emailOTPRecord(req, req.ProofID, expires)
		// A declined code answers as a sent one: nothing is stored or mailed,
		// an earlier code stays, and the current address's code is not judged.
		if err := a.beforeVerification(ctx, chain, rec); errors.Is(err, ErrSkipWrite) {
			return "", true, nil
		} else if err != nil {
			return "", false, err
		}
		// Slow hooks cannot stretch the life of the session, or of the
		// current address's code, that the same store call judges.
		req.Now = a.now().UTC().Truncate(time.Millisecond)
	}
	raw, err = a.opts.Store.(EmailOTPStore).SaveEmailOTP(ctx, req, allowNew, expires, prepare)
	// The current address's code, judged by the same call, runs its after hooks first.
	if hookErr := a.afterCodeGuess(ctx, current); hookErr != nil {
		return "", false, hookErr
	}
	if err != nil || raw == "" || !chain.set() {
		return raw, false, err
	}
	// The code is stored; an after hook's error fails the send before any mail.
	if err := runAfter(ctx, a, chain, rec); err != nil {
		return "", false, err
	}
	return raw, false, nil
}

// beforeEmailGuess prepares a guess at the code req names. With verification
// update or delete hooks it reads the code without spending it and binds req
// to it, so the store judges that code and no newer one and reports what it
// did. A live code runs the delete before hooks, then req.Now is taken
// again, so slow hooks cannot stretch its life; an expired one runs none and
// the store removes it. With no code the guess is refused, as the store
// would refuse it.
func (a *Auth) beforeEmailGuess(ctx context.Context, req *EmailOTPRequest, code string) (*codeGuess, error) {
	if err := checkEmailOTPFormat(code); err != nil {
		return nil, err
	}
	g := &codeGuess{}
	if !a.watchesCodes() {
		return g, nil
	}
	// New requires the finder with these hooks.
	id, expiresAt, err := a.opts.Store.(EmailOTPFinder).FindEmailOTP(ctx, *req)
	if errors.Is(err, ErrNotFound) {
		return nil, invalidOTP()
	}
	if err != nil {
		return nil, err
	}
	req.ProofID, req.Decided = id, &g.decision
	if expiresAt.After(req.Now) {
		if err := a.beforeCodeGuess(ctx, g, emailOTPRecord(*req, id, expiresAt), invalidOTP()); err != nil {
			return nil, err
		}
		req.Now = a.now().UTC().Truncate(time.Millisecond)
	}
	return g, nil
}

func (a *Auth) consumeEmailOTP(ctx context.Context, req EmailOTPRequest, code string, act EmailOTPAction) (User, error) {
	return a.consumeEmailOTPWithFields(ctx, req, code, act, nil)
}

func (a *Auth) consumeEmailOTPWithFields(ctx context.Context, req EmailOTPRequest, code string, act EmailOTPAction, fields EmailOTPRegistrationFields) (User, error) {
	if err := checkEmailOTPFormat(code); err != nil {
		return User{}, err
	}
	act.EmailOTPRequest = req
	act.MaxAttempts = a.emailOTP.AllowedAttempts
	match := a.matchEmailOTP(ctx, code)
	if fields != nil {
		return a.opts.Store.(EmailOTPRegistrationStore).UseEmailOTPRegistration(ctx, act, match, fields)
	}
	return a.opts.Store.(EmailOTPStore).UseEmailOTP(ctx, act, match)
}

// CreateEmailOTP creates a fresh code without sending mail. Only trusted Go
// application code can call this method, including for an unregistered
// address. A verification create hook that declines the code makes it
// return a code that was never stored.
func (a *Auth) CreateEmailOTP(ctx context.Context, email string, purpose EmailOTPPurpose) (string, error) {
	req, err := a.emailOTPRequest(email, purpose)
	if err != nil {
		return "", err
	}
	raw, declined, err := a.saveEmailOTP(ctx, req, true, false, nil)
	if declined {
		// A declined code is returned unstored, as a declined one-time token
		// is: it proves nothing.
		return a.newEmailOTP(ctx, req)
	}
	return raw, err
}

// ReadEmailOTP returns a recoverable stored proof, or nil when absent or expired.
// This trusted Go operation has no HTTP route. Hashed proofs cannot be recovered.
func (a *Auth) ReadEmailOTP(ctx context.Context, email string, purpose EmailOTPPurpose) (*string, error) {
	req, err := a.emailOTPRequest(email, purpose)
	if err != nil {
		return nil, err
	}
	rec, err := a.opts.Store.(EmailOTPStore).ReadEmailOTP(ctx, req)
	if err != nil || rec == nil {
		return nil, err
	}
	code, err := a.recoverEmailOTP(ctx, rec.Stored)
	if err != nil {
		return nil, err
	}
	return &code, nil
}

// CompleteEmailVerificationOTP optionally issues a session according to the plugin's policy.
func (a *Auth) CompleteEmailVerificationOTP(ctx context.Context, email, code string, meta RequestMeta) (AuthResult, error) {
	return a.completeEmailVerificationOTP(ctx, email, code, meta, true, nil)
}

func (a *Auth) completeEmailVerificationOTP(ctx context.Context, email, code string, meta RequestMeta, allowSession bool, r *http.Request) (AuthResult, error) {
	req, err := a.emailOTPRequest(email, OTPVerifyEmail)
	if err != nil {
		return AuthResult{}, err
	}
	var act EmailOTPAction
	if allowSession && a.emailOTP.AutoSignInAfterVerification {
		act.Session, _ = a.newSession("", meta)
	}
	if a.hasVerificationObservers() {
		return a.observeEmailOTP(ctx, req, code, act.Session, r)
	}
	g, err := a.beforeEmailGuess(ctx, &req, code)
	if err != nil {
		return AuthResult{}, err
	}
	var u User
	consume := func(ctx context.Context) (err error) {
		g.decision = PhoneKeepProof
		u, err = a.consumeEmailOTP(ctx, req, code, act)
		return err
	}
	if act.Session.Token == "" {
		err = consume(ctx)
	} else {
		err = a.planSignIn(ctx, nil, consume)
	}
	// The code's after hooks run before the session's.
	if hookErr := a.afterCodeGuess(ctx, g); hookErr != nil {
		if err == nil && act.Session.Token != "" {
			hookErr = a.discardUnpublishedSession(ctx, act.Session.Token, hookErr)
		}
		return AuthResult{}, hookErr
	}
	if err == nil && act.Session.Token != "" {
		err = a.afterDecidedSignIn(ctx, u, false, act.Session.Token)
	}
	if err != nil {
		return AuthResult{}, err
	}
	return AuthResult{User: u, Token: act.Session.Token}, nil
}
func (a *Auth) emailChangeOTPRequest(ctx context.Context, h http.Header, address string) (EmailOTPRequest, error) {
	s, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return EmailOTPRequest{}, err
	}
	if !a.emailOTP.ChangeEmail.Enabled {
		return EmailOTPRequest{}, &APIError{Status: 400, Message: "Change email with OTP is disabled"}
	}
	req, err := a.emailOTPRequest(address, OTPChangeEmail)
	if err != nil {
		return req, err
	}
	if req.Email == s.User.Email {
		return req, &APIError{Status: 400, Message: "Email is the same"}
	}
	req.Source = &EmailOTPSource{UserID: s.User.ID, Email: s.User.Email, SessionToken: s.Session.Token}
	return req, nil
}

// RequestEmailChangeOTP delivers a proof to the new address, bound to the authenticated account.
func (a *Auth) RequestEmailChangeOTP(ctx context.Context, h http.Header, newEmail, currentOTP string) error {
	req, err := a.emailChangeOTPRequest(ctx, h, newEmail)
	if err != nil {
		return err
	}
	var current *codeGuess
	if a.emailOTP.ChangeEmail.VerifyCurrentEmail {
		if currentOTP == "" || len(currentOTP) > 256 {
			return &APIError{400, "BAD_REQUEST", "OTP is required to verify current email"}
		}
		// The store call that stores the new code judges the current
		// address's code, so that guess's before hooks run first.
		cur := EmailOTPRequest{Email: req.Source.Email, Purpose: OTPVerifyEmail, Now: req.Now}
		if current, err = a.beforeEmailGuess(ctx, &cur, currentOTP); err != nil {
			return err
		}
		req.CurrentProofID, req.CurrentDecided, req.Now = cur.ProofID, cur.Decided, cur.Now
		req.CurrentMatches = a.matchEmailOTP(ctx, currentOTP)
		req.MaxAttempts = a.emailOTP.AllowedAttempts
	}
	raw, _, err := a.saveEmailOTP(ctx, req, true, false, current)
	if err != nil || raw == "" {
		return err
	}
	return a.deliver(ctx, "Could not deliver email OTP", func(ctx context.Context) error {
		return a.emailOTP.Send(ctx, EmailOTPMessage{Email: req.Email, Type: OTPChangeEmail, OTP: raw})
	})
}

// ChangeEmailOTP consumes the new mailbox's proof for the authenticated account.
func (a *Auth) ChangeEmailOTP(ctx context.Context, h http.Header, newEmail, code string) error {
	return a.changeEmailOTP(ctx, h, newEmail, code, nil)
}

func (a *Auth) changeEmailOTP(ctx context.Context, h http.Header, newEmail, code string, r *http.Request) error {
	req, err := a.emailChangeOTPRequest(ctx, h, newEmail)
	if err != nil {
		return err
	}
	if a.hasVerificationObservers() {
		_, err = a.observeEmailOTP(ctx, req, code, StoredSession{}, r)
		return err
	}
	g, err := a.beforeEmailGuess(ctx, &req, code)
	if err != nil {
		return err
	}
	_, err = a.consumeEmailOTP(ctx, req, code, EmailOTPAction{})
	if hookErr := a.afterCodeGuess(ctx, g); hookErr != nil {
		return hookErr
	}
	return err
}
func (a *Auth) serveEmailOTPChange(c EndpointContext, path string) (any, error) {
	newEmail, err := requiredString(c.Body, "newEmail")
	if err != nil {
		return nil, err
	}
	success := map[string]bool{"success": true}
	if path == "/email-otp/request-email-change" {
		otp := ""
		if _, ok := c.Body["otp"]; ok {
			otp, err = requiredString(c.Body, "otp")
			if err != nil {
				return nil, err
			}
		}
		return success, a.RequestEmailChangeOTP(c.Request.Context(), c.Request.Header, newEmail, otp)
	}
	code, err := requiredString(c.Body, "otp")
	if err != nil {
		return nil, err
	}
	if err = a.changeEmailOTP(c.Request.Context(), c.Request.Header, newEmail, code, c.Request); err != nil {
		return nil, err
	}
	if token := a.cookieToken(c.Request.Header); token != "" {
		if a.hasVerificationObservers() {
			identity, err := a.GetSession(c.Request.Context(), c.Request.Header)
			if err != nil {
				return nil, err
			}
			if identity == nil || identity.Session.Token != token || identity.Session.RequireOwner() != nil || identity.User.Email != strings.ToLower(newEmail) {
				return success, nil
			}
		}
		if err := a.addSessionCookieHeaders(c.ResponseHeader, c.Request, token, !a.dontRemember(c.Request)); err != nil {
			return nil, err
		}
	}
	return success, nil
}
