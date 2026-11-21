package fineauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
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
func (a *Auth) saveEmailOTP(ctx context.Context, req EmailOTPRequest, allowNew, reuse bool) (string, error) {
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
	return a.opts.Store.(EmailOTPStore).SaveEmailOTP(ctx, req, allowNew, req.Now.Add(o.ExpiresIn), prepare)
}
func (a *Auth) consumeEmailOTP(ctx context.Context, req EmailOTPRequest, code string, act EmailOTPAction) (User, error) {
	if code == "" || len(code) > 256 {
		return User{}, &APIError{400, "INVALID_OTP", "Invalid OTP"}
	}
	act.EmailOTPRequest = req
	act.MaxAttempts = a.emailOTP.AllowedAttempts
	return a.opts.Store.(EmailOTPStore).UseEmailOTP(ctx, act, a.matchEmailOTP(ctx, code))
}

// CreateEmailOTP creates a fresh code without sending mail. Only trusted Go
// application code can call this method, including for an unregistered address.
func (a *Auth) CreateEmailOTP(ctx context.Context, email string, purpose EmailOTPPurpose) (string, error) {
	req, err := a.emailOTPRequest(email, purpose)
	if err != nil {
		return "", err
	}
	return a.saveEmailOTP(ctx, req, true, false)
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
	req, err := a.emailOTPRequest(email, OTPVerifyEmail)
	if err != nil {
		return AuthResult{}, err
	}
	var act EmailOTPAction
	if a.emailOTP.AutoSignInAfterVerification {
		act.Session, _ = a.newSession("", meta)
	}
	u, err := a.consumeEmailOTP(ctx, req, code, act)
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
	req, err := a.emailOTPRequest(address, OTPChangeEmail)
	if err != nil {
		return req, err
	}
	if !a.emailOTP.ChangeEmail.Enabled {
		return req, &APIError{400, "BAD_REQUEST", "Change email with OTP is disabled"}
	}
	if req.Email == s.User.Email {
		return req, &APIError{400, "BAD_REQUEST", "Email is the same"}
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
	if a.emailOTP.ChangeEmail.VerifyCurrentEmail {
		if currentOTP == "" || len(currentOTP) > 256 {
			return &APIError{400, "BAD_REQUEST", "OTP is required to verify current email"}
		}
		req.CurrentMatches = a.matchEmailOTP(ctx, currentOTP)
		req.MaxAttempts = a.emailOTP.AllowedAttempts
	}
	raw, err := a.saveEmailOTP(ctx, req, true, false)
	if err != nil || raw == "" {
		return err
	}
	return a.emailOTP.Send(ctx, EmailOTPMessage{Email: req.Email, Type: OTPChangeEmail, OTP: raw})
}

// ChangeEmailOTP consumes the new mailbox's proof for the authenticated account.
func (a *Auth) ChangeEmailOTP(ctx context.Context, h http.Header, newEmail, code string) error {
	req, err := a.emailChangeOTPRequest(ctx, h, newEmail)
	if err != nil {
		return err
	}
	_, err = a.consumeEmailOTP(ctx, req, code, EmailOTPAction{})
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
	if err = a.ChangeEmailOTP(c.Request.Context(), c.Request.Header, newEmail, code); err != nil {
		return nil, err
	}
	if token := a.cookieToken(c.Request.Header); token != "" {
		if err := a.addSessionCookieHeaders(c.ResponseHeader, c.Request, token, !a.dontRemember(c.Request)); err != nil {
			return nil, err
		}
	}
	return success, nil
}
