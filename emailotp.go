package plainauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// EmailOTPPurpose binds a delivered proof to one operation.
type EmailOTPPurpose string

const (
	OTPVerifyEmail   EmailOTPPurpose = "email-verification"
	OTPSignIn        EmailOTPPurpose = "sign-in"
	OTPResetPassword EmailOTPPurpose = "forget-password"
	OTPChangeEmail   EmailOTPPurpose = "change-email"
)

// EmailOTPMessage carries the raw code exclusively for delivery to Email.
type EmailOTPMessage struct {
	Email, OTP string
	Type       EmailOTPPurpose
}

// EmailOTPTransform is an application-provided hash, encrypt or decrypt operation.
type EmailOTPTransform func(context.Context, string) (string, error)

// EmailOTPChangeOptions controls confirmation at the current and new mailboxes.
type EmailOTPChangeOptions struct {
	Enabled            bool
	VerifyCurrentEmail bool
}

// EmailOTPOptions configures code generation, delivery, storage and registration policy.
type EmailOTPOptions struct {
	// A custom hash is one-way. A custom cipher supplies both reversible transforms.
	Hash, Encrypt, Decrypt      EmailOTPTransform
	ChangeEmail                 EmailOTPChangeOptions
	AutoSignInAfterVerification bool
	Send                        func(context.Context, EmailOTPMessage) error
	GenerateOTP                 func(context.Context, string, EmailOTPPurpose) (string, error)
	Length, AllowedAttempts     int
	ExpiresIn                   time.Duration
	// StoreOTP accepts plain (default), encrypted, or hashed.
	StoreOTP string
	// ResendStrategy accepts rotate (default) or reuse.
	ResendStrategy                   string
	DisableSignUp                    bool
	SendVerificationOnSignUp         bool
	OverrideDefaultEmailVerification bool
	RateLimit                        *RateLimitRule
}

type EmailOTPSource struct {
	UserID, Email, SessionToken string
}
type EmailOTPRequest struct {
	// Observation is present only while completing host-observed verification.
	Observation *EmailOTPObservation
	// Source binds email changes to the authenticated original account.
	Source         *EmailOTPSource
	CurrentMatches func(string) (bool, error)
	MaxAttempts    int
	Email          string
	Purpose        EmailOTPPurpose
	Now            time.Time
}
type EmailOTPRecord struct {
	Stored    string
	Attempts  int
	ExpiresAt time.Time
}
type EmailOTPAction struct {
	EmailOTPRequest
	// CheckOnly preserves a valid proof. Every other successful action consumes it.
	CheckOnly, AllowSignUp, RevokeSessions bool
	MaxAttempts                            int
	NewUser                                User
	Session                                StoredSession
	PasswordHash                           string
}
type EmailOTPStore interface {
	ReadEmailOTP(context.Context, EmailOTPRequest) (*EmailOTPRecord, error)
	// SaveEmailOTP serializes replacement or reuse for the same purpose and mailbox.
	// Returns an empty code when delivery would disclose account existence.
	SaveEmailOTP(ctx context.Context, req EmailOTPRequest, allowNew bool, expires time.Time, prepare func(previous *EmailOTPRecord) (raw, stored string, attempts int, err error)) (string, error)
	// UseEmailOTP commits the retry count or consumes the proof atomically with the requested mutation.
	UseEmailOTP(ctx context.Context, action EmailOTPAction, matches func(stored string) (bool, error)) (User, error)
}

// EmailOTPRegistrationFields prepares configured attributes for a new mailbox
// owner. It has no storage or delivery side effects and can be retried.
type EmailOTPRegistrationFields func() (UserFieldValues, error)

// EmailOTPRegistrationStore consumes a valid proof before applying the new-account
// field policy. A rejected field set spends the proof without creating a user or
// session. Existing mailbox owners sign in without evaluating registration data.
type EmailOTPRegistrationStore interface {
	UseEmailOTPRegistration(context.Context, EmailOTPAction, func(string) (bool, error), EmailOTPRegistrationFields) (User, error)
}

// EmailOTPResetHookStore separates a successful credential reset from promotion
// of the same mailbox. The latter runs only after the host callback succeeds.
type EmailOTPResetHookStore interface {
	UseEmailOTPBeforeVerification(context.Context, EmailOTPAction, func(string) (bool, error)) (User, error)
	VerifyAccountEmail(ctx context.Context, userID, email string, now time.Time) error
}

// NewEmailOTP enables single-use mailbox codes for registration, sign-in, verification and password recovery.
func NewEmailOTP(o EmailOTPOptions) (Plugin, error) {
	if o.Send == nil {
		return Plugin{}, errors.New("email OTP requires a mail sender")
	}
	if o.Length == 0 {
		o.Length = 6
	}
	if o.AllowedAttempts == 0 {
		o.AllowedAttempts = 3
	}
	if o.ExpiresIn == 0 {
		o.ExpiresIn = 5 * time.Minute
	}
	if o.Hash != nil {
		if o.StoreOTP != "" || o.Encrypt != nil || o.Decrypt != nil {
			return Plugin{}, errors.New("choose a single email OTP storage strategy")
		}
		o.StoreOTP = "hashed"
	} else if o.Encrypt != nil || o.Decrypt != nil {
		if o.StoreOTP != "" || o.Encrypt == nil || o.Decrypt == nil {
			return Plugin{}, errors.New("email OTP requires a paired encrypt and decrypt transform")
		}
		o.StoreOTP = "encrypted"
	} else if o.StoreOTP == "" {
		o.StoreOTP = "plain"
	}
	if o.ResendStrategy == "" {
		o.ResendStrategy = "rotate"
	}
	if o.Length < 1 || o.Length > 128 || o.AllowedAttempts < 1 || o.ExpiresIn <= 0 ||
		(o.StoreOTP != "plain" && o.StoreOTP != "encrypted" && o.StoreOTP != "hashed") ||
		(o.ResendStrategy != "rotate" && o.ResendStrategy != "reuse") {
		return Plugin{}, errors.New("invalid email OTP configuration")
	}
	rule := RateLimitRule{Max: 3, Window: time.Minute}
	if o.RateLimit != nil {
		rule = *o.RateLimit
	}
	if rule.Max < 1 || rule.Window <= 0 {
		return Plugin{}, errors.New("invalid email OTP rate limit")
	}
	p := Plugin{ID: "email-otp", emailOTP: &o, ValidateStore: func(s Store) error {
		if _, ok := s.(EmailOTPStore); !ok {
			return errors.New("email OTP requires an EmailOTPStore")
		}
		return nil
	}}
	for _, path := range []string{"/email-otp/send-verification-otp", "/email-otp/check-verification-otp", "/email-otp/verify-email", "/sign-in/email-otp", "/email-otp/request-password-reset", "/forget-password/email-otp", "/email-otp/reset-password", "/email-otp/request-email-change", "/email-otp/change-email"} {
		p.Endpoints = append(p.Endpoints, Endpoint{Method: http.MethodPost, Path: path, RateLimit: &rule, Handler: func(c EndpointContext) (any, error) { return c.Auth.serveEmailOTP(c, path) }})
	}
	return p, nil
}

func (a *Auth) emailOTPRequest(email string, purpose EmailOTPPurpose) (EmailOTPRequest, error) {
	if a.emailOTP == nil {
		return EmailOTPRequest{}, &APIError{404, "NOT_FOUND", "Email OTP is disabled"}
	}
	if len(email) > 254 || !emailPattern.MatchString(email) || strings.Contains(email, "..") {
		return EmailOTPRequest{}, &APIError{400, "INVALID_EMAIL", "Invalid email"}
	}
	switch purpose {
	case OTPSignIn, OTPVerifyEmail, OTPResetPassword, OTPChangeEmail:
	default:
		return EmailOTPRequest{}, validationError("Unsupported email OTP purpose")
	}
	return EmailOTPRequest{Email: strings.ToLower(email), Purpose: purpose, Now: a.now().UTC().Truncate(time.Millisecond)}, nil
}

func hashEmailOTP(code string) string {
	sum := sha256.Sum256([]byte(code))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func (a *Auth) newEmailOTP(ctx context.Context, req EmailOTPRequest) (string, error) {
	o := a.emailOTP
	if o.GenerateOTP != nil {
		code, err := o.GenerateOTP(ctx, req.Email, req.Purpose)
		if err != nil {
			return "", err
		}
		if code != "" {
			if len(code) > 256 {
				return "", errors.New("generated email OTP is too long")
			}
			return code, nil
		}
	}
	return randomDecimalCode(o.Length)
}
func randomDecimalCode(length int) (string, error) {
	maximum := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)
	n, err := rand.Int(rand.Reader, maximum)
	if err != nil {
		return "", err
	}
	code := n.String()
	return strings.Repeat("0", length-len(code)) + code, nil
}

// SendEmailOTP requests delivery to Email under the supplied purpose.
func (a *Auth) SendEmailOTP(ctx context.Context, email string, purpose EmailOTPPurpose) error {
	message, err := a.prepareEmailOTP(ctx, email, purpose)
	if err != nil || message == nil {
		return err
	}
	return a.emailOTP.Send(ctx, *message)
}

// prepareEmailOTP stores a new code for email and returns its message, or
// nil when no code is sent.
func (a *Auth) prepareEmailOTP(ctx context.Context, email string, purpose EmailOTPPurpose) (*EmailOTPMessage, error) {
	req, err := a.emailOTPRequest(email, purpose)
	if err != nil {
		return nil, err
	}
	if purpose == OTPChangeEmail {
		return nil, validationError("Use the email change request endpoint")
	}
	raw, err := a.saveEmailOTP(ctx, req, purpose == OTPSignIn && !a.emailOTP.DisableSignUp, true)
	if err != nil || raw == "" {
		return nil, err
	}
	return &EmailOTPMessage{Email: req.Email, Type: purpose, OTP: raw}, nil
}

func (a *Auth) useEmailOTP(ctx context.Context, email, code string, purpose EmailOTPPurpose, action EmailOTPAction) (User, error) {
	req, err := a.emailOTPRequest(email, purpose)
	if err != nil {
		return User{}, err
	}
	return a.consumeEmailOTP(ctx, req, code, action)

}

// CheckEmailOTP preserves a successful proof for a subsequent action.
func (a *Auth) CheckEmailOTP(ctx context.Context, email, code string, purpose EmailOTPPurpose) error {
	_, err := a.useEmailOTP(ctx, email, code, purpose, EmailOTPAction{CheckOnly: true})
	return err
}

// VerifyEmailOTP confirms an address without creating a session.
func (a *Auth) VerifyEmailOTP(ctx context.Context, email, code string) (User, error) {
	res, err := a.completeEmailVerificationOTP(ctx, email, code, RequestMeta{}, false, nil)
	return res.User, err
}

type EmailOTPSignInInput struct {
	AdditionalFields map[string]any `json:"-"`
	Email            string         `json:"email"`
	OTP              string         `json:"otp"`
	Name             string         `json:"name,omitempty"`
	Image            *string        `json:"image,omitempty"`
}

// SignInEmailOTP consumes a sign-in code and creates a session.
func (a *Auth) SignInEmailOTP(ctx context.Context, in EmailOTPSignInInput, meta RequestMeta) (AuthResult, error) {
	if a.emailOTP == nil {
		return AuthResult{}, &APIError{404, "NOT_FOUND", "Email OTP is disabled"}
	}
	if len([]rune(in.Name)) > 255 {
		return AuthResult{}, validationError("Invalid name")
	}
	session, _ := a.newSession("", meta)
	request, err := a.emailOTPRequest(in.Email, OTPSignIn)
	if err != nil {
		return AuthResult{}, err
	}
	act := EmailOTPAction{AllowSignUp: !a.emailOTP.DisableSignUp, Session: session, NewUser: User{ID: randomID(), Name: in.Name, Image: in.Image}}
	var registration EmailOTPRegistrationFields
	if act.AllowSignUp && len(a.opts.UserAdditionalFields) > 0 {
		registration = func() (UserFieldValues, error) {
			if _, collision := in.AdditionalFields["otp"]; collision {
				return UserFieldValues{}, validationError("Additional user field otp conflicts with the verification code")
			}
			return a.prepareUserFields(in.AdditionalFields, true, false)
		}
	}
	var u User
	var gate *signInGate
	if act.AllowSignUp {
		gate = &signInGate{method: "email-otp", fields: serverInput(a.opts.UserAdditionalFields, in.AdditionalFields)}
	}
	err = a.planSignIn(ctx, gate, func(ctx context.Context) (err error) {
		u, err = a.consumeEmailOTPWithFields(ctx, request, in.OTP, act, registration)
		return err
	})
	if err == nil {
		err = a.afterDecidedSignIn(ctx, u, u.ID == act.NewUser.ID, session.Token)
	}
	if err != nil {
		return AuthResult{}, err
	}
	if err := a.readPublicUserFields(ctx, &u); err != nil {
		return AuthResult{}, a.discardUnpublishedSession(ctx, session.Token, err)
	}
	return AuthResult{Token: session.Token, User: u}, nil
}

// ResetPasswordEmailOTP consumes the recovery proof under the configured password policy.
func (a *Auth) ResetPasswordEmailOTP(ctx context.Context, email, code, password string) error {
	return a.resetPasswordEmailOTP(ctx, email, code, password, nil)
}

func (a *Auth) resetPasswordEmailOTP(ctx context.Context, email, code, password string, request *http.Request) error {
	if err := a.validatePasswordLength(password, true); err != nil {
		return err
	}
	if err := a.CheckEmailOTP(ctx, email, code, OTPResetPassword); err != nil {
		return err
	}
	hash, err := a.hashCredential(ctx, "/email-otp/reset-password", password)
	if err != nil {
		return err
	}
	act := EmailOTPAction{PasswordHash: hash, RevokeSessions: a.opts.RevokeSessionsOnPasswordReset}
	if a.opts.OnPasswordReset == nil {
		_, err = a.useEmailOTP(ctx, email, code, OTPResetPassword, act)
		return err
	}
	store := a.opts.Store.(EmailOTPResetHookStore)
	act.EmailOTPRequest, err = a.emailOTPRequest(email, OTPResetPassword)
	if err != nil {
		return err
	}
	act.MaxAttempts = a.emailOTP.AllowedAttempts
	owner, err := store.UseEmailOTPBeforeVerification(ctx, act, a.matchEmailOTP(ctx, code))
	if err != nil {
		return err
	}
	if err := a.notifyPasswordReset(ctx, owner, request); err != nil {
		return err
	}
	if owner.EmailVerified {
		return nil
	}
	return store.VerifyAccountEmail(ctx, owner.ID, owner.Email, a.now().UTC())
}

func (a *Auth) serveEmailOTP(c EndpointContext, path string) (any, error) {
	ctx := c.Request.Context()
	if path == "/email-otp/request-email-change" || path == "/email-otp/change-email" {
		return a.serveEmailOTPChange(c, path)
	}
	email, err := requiredString(c.Body, "email")
	if err != nil {
		return nil, err
	}
	success := map[string]bool{"success": true}
	switch path {
	case "/email-otp/send-verification-otp", "/email-otp/check-verification-otp":
		purpose, err := requiredString(c.Body, "type")
		if err != nil {
			return nil, err
		}
		if path == "/email-otp/send-verification-otp" {
			return success, a.SendEmailOTP(ctx, email, EmailOTPPurpose(purpose))
		}
		code, err := requiredString(c.Body, "otp")
		if err != nil {
			return nil, err
		}
		return success, a.CheckEmailOTP(ctx, email, code, EmailOTPPurpose(purpose))
	case "/email-otp/request-password-reset", "/forget-password/email-otp":
		return success, a.SendEmailOTP(ctx, email, OTPResetPassword)
	}
	code, err := requiredString(c.Body, "otp")
	if err != nil {
		return nil, err
	}
	switch path {
	case "/email-otp/verify-email":
		res, err := a.completeEmailVerificationOTP(ctx, email, code, RequestMeta{IPAddress: a.clientIP(c.Request), UserAgent: c.Request.UserAgent()}, true, c.Request)
		if err != nil {
			return nil, err
		}
		var token *string
		if res.Token != "" {
			token = &res.Token
			if err := a.addSessionCookieHeaders(c.ResponseHeader, c.Request, res.Token, true); err != nil {
				return nil, a.discardUnpublishedSession(ctx, res.Token, err)
			}
		}
		return map[string]any{"status": true, "user": res.User, "token": token}, nil
	case "/email-otp/reset-password":
		pass, err := requiredString(c.Body, "password")
		if err != nil {
			return nil, err
		}
		return success, a.resetPasswordEmailOTP(ctx, email, code, pass, c.Request)
	case "/sign-in/email-otp":
		fields := a.userFieldInput(c.Body)
		// The proof belongs to the protocol, including when an application uses
		// "otp" as the name of an unrelated profile field.
		delete(fields, "otp")
		in := EmailOTPSignInInput{Email: email, OTP: code, AdditionalFields: fields}
		if _, ok := c.Body["name"]; ok {
			in.Name, err = requiredString(c.Body, "name")
			if err != nil {
				return nil, err
			}
		}
		if _, ok := c.Body["image"]; ok {
			image, err := requiredString(c.Body, "image")
			if err != nil {
				return nil, err
			}
			in.Image = &image
		}
		result, err := a.SignInEmailOTP(ctx, in, RequestMeta{IPAddress: a.clientIP(c.Request), UserAgent: c.Request.UserAgent()})
		if err != nil {
			return nil, err
		}
		if err := a.addSessionCookieHeaders(c.ResponseHeader, c.Request, result.Token, true); err != nil {
			return nil, a.discardUnpublishedSession(ctx, result.Token, err)
		}
		return result, nil
	default:
		return nil, &APIError{404, "NOT_FOUND", "Unknown email OTP route"}
	}
}
