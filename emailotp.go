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
	// Decided and CurrentDecided, when set, receive what the call did to the
	// codes ProofID and CurrentProofID name: PhoneCountAttempt for a counted
	// wrong guess, PhoneRemoveProof for a code it spent or removed, and
	// PhoneKeepProof otherwise, including whenever its write did not commit.
	Decided, CurrentDecided *PhoneOTPDecision
	MaxAttempts             int
	// ProofID and CurrentProofID bind the call to stored codes, for
	// verification database hooks. SaveEmailOTP stores its new code under
	// ProofID. A call that judges a code judges only the one ProofID names,
	// and CurrentMatches only the current address's code CurrentProofID
	// names; it refuses any other with INVALID_OTP without writing to it.
	// Empty lets the store choose the ID and judge the newest code.
	ProofID, CurrentProofID string
	Email                   string
	Purpose                 EmailOTPPurpose
	Now                     time.Time
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

// EmailOTPFinder reads an email code without spending it, for verification
// update and delete hooks. FindEmailOTP returns the ID and expiry of the
// newest code stored for req's purpose and address, and for an email change
// req.Source's account, live or expired, without counting an attempt,
// taking a lock or joining a LoginPlan. With none it returns ErrNotFound.
//
// A store that implements it honours EmailOTPRequest's ProofID,
// CurrentProofID, Decided and CurrentDecided in its email code methods. A
// call that judges a code first refuses, untouched, any code but the bound
// one. It reports PhoneRemoveProof when it removes the code: a spend, an
// expired or exhausted code, or a refusal that spends it, such as an
// unknown account, closed sign-up, invalid registration fields, an address
// already in use or a changed owner. It reports PhoneCountAttempt when it
// counts a wrong guess, and PhoneKeepProof for a successful check, a
// refusal that writes nothing, and every call whose write rolls back. New
// requires it for verification update and delete hooks with the email OTP
// plugin.
type EmailOTPFinder interface {
	FindEmailOTP(ctx context.Context, req EmailOTPRequest) (id string, expiresAt time.Time, err error)
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

// invalidOTP refuses a guess at an email or phone code.
func invalidOTP() error { return &APIError{400, "INVALID_OTP", "Invalid OTP"} }

// checkEmailOTPFormat refuses a code no store holds, before any hook runs.
func checkEmailOTPFormat(code string) error {
	if code == "" || len(code) > 256 {
		return invalidOTP()
	}
	return nil
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
	return a.deliver(ctx, "Could not deliver email OTP", func(ctx context.Context) error {
		return a.emailOTP.Send(ctx, *message)
	})
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
	raw, _, err := a.saveEmailOTP(ctx, req, purpose == OTPSignIn && !a.emailOTP.DisableSignUp, true, nil)
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
	g, err := a.beforeEmailGuess(ctx, &req, code)
	if err != nil {
		return User{}, err
	}
	u, err := a.consumeEmailOTP(ctx, req, code, action)
	if hookErr := a.afterCodeGuess(ctx, g); hookErr != nil {
		return User{}, hookErr
	}
	return u, err
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
	g, err := a.beforeEmailGuess(ctx, &request, in.OTP)
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
		g.decision = PhoneKeepProof
		u, err = a.consumeEmailOTPWithFields(ctx, request, in.OTP, act, registration)
		return err
	})
	// The code's after hooks run before the user's and session's.
	if hookErr := a.afterCodeGuess(ctx, g); hookErr != nil {
		if err == nil {
			hookErr = a.discardUnpublishedSession(ctx, session.Token, hookErr)
		}
		return AuthResult{}, hookErr
	}
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
	req, err := a.emailOTPRequest(email, OTPResetPassword)
	if err != nil {
		return err
	}
	// A reset is one guess: its before hooks run once, ahead of the check
	// that spares a wrong guess the password hashing, and cover the spend.
	g, err := a.beforeEmailGuess(ctx, &req, code)
	if err != nil {
		return err
	}
	if _, err := a.consumeEmailOTP(ctx, req, code, EmailOTPAction{CheckOnly: true}); err != nil {
		if hookErr := a.afterCodeGuess(ctx, g); hookErr != nil {
			return hookErr
		}
		return err
	}
	hash, err := a.hashCredential(ctx, "/email-otp/reset-password", password)
	if err != nil {
		return err
	}
	req.Now = a.now().UTC().Truncate(time.Millisecond)
	act := EmailOTPAction{PasswordHash: hash, RevokeSessions: a.opts.RevokeSessionsOnPasswordReset}
	var owner User
	if a.opts.OnPasswordReset == nil {
		_, err = a.consumeEmailOTP(ctx, req, code, act)
	} else {
		act.EmailOTPRequest, act.MaxAttempts = req, a.emailOTP.AllowedAttempts
		owner, err = a.opts.Store.(EmailOTPResetHookStore).UseEmailOTPBeforeVerification(ctx, act, a.matchEmailOTP(ctx, code))
	}
	// The code's after hooks run before the reset callback; their error
	// fails the request after the password changed.
	if hookErr := a.afterCodeGuess(ctx, g); hookErr != nil {
		return hookErr
	}
	if err != nil || a.opts.OnPasswordReset == nil {
		return err
	}
	store := a.opts.Store.(EmailOTPResetHookStore)
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
