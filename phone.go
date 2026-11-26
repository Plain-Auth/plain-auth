package plainauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"
	"unicode/utf8"
)

// PhoneOTPPurpose keeps number verification and password recovery proofs separate.
type PhoneOTPPurpose string

const (
	PhoneVerify        PhoneOTPPurpose = "verification"
	PhonePasswordReset PhoneOTPPurpose = "password-reset"
)

type PhoneOTPMessage struct {
	PhoneNumber, Code string
	Purpose           PhoneOTPPurpose
}
type PhoneNumberOptions struct {
	SendPasswordResetOTP func(context.Context, PhoneOTPMessage) error
	VerifyOTP            func(context.Context, PhoneOTPMessage) (bool, error)
	OnVerification       func(context.Context, string, User) error
	SignUpOnVerification *PhoneSignUpOptions
	RequireVerification  bool
	SendOTP              func(context.Context, PhoneOTPMessage) error
	Validate             func(context.Context, string) (bool, error)
	OTPLength            int
	// AllowedAttempts defaults to three. An explicit zero rejects every proof.
	AllowedAttempts *int
	ExpiresIn       time.Duration
}

// PhoneOTPRecord is one generation of a proof. The value is for server-side delivery only.
type PhoneOTPRecord struct {
	BoundOwner            string
	OwnerBound            bool
	ID, PhoneNumber, Code string
	Purpose               PhoneOTPPurpose
	Attempts              int
	CreatedAt, ExpiresAt  time.Time
}
type PhoneOTPUse struct {
	// ProviderProof binds the use to one stored code: the one an external
	// verifier answered for, or the one verification hooks saw.
	ProviderProof    string
	ProviderAccepted bool
	// Decided, when set, receives what the call did to the code
	// ProviderProof names: Check's decision once its write committed, and
	// PhoneKeepProof otherwise.
	Decided           *PhoneOTPDecision
	PhoneNumber, Code string
	Purpose           PhoneOTPPurpose
	AllowedAttempts   int
	Now               time.Time
}

// PhoneOTPDecision is what a store commits to a phone or email code it
// judges: it keeps the code, counts a wrong guess, or removes the code.
type PhoneOTPDecision uint8

const (
	PhoneKeepProof PhoneOTPDecision = iota
	PhoneCountAttempt
	PhoneRemoveProof
)

// Check returns the storage mutation to commit together with any verification result.
func (u PhoneOTPUse) Check(r *PhoneOTPRecord) (PhoneOTPDecision, error) {
	switch {
	case r == nil:
		return PhoneKeepProof, &APIError{400, "OTP_NOT_FOUND", "OTP not found"}
	case u.ProviderProof != "" && r.ID != u.ProviderProof:
		return PhoneKeepProof, &APIError{400, "INVALID_OTP", "Invalid OTP"}
	case !r.ExpiresAt.After(u.Now):
		return PhoneRemoveProof, &APIError{400, "OTP_EXPIRED", "OTP expired"}
	case r.Attempts >= u.AllowedAttempts:
		return PhoneRemoveProof, &APIError{403, "TOO_MANY_ATTEMPTS", "Too many attempts"}
	case (u.ProviderProof != "" && !u.ProviderAccepted) || (u.ProviderProof == "" && subtle.ConstantTimeCompare([]byte(r.Code), []byte(u.Code)) != 1):
		return PhoneCountAttempt, &APIError{400, "INVALID_OTP", "Invalid OTP"}
	default:
		return PhoneRemoveProof, nil
	}
}

type PhoneNumberStore interface {
	CheckPhoneNumberSchema(context.Context) error
	SavePhoneOTP(context.Context, PhoneOTPRecord) error
	ConsumePhoneOTP(context.Context, PhoneOTPUse) error
}

// PhoneOTPReporter is a PhoneAccountStore whose ConsumePhoneOTP,
// ApplyPhoneOTP and ApplyPhoneRegistration report through PhoneOTPUse.Decided
// what they committed to the code. They report PhoneRemoveProof when they
// spend or remove it, including by a refusal after a spend, such as an
// owner mismatch, a held number or a missing session, and PhoneKeepProof
// for a code another use bound, a missing code, and every rolled-back
// write. New requires it for verification update and delete hooks with the
// phone number plugin.
type PhoneOTPReporter interface{ ReportsPhoneOTPDecisions() }

// NewPhoneNumber enables phone-number proofs with an application-provided SMS sender.
func NewPhoneNumber(o PhoneNumberOptions) (Plugin, error) {
	if o.SignUpOnVerification != nil {
		if o.SignUpOnVerification.GetTempEmail == nil {
			return Plugin{}, errors.New("phone-number signup requires a temporary email function")
		}
		copy := *o.SignUpOnVerification
		o.SignUpOnVerification = &copy
	}
	if o.OTPLength == 0 {
		o.OTPLength = 6
	}
	attempts := 3
	if o.AllowedAttempts != nil {
		attempts = *o.AllowedAttempts
	}
	o.AllowedAttempts = &attempts
	if o.ExpiresIn == 0 {
		o.ExpiresIn = 5 * time.Minute
	}
	if o.OTPLength < 1 || o.OTPLength > 128 || attempts < 0 || o.ExpiresIn <= 0 {
		return Plugin{}, errors.New("phone-number: invalid OTP length, lifetime or attempts")
	}
	p := Plugin{ID: "phone-number", StoredUserFields: map[string]UserField{"phoneNumber": {Type: FieldString}, "phoneNumberVerified": {Type: FieldBoolean}}, phoneNumber: &o, ValidateStore: func(store Store) error {
		s, ok := store.(PhoneAccountStore)
		if !ok {
			return errors.New("phone-number requires a PhoneAccountStore")
		}
		return s.CheckPhoneNumberSchema(context.Background())
	}}
	rule := &RateLimitRule{Max: 10, Window: time.Minute}
	p.Endpoints = []Endpoint{{Method: "POST", Path: "/phone-number/send-otp", RateLimit: rule, Handler: func(c EndpointContext) (any, error) {
		n, err := requiredString(c.Body, "phoneNumber")
		if err != nil {
			return nil, err
		}
		ctx := c.Request.Context()
		message, err := c.Auth.preparePhoneOTP(ctx, n)
		if err != nil {
			return nil, err
		}
		// A declined code answers as a sent one.
		if message != nil {
			send := func(ctx context.Context) error { return c.Auth.phoneNumber.SendOTP(ctx, *message) }
			// With BackgroundTasks the code is sent after the response; without
			// a runner a delivery failure fails the request, as before.
			if !c.Auth.handOff(ctx, "Could not deliver phone verification code", send) {
				if err := send(ctx); err != nil {
					return nil, err
				}
			}
		}
		return map[string]string{"message": "code sent"}, nil
	}}}
	p.Endpoints = append(p.Endpoints, phoneAccountEndpoints(rule)...)
	return p, nil
}

func (a *Auth) phoneStore() (PhoneNumberStore, error) {
	if a.phoneNumber == nil {
		return nil, errors.New("phone-number plugin is disabled")
	}
	store, ok := a.opts.Store.(PhoneNumberStore)
	if !ok {
		return nil, errors.New("phone-number: store is unavailable")
	}
	return store, nil
}

// checkPhone runs on every phone route, Go method and admin change, not only
// on sending a code and password sign-in. Deviation for safety: a number the
// application refuses is never verified, reset or attached, and the
// 255-character UTF-8 bound applies even without Validate.
func (a *Auth) checkPhone(ctx context.Context, number string) error {
	ok := utf8.ValidString(number) && utf8.RuneCountInString(number) <= 255
	if ok && a.phoneNumber.Validate != nil {
		valid, err := a.phoneNumber.Validate(ctx, number)
		if err != nil {
			return err
		}
		ok = valid
	}
	if !ok {
		return &APIError{400, "INVALID_PHONE_NUMBER", "Invalid phone number"}
	}
	return nil
}

// SendPhoneNumberOTP stores a fresh verification code and passes the raw value only to SendOTP.
func (a *Auth) SendPhoneNumberOTP(ctx context.Context, number string) error {
	message, err := a.preparePhoneOTP(ctx, number)
	if err != nil || message == nil {
		return err
	}
	return a.phoneNumber.SendOTP(ctx, *message)
}

// preparePhoneOTP stores a fresh verification code for number and returns
// its message, or nil when a verification create hook declined the code,
// which stores and sends nothing.
func (a *Auth) preparePhoneOTP(ctx context.Context, number string) (*PhoneOTPMessage, error) {
	store, err := a.phoneStore()
	if err != nil {
		return nil, err
	}
	if a.phoneNumber.SendOTP == nil {
		return nil, &APIError{501, "SEND_OTP_NOT_IMPLEMENTED", "sendOTP not implemented"}
	}
	if err = a.checkPhone(ctx, number); err != nil {
		return nil, err
	}
	code, err := randomDecimalCode(a.phoneNumber.OTPLength)
	if err != nil {
		return nil, err
	}
	now := a.now().UTC()
	r := PhoneOTPRecord{ID: randomID(), PhoneNumber: number, Code: code, Purpose: PhoneVerify, CreatedAt: now, ExpiresAt: now.Add(a.phoneNumber.ExpiresIn)}
	declined, err := a.createVerification(ctx, phoneOTPRecord(PhoneVerify, r.ID, r.ExpiresAt), func() error {
		return store.SavePhoneOTP(ctx, r)
	})
	if err != nil || declined {
		return nil, err
	}
	return &PhoneOTPMessage{PhoneNumber: number, Code: code, Purpose: PhoneVerify}, nil
}

// ConsumePhoneNumberOTP spends a verification code without changing the user or creating a session.
// This method has no HTTP endpoint.
func (a *Auth) ConsumePhoneNumberOTP(ctx context.Context, number, code string) error {
	store, err := a.phoneStore()
	if err != nil {
		return err
	}
	if err = a.checkPhone(ctx, number); err != nil {
		return err
	}
	use, g, err := a.phoneUse(ctx, number, code, PhoneVerify)
	if err != nil {
		return err
	}
	err = store.ConsumePhoneOTP(ctx, use)
	if hookErr := a.afterCodeGuess(ctx, g); hookErr != nil {
		return hookErr
	}
	return err
}
