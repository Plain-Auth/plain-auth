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
	// ProviderProof binds an external verifier's answer to the exact local issuance.
	ProviderProof     string
	ProviderAccepted  bool
	PhoneNumber, Code string
	Purpose           PhoneOTPPurpose
	AllowedAttempts   int
	Now               time.Time
}
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
	p := Plugin{ID: "phone-number", phoneNumber: &o, ValidateStore: func(store Store) error {
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
		if err = c.Auth.SendPhoneNumberOTP(c.Request.Context(), n); err != nil {
			return nil, err
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
	store, err := a.phoneStore()
	if err != nil {
		return err
	}
	if a.phoneNumber.SendOTP == nil {
		return &APIError{501, "SEND_OTP_NOT_IMPLEMENTED", "sendOTP not implemented"}
	}
	if err = a.checkPhone(ctx, number); err != nil {
		return err
	}
	code, err := randomDecimalCode(a.phoneNumber.OTPLength)
	if err != nil {
		return err
	}
	now := a.now().UTC()
	r := PhoneOTPRecord{ID: randomID(), PhoneNumber: number, Code: code, Purpose: PhoneVerify, CreatedAt: now, ExpiresAt: now.Add(a.phoneNumber.ExpiresIn)}
	if err = store.SavePhoneOTP(ctx, r); err != nil {
		return err
	}
	return a.phoneNumber.SendOTP(ctx, PhoneOTPMessage{PhoneNumber: number, Code: code, Purpose: PhoneVerify})
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
	use, err := a.phoneUse(ctx, number, code, PhoneVerify)
	if err != nil {
		return err
	}
	return store.ConsumePhoneOTP(ctx, use)
}
