package plainauth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

var ErrPhoneNumberExists = &APIError{400, "PHONE_NUMBER_EXIST", "Phone number already exists"}

// PhoneNumberFields is present when the phone plugin is enabled. A user may have no number.
type PhoneNumberFields struct {
	PhoneNumber         *string `json:"phoneNumber"`
	PhoneNumberVerified *bool   `json:"phoneNumberVerified"`
}
type PhoneSignUpOptions struct{ GetTempEmail, GetTempName func(string) string }
type PhoneVerificationInput struct {
	// AdditionalFields supplies writable user attributes only for first-time registration.
	AdditionalFields  map[string]any `json:"-"`
	PhoneNumber       string         `json:"phoneNumber"`
	Code              string         `json:"code"`
	UpdatePhoneNumber bool           `json:"updatePhoneNumber,omitempty"`
	DisableSession    bool           `json:"disableSession,omitempty"`
}
type PhoneVerificationResult struct {
	Factor *AuthResult `json:"-"`
	Status bool        `json:"status"`
	Token  *string     `json:"token"`
	User   User        `json:"user"`
}
type PhoneAccountAction struct {
	Use                   PhoneOTPUse
	SourceID, SourceToken string
	// Create is optional and is used only if no account exists for this number.
	Create                              *User
	Session                             *StoredSession
	PasswordHash                        string
	RevokeSessions, RequireVerification bool
}
type PhoneAccountResult struct {
	User         User
	NeedsFactor  bool
	ExpectedHash string
}

// PhoneLoginBinding identifies the number a password or pending factor login proved.
type PhoneLoginBinding struct {
	Number          string
	RequireVerified bool
}
type phoneLoginKey struct{}

// PhoneLoginFrom is used by stores to recheck a phone login under the session owner's lock.
func PhoneLoginFrom(ctx context.Context) (PhoneLoginBinding, bool) {
	binding, ok := ctx.Value(phoneLoginKey{}).(PhoneLoginBinding)
	return binding, ok
}
func (b PhoneLoginBinding) Matches(f *PhoneNumberFields) bool {
	return f != nil && f.PhoneNumber != nil && *f.PhoneNumber == b.Number && (!b.RequireVerified || f.PhoneNumberVerified != nil && *f.PhoneNumberVerified)
}
func (a *Auth) bindPhoneLogin(ctx context.Context, n string) context.Context {
	return context.WithValue(ctx, phoneLoginKey{}, PhoneLoginBinding{Number: n, RequireVerified: a.phoneNumber.RequireVerification})
}

type PhoneAccountStore interface {
	PhoneNumberStore
	ReadPhoneOTP(ctx context.Context, number string, purpose PhoneOTPPurpose) (*PhoneOTPRecord, error)
	ReadPhoneNumber(ctx context.Context, userID string) (*PhoneNumberFields, error)
	PhoneCredential(ctx context.Context, number string) (User, string, error)
	SavePhoneReset(ctx context.Context, r PhoneOTPRecord, requireVerified bool) (bool, error)
	// A successful password reset returns the account selected by the consumed proof.
	ApplyPhoneOTP(context.Context, PhoneAccountAction) (PhoneAccountResult, error)
	ClearPhoneProfile(ctx context.Context, userID, token string, p ProfileUpdate, now time.Time) error
}

func (a *Auth) phoneUse(ctx context.Context, number, code string, purpose PhoneOTPPurpose) (PhoneOTPUse, error) {
	u := PhoneOTPUse{PhoneNumber: number, Code: code, Purpose: purpose, AllowedAttempts: *a.phoneNumber.AllowedAttempts, Now: a.now().UTC()}
	if verify := a.phoneNumber.VerifyOTP; verify != nil {
		r, err := a.opts.Store.(PhoneAccountStore).ReadPhoneOTP(ctx, number, purpose)
		if err != nil {
			return u, err
		}
		// Expired/exhausted proofs are cleaned by the consuming transaction.
		if r == nil || !r.ExpiresAt.After(u.Now) || r.Attempts >= u.AllowedAttempts {
			if r == nil {
				return u, &APIError{400, "OTP_NOT_FOUND", "OTP not found"}
			}
			u.ProviderProof = r.ID
			return u, nil
		}
		u.ProviderProof = r.ID
		u.ProviderAccepted, err = verify(ctx, PhoneOTPMessage{PhoneNumber: number, Code: code, Purpose: purpose})
		if err != nil {
			return u, err
		}
		u.Now = a.now().UTC()
	}
	return u, nil
}
func (a *Auth) readPhone(ctx context.Context, u *User) error {
	if a.phoneNumber == nil || u.ID == "" {
		return nil
	}
	f, err := a.opts.Store.(PhoneAccountStore).ReadPhoneNumber(ctx, u.ID)
	if err != nil {
		return err
	}
	u.PhoneNumberFields = f
	return nil
}

// VerifyPhoneNumber consumes a verification proof and links, creates or signs in the account.
func (a *Auth) VerifyPhoneNumber(ctx context.Context, h http.Header, in PhoneVerificationInput, meta RequestMeta) (PhoneVerificationResult, error) {
	return a.verifyPhoneNumber(ctx, h, in, meta, nil)
}

func (a *Auth) verifyPhoneNumber(ctx context.Context, h http.Header, in PhoneVerificationInput, meta RequestMeta, requestedVerified any) (PhoneVerificationResult, error) {
	var out PhoneVerificationResult
	if _, err := a.phoneStore(); err != nil {
		return out, err
	}
	if err := a.checkPhone(ctx, in.PhoneNumber); err != nil {
		return out, err
	}
	use, err := a.phoneUse(ctx, in.PhoneNumber, in.Code, PhoneVerify)
	if err != nil {
		return out, err
	}
	var registration RegistrationUserFields
	act := PhoneAccountAction{Use: use}
	if in.UpdatePhoneNumber {
		current, err := a.requireOwnerSession(ctx, h)
		if err != nil {
			var denial *APIError
			if !errors.As(err, &denial) || (denial.Status != 401 && denial.Status != 403) {
				return out, err
			}
			// A link attempt shares verification's guess budget and spends a correct proof,
			// even when there is no eligible session. Account mutation stays in ApplyPhoneOTP.
			if proofErr := a.opts.Store.(PhoneAccountStore).ConsumePhoneOTP(ctx, use); proofErr != nil {
				return out, proofErr
			}
			if denial.Status == 401 {
				return out, &APIError{401, "USER_NOT_FOUND", "User not found"}
			}
			return out, err
		}
		act.SourceID, act.SourceToken = current.User.ID, current.Session.Token
	} else {
		if !a.opts.DisableSignUp && a.phoneNumber.SignUpOnVerification != nil {
			registration, err = a.preparePhoneRegistration(ctx, &act, in, requestedVerified)
			if err != nil {
				return out, err
			}
		}
		if !in.DisableSession {
			ss, _ := a.newSession("", meta)
			act.Session = &ss
		}
	}
	act.Use.Now = a.now().UTC()
	var result PhoneAccountResult
	store := func(ctx context.Context) (err error) {
		if ext, ok := a.opts.Store.(PhoneRegistrationStore); ok && (registration.err != nil || act.Create != nil && len(a.opts.UserAdditionalFields) > 0) {
			result, err = ext.ApplyPhoneRegistration(ctx, act, registration)
		} else if registration.err != nil {
			// A legacy adapter can enforce the built-in phone flag without custom columns.
			if err = a.opts.Store.(PhoneAccountStore).ConsumePhoneOTP(ctx, act.Use); err == nil {
				err = registration.err
			}
		} else {
			result, err = a.opts.Store.(PhoneAccountStore).ApplyPhoneOTP(ctx, act)
		}
		return err
	}
	if registration.err != nil {
		err = store(ctx)
	} else {
		err = a.planSignIn(ctx, store)
	}
	if errors.Is(err, ErrEmailTaken) {
		return out, &APIError{400, "USER_ALREADY_EXISTS", "User already exists"}
	}
	if err == nil {
		token := ""
		if act.Session != nil && !result.NeedsFactor && act.SourceToken == "" {
			token = act.Session.Token
		}
		err = a.afterDecidedSignIn(ctx, result.User, act.Create != nil && result.User.ID == act.Create.ID, token)
	}
	if err != nil {
		return out, err
	}
	user := result.User
	if err = a.readPublicUserFields(ctx, &user); err != nil {
		if act.Session != nil && !result.NeedsFactor {
			return out, a.discardUnpublishedSession(ctx, act.Session.Token, err)
		}
		return out, err
	}
	out.Status, out.User = true, user
	if act.SourceToken != "" {
		out.Token = &act.SourceToken
	} else if act.Session != nil {
		if result.NeedsFactor {
			if a.factorStore == nil {
				return out, &APIError{403, "TWO_FACTOR_REQUIRED", "Two-factor authentication is required"}
			}
			act.Session.UserID = user.ID
			factor, err := a.factorLogin(a.bindPhoneLogin(ctx, in.PhoneNumber), user, result.ExpectedHash, *act.Session, meta.TrustedDeviceCookie)
			if err != nil {
				return PhoneVerificationResult{}, err
			}
			out.Factor = &factor
			if factor.Token != "" {
				out.Token = &factor.Token
			}
		} else {
			out.Token = &act.Session.Token
		}
	}
	if fn := a.phoneNumber.OnVerification; fn != nil {
		if err = fn(ctx, in.PhoneNumber, user); err != nil {
			return PhoneVerificationResult{}, err
		}
	}
	return out, nil
}

// SignInPhoneNumber authenticates a stored credential and uses the same MFA and ban policy as email sign-in.
func (a *Auth) SignInPhoneNumber(ctx context.Context, number, password string, meta RequestMeta) (AuthResult, error) {
	if _, err := a.phoneStore(); err != nil {
		return AuthResult{}, err
	}
	if err := a.checkPhone(ctx, number); err != nil {
		return AuthResult{}, err
	}
	if err := a.validatePasswordLength(password, false); err != nil {
		return AuthResult{}, err
	}
	u, hash, err := a.opts.Store.(PhoneAccountStore).PhoneCredential(ctx, number)
	if (err == nil || errors.Is(err, ErrNotFound)) && u.ID != "" && a.phoneNumber.RequireVerification && (u.PhoneNumberVerified == nil || !*u.PhoneNumberVerified) {
		if a.phoneNumber.SendOTP != nil {
			if e := a.SendPhoneNumberOTP(ctx, number); e != nil {
				return AuthResult{}, e
			}
		}
		return AuthResult{}, &APIError{401, "PHONE_NUMBER_NOT_VERIFIED", "Phone number not verified"}
	}
	return a.completeCredentialSignIn(a.bindPhoneLogin(ctx, number), u, hash, err, password, meta, &APIError{401, "INVALID_PHONE_NUMBER_OR_PASSWORD", "Invalid phone number or password"})
}

// RequestPhonePasswordReset delivers a separate code only to eligible registered numbers.
func (a *Auth) RequestPhonePasswordReset(ctx context.Context, number string) error {
	if _, err := a.phoneStore(); err != nil {
		return err
	}
	if err := a.checkPhone(ctx, number); err != nil {
		return err
	}
	code, err := randomDecimalCode(a.phoneNumber.OTPLength)
	if err != nil {
		return err
	}
	now := a.now().UTC()
	r := PhoneOTPRecord{ID: randomID(), PhoneNumber: number, Code: code, Purpose: PhonePasswordReset, CreatedAt: now, ExpiresAt: now.Add(a.phoneNumber.ExpiresIn)}
	deliver, err := a.opts.Store.(PhoneAccountStore).SavePhoneReset(ctx, r, a.phoneNumber.RequireVerification)
	if err != nil {
		return err
	}
	if deliver && a.phoneNumber.SendPasswordResetOTP != nil {
		return a.phoneNumber.SendPasswordResetOTP(ctx, PhoneOTPMessage{PhoneNumber: number, Code: code, Purpose: PhonePasswordReset})
	}
	return nil
}

// ResetPhonePassword changes the bound account's credential atomically with proof consumption.
func (a *Auth) ResetPhonePassword(ctx context.Context, number, code, password string) error {
	return a.resetPhonePassword(ctx, number, code, password, nil)
}

func (a *Auth) resetPhonePassword(ctx context.Context, number, code, password string, request *http.Request) error {
	if _, err := a.phoneStore(); err != nil {
		return err
	}
	if err := a.checkPhone(ctx, number); err != nil {
		return err
	}
	if err := a.validatePasswordLength(password, true); err != nil {
		return err
	}
	use, err := a.phoneUse(ctx, number, code, PhonePasswordReset)
	if err != nil {
		return err
	}
	// Preflight avoids password hashing on an invalid guess; the transaction checks the proof again.
	store := a.opts.Store.(PhoneAccountStore)
	r, err := store.ReadPhoneOTP(ctx, number, PhonePasswordReset)
	if err != nil {
		return err
	}
	if _, err = use.Check(r); err != nil {
		// Recheck the exact generation inside the store before counting the attempt.
		if r == nil || use.ProviderProof != "" && use.ProviderProof != r.ID {
			return err
		}
		use.ProviderProof, use.ProviderAccepted = r.ID, false
		return store.ConsumePhoneOTP(ctx, use)
	}
	hash, err := a.hashCredential(ctx, "/phone-number/reset-password", password)
	if err != nil {
		return err
	}
	use.ProviderProof, use.ProviderAccepted = r.ID, true
	use.Now = a.now().UTC()
	out, err := store.ApplyPhoneOTP(ctx, PhoneAccountAction{Use: use, PasswordHash: hash, RevokeSessions: a.opts.RevokeSessionsOnPasswordReset, RequireVerification: a.phoneNumber.RequireVerification})
	if err != nil || a.opts.OnPasswordReset == nil {
		return err
	}
	return a.notifyPasswordReset(ctx, out.User, request)
}
