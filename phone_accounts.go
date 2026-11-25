package plainauth

import (
	"context"
	"crypto/subtle"
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

// phoneUse prepares a guess at number's code. Without a VerifyOTP provider
// or verification update or delete hooks, the store compares the code.
// Otherwise the Auth reads the code first and binds the guess to it, so the
// store judges that code and no newer one: a live code runs the guess's
// delete before hooks, then the provider or a constant-time comparison
// judges it. A guess that cannot succeed is applied here and refused; what
// returns is a correct guess, with the record its hooks saw.
func (a *Auth) phoneUse(ctx context.Context, number, code string, purpose PhoneOTPPurpose) (PhoneOTPUse, *codeGuess, error) {
	u := PhoneOTPUse{PhoneNumber: number, Code: code, Purpose: purpose, AllowedAttempts: *a.phoneNumber.AllowedAttempts, Now: a.now().UTC()}
	g := &codeGuess{}
	verify, watched := a.phoneNumber.VerifyOTP, a.watchesCodes()
	if verify == nil && !watched {
		return u, g, nil
	}
	store := a.opts.Store.(PhoneAccountStore)
	r, err := store.ReadPhoneOTP(ctx, number, purpose)
	if err != nil {
		return u, nil, err
	}
	if r == nil {
		return u, nil, &APIError{400, "OTP_NOT_FOUND", "OTP not found"}
	}
	u.ProviderProof = r.ID
	if watched {
		u.Decided = &g.decision
		// A code that has expired is removed without hooks.
		if r.ExpiresAt.After(u.Now) {
			if err := a.beforeCodeGuess(ctx, g, phoneOTPRecord(purpose, r.ID, r.ExpiresAt), invalidOTP()); err != nil {
				return u, nil, err
			}
			u.Now = a.now().UTC()
		}
	}
	// An expired or exhausted code needs no verdict: the store removes it.
	if r.ExpiresAt.After(u.Now) && r.Attempts < u.AllowedAttempts {
		if verify != nil {
			if u.ProviderAccepted, err = verify(ctx, PhoneOTPMessage{PhoneNumber: number, Code: code, Purpose: purpose}); err != nil {
				return u, nil, err
			}
			u.Now = a.now().UTC()
		} else {
			u.ProviderAccepted = subtle.ConstantTimeCompare([]byte(r.Code), []byte(code)) == 1
		}
	}
	if _, denied := u.Check(r); denied != nil {
		return u, nil, a.refusePhoneGuess(ctx, store, u, g, denied)
	}
	return u, g, nil
}

// refusePhoneGuess applies a guess at a phone code that cannot succeed: the
// store counts it, or removes a code that expired or ran out, and the guess
// is refused. It runs without the request's cancellation or deadline, so a
// client that goes away once its guess was judged cannot keep it from being
// counted, and the count waits at least as long as a correct guess's spend.
func (a *Auth) refusePhoneGuess(ctx context.Context, store PhoneAccountStore, u PhoneOTPUse, g *codeGuess, denied error) error {
	err := store.ConsumePhoneOTP(context.WithoutCancel(ctx), u)
	if hookErr := a.afterCodeGuess(ctx, g); hookErr != nil {
		return hookErr
	}
	if err == nil {
		err = denied
	}
	return err
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
	use, g, err := a.phoneUse(ctx, in.PhoneNumber, in.Code, PhoneVerify)
	if err != nil {
		return out, err
	}
	// spentEarly runs the code's after hooks once a store call ahead of the
	// sign-in committed to the code, before the refusal it answers.
	spentEarly := func(storeErr error) error {
		if hookErr := a.afterCodeGuess(ctx, g); hookErr != nil {
			return hookErr
		}
		return storeErr
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
			if proofErr := spentEarly(a.opts.Store.(PhoneAccountStore).ConsumePhoneOTP(ctx, use)); proofErr != nil {
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
				return out, spentEarly(err)
			}
			if act.Create != nil && registration.err == nil {
				candidate := *act.Create
				number, verified := in.PhoneNumber, true
				candidate.PhoneNumberFields = &PhoneNumberFields{PhoneNumber: &number, PhoneNumberVerified: &verified}
				check := UserInfoValidation{Action: UserInfoCreateUser, Method: "phone-number", User: UserRecord{User: candidate, Fields: serverInput(a.opts.UserAdditionalFields, in.AdditionalFields)}}
				if err := a.ValidateUserInfo(ctx, check); err != nil {
					// A refusal spends the correct code, as a wrong one would be counted.
					act.Use.Now = a.now().UTC()
					if proofErr := spentEarly(a.opts.Store.(PhoneAccountStore).ConsumePhoneOTP(ctx, act.Use)); proofErr != nil {
						return out, proofErr
					}
					return out, err
				}
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
		g.decision = PhoneKeepProof
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
		err = a.planSignIn(ctx, nil, store)
	}
	token := ""
	if err == nil && act.Session != nil && !result.NeedsFactor && act.SourceToken == "" {
		token = act.Session.Token
	}
	// The code's after hooks run before the user's and session's.
	if hookErr := a.afterCodeGuess(ctx, g); hookErr != nil {
		if token != "" {
			hookErr = a.discardUnpublishedSession(ctx, token, hookErr)
		}
		return out, hookErr
	}
	if errors.Is(err, ErrEmailTaken) {
		return out, &APIError{400, "USER_ALREADY_EXISTS", "User already exists"}
	}
	if err == nil {
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
			message, e := a.preparePhoneOTP(ctx, number)
			if e == nil && message != nil {
				e = a.deliver(ctx, "Could not deliver phone verification code", func(ctx context.Context) error {
					return a.phoneNumber.SendOTP(ctx, *message)
				})
			}
			if e != nil {
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
	// The store keeps a code for every number, so the hooks reveal nothing
	// about which numbers have accounts. A declined code is stored and sent
	// nowhere.
	var deliver bool
	declined, err := a.createVerification(ctx, phoneOTPRecord(PhonePasswordReset, r.ID, r.ExpiresAt), func() (err error) {
		deliver, err = a.opts.Store.(PhoneAccountStore).SavePhoneReset(ctx, r, a.phoneNumber.RequireVerification)
		return err
	})
	if err != nil || declined || !deliver || a.phoneNumber.SendPasswordResetOTP == nil {
		return err
	}
	return a.deliver(ctx, "Could not deliver phone password reset code", func(ctx context.Context) error {
		return a.phoneNumber.SendPasswordResetOTP(ctx, PhoneOTPMessage{PhoneNumber: number, Code: code, Purpose: PhonePasswordReset})
	})
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
	// A guess phoneUse bound was judged there, and a failing one applied.
	use, g, err := a.phoneUse(ctx, number, code, PhonePasswordReset)
	if err != nil {
		return err
	}
	store := a.opts.Store.(PhoneAccountStore)
	if use.ProviderProof == "" {
		// Preflight avoids password hashing on an invalid guess; the transaction checks the proof again.
		r, err := store.ReadPhoneOTP(ctx, number, PhonePasswordReset)
		if err != nil {
			return err
		}
		if _, err = use.Check(r); err != nil {
			if r == nil {
				return err
			}
			// Recheck the exact generation inside the store before counting the attempt.
			use.ProviderProof, use.ProviderAccepted = r.ID, false
			return store.ConsumePhoneOTP(ctx, use)
		}
		use.ProviderProof, use.ProviderAccepted = r.ID, true
	}
	hash, err := a.hashCredential(ctx, "/phone-number/reset-password", password)
	if err != nil {
		return err
	}
	use.Now = a.now().UTC()
	out, err := store.ApplyPhoneOTP(ctx, PhoneAccountAction{Use: use, PasswordHash: hash, RevokeSessions: a.opts.RevokeSessionsOnPasswordReset, RequireVerification: a.phoneNumber.RequireVerification})
	// The code's after hooks run before the reset callback; their error
	// fails the request after the password changed.
	if hookErr := a.afterCodeGuess(ctx, g); hookErr != nil {
		return hookErr
	}
	if err != nil || a.opts.OnPasswordReset == nil {
		return err
	}
	return a.notifyPasswordReset(ctx, out.User, request)
}
