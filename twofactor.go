package plainauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"
)

// FactorSubject identifies an existing signed-in session, a login after a
// password check, or a short-lived first-factor challenge.
type FactorSubject struct {
	ApplicationKeyID, ApplicationOperation string
	ReadDelivery                           bool
	TrustedGrant                           string
	UserID, SessionToken, Challenge        string
	Now                                    time.Time
}
type FactorRecord struct {
	ID, Secret, BackupCodes string
	Verified                bool
	Failures                int
	LockedUntil             *time.Time
}
type FactorState struct {
	Delivery       *FactorDelivery
	TrustedGrant   string
	User           User
	Enabled        bool
	Record         *FactorRecord
	PasswordHash   string
	Attempts       int
	LastTOTPStep   int64
	LastTOTPPeriod time.Duration
	Session        *Session
}

// FactorChange is committed under the same owner lock used to load FactorState.
// SaveRecord and DeleteRecord are mutually exclusive. Sessions are persisted
// only after the corresponding authentication decision succeeds.
type FactorChange struct {
	SaveDelivery                        *FactorDelivery
	RemoveDelivery                      bool
	CreateTrustedGrant                  string
	TrustedUntil                        time.Time
	SaveRecord                          *FactorRecord
	DeleteRecord                        bool
	Enabled                             *bool
	CreateChallenge                     string
	ChallengeExpires                    time.Time
	IncrementAttempts, ConsumeChallenge bool
	UsedTOTPStep                        *int64
	UsedTOTPPeriod                      time.Duration
	RevokeSessions                      bool
	Session                             *StoredSession
}
type TwoFactorStore interface {
	FactorEnabled(context.Context, string) (bool, error)
	WithTwoFactor(ctx context.Context, subject FactorSubject, decide func(FactorState) (FactorChange, error)) error
}
type TwoFactorOptions struct {
	TOTP                                        FactorTOTPOptions
	Backup                                      FactorBackupOptions
	Lockout                                     FactorLockoutOptions
	OTP                                         FactorOTPOptions
	AllowPasswordless, SkipVerificationOnEnable bool
	Issuer                                      string
	ChallengeLifetime                           time.Duration
	TrustDeviceMaxAge                           time.Duration
}

type LoginChallenge struct{ Identifier string }

const challengeLifetime = 10 * time.Minute

// NewTwoFactor implements credential login with authenticator codes or backup codes.
func NewTwoFactor(opts TwoFactorOptions) Plugin {
	if opts.ChallengeLifetime == 0 {
		opts.ChallengeLifetime = challengeLifetime
	}
	if opts.TrustDeviceMaxAge == 0 {
		opts.TrustDeviceMaxAge = 30 * 24 * time.Hour
	}
	settingsErr := opts.setDefaults()
	p := Plugin{ID: "two-factor", StoredUserFields: map[string]UserField{"twoFactorEnabled": {Type: FieldBoolean}}, factor: &opts, ValidateStore: func(Store) error {
		if settingsErr != nil {
			return settingsErr
		}
		if opts.TrustDeviceMaxAge < time.Second || opts.ChallengeLifetime < time.Second {
			return errors.New("two-factor cookie lifetimes must be at least one second")
		}
		return nil
	}}
	for _, path := range []string{"/two-factor/enable", "/two-factor/disable", "/two-factor/get-totp-uri", "/two-factor/verify-totp", "/two-factor/verify-backup-code", "/two-factor/generate-backup-codes", "/two-factor/send-otp", "/two-factor/verify-otp"} {
		p.Endpoints = append(p.Endpoints, Endpoint{Method: http.MethodPost, Path: path, Handler: func(c EndpointContext) (any, error) {
			return c.Auth.factorEndpoint(path, c)
		}})
	}
	return p
}

func (a *Auth) factorLogin(ctx context.Context, user User, expectedHash string, session StoredSession, signedDevice string) (AuthResult, error) {
	result := AuthResult{}
	subject := FactorSubject{UserID: user.ID, Now: a.now().UTC(), TrustedGrant: a.readTrustedGrant(signedDevice, user.ID)}
	err := a.planSignIn(ctx, func(ctx context.Context) error {
		return a.factorStore.WithTwoFactor(ctx, subject, a.factorLoginDecision(&result, subject, session, signedDevice, expectedHash))
	})
	if errors.Is(err, errPlannedSessionSkipped) {
		return AuthResult{}, &APIError{401, "FAILED_TO_CREATE_SESSION", "Failed to create session"}
	}
	if err == nil && result.Token != "" {
		err = a.afterDecidedSignIn(ctx, result.User, false, result.Token)
	}
	if err != nil {
		return AuthResult{}, err
	}
	if err := a.readPublicUserFields(ctx, &result.User); err != nil {
		return AuthResult{}, err
	}
	return result, nil
}

// factorLoginDecision issues the session for an account without a second
// factor or with a trusted device, and a challenge otherwise.
func (a *Auth) factorLoginDecision(out *AuthResult, subject FactorSubject, session StoredSession, signedDevice, expectedHash string) func(FactorState) (FactorChange, error) {
	return func(state FactorState) (FactorChange, error) {
		result := AuthResult{}
		defer func() { *out = result }()
		if state.PasswordHash != expectedHash {
			return FactorChange{}, &APIError{401, "INVALID_EMAIL_OR_PASSWORD", "Invalid email or password"}
		}
		if !state.Enabled {
			result = AuthResult{User: state.User, Token: session.Token}
			return FactorChange{Session: &session}, nil
		}
		// An enabled account with unavailable factor material must never fall
		// through to an authenticated session.
		methods := a.factorMethods(state)
		if len(methods) == 0 && (state.Record == nil || !state.Record.Verified || state.Record.BackupCodes == "") {
			return FactorChange{}, &APIError{403, "TOTP_NOT_CONFIGURED", "Two-factor verification is unavailable"}
		}
		if state.TrustedGrant != "" {
			change := FactorChange{Session: &session}
			result = AuthResult{User: state.User, Token: session.Token, TrustedDeviceCookie: a.rotateTrustedGrant(&change, state.User.ID, subject.Now)}
			return change, nil
		}
		if signedDevice != "" {
			result.TrustedDeviceCookie = a.trustedDeviceCookie("", "", -1)
		}
		id := "2fa-" + randomID()
		result.Challenge = &LoginChallenge{Identifier: id}
		result.TwoFactorRedirect = true
		result.TwoFactorMethods = methods
		return FactorChange{CreateChallenge: id, ChallengeExpires: subject.Now.Add(a.factorOptions.ChallengeLifetime)}, nil
	}
}

// TwoFactorChallengeCookie serializes a pending native sign-in result for the
// browser to carry to the verification endpoint. It cannot authenticate GetSession.
func (a *Auth) TwoFactorChallengeCookie(challenge LoginChallenge) *http.Cookie {
	life := challengeLifetime
	if a.factorOptions != nil {
		life = a.factorOptions.ChallengeLifetime
	}
	return a.factorCookie(challenge.Identifier, int(life.Seconds()))
}
func (a *Auth) factorCookie(id string, expires int) *http.Cookie {
	c := a.SignedCookie("two_factor", id, expires)
	if expires < 0 {
		c.Value = ""
	}
	return c
}

func (a *Auth) factorEndpoint(route string, c EndpointContext) (any, error) {
	ctx, r := c.Request.Context(), c.Request
	subject := FactorSubject{Now: a.now().UTC()}
	if raw := a.cookieToken(r.Header); raw != "" {
		subject.SessionToken = raw
	}
	keySession, _ := ctx.Value(credentialSessionKey{a}).(*SessionResult)
	if keySession != nil {
		store, ok := a.factorStore.(interface{ SupportsKeyFactorEnrollment() bool })
		if !ok || !store.SupportsKeyFactorEnrollment() || !keySession.Session.AllowsCredentialAction("twoFactor", "enable") || (route != "/two-factor/enable" && route != "/two-factor/verify-totp") {
			return nil, &APIError{403, "OWNER_SESSION_REQUIRED", "This factor operation requires a direct login"}
		}
		if method, ok := c.Body["method"]; ok && method != "totp" {
			return nil, &APIError{403, "OWNER_SESSION_REQUIRED", "This enrollment method requires a direct login"}
		}
		subject.ApplicationKeyID = keySession.Session.ID
		subject.ApplicationOperation = route
		subject.UserID = keySession.User.ID
	}
	isSend := route == "/two-factor/send-otp"
	subject.ReadDelivery = isSend || route == "/two-factor/verify-otp"
	isProof := route == "/two-factor/verify-totp" || route == "/two-factor/verify-backup-code" || route == "/two-factor/verify-otp"
	if subject.SessionToken == "" && keySession == nil {
		if !isProof && !isSend {
			return nil, &APIError{401, "UNAUTHORIZED", "Unauthorized"}
		}
		marker, err := r.Cookie(a.factorCookie("", 0).Name)
		if err == nil {
			subject.Challenge = a.VerifySignedSessionToken(marker.Value)
		}
		if !strings.HasPrefix(subject.Challenge, "2fa-") {
			return nil, factorCookieError()
		}
	}
	remember := !a.dontRemember(r)
	op := factorRequest{
		auth: a, ctx: ctx, route: route, body: c.Body, subject: subject,
		meta: RequestMeta{IPAddress: a.clientIP(r), UserAgent: r.UserAgent(), RememberMe: &remember},
	}
	decide := op.manage
	if isProof {
		decide = op.verify
	} else if isSend {
		decide = op.sendOTP
	}
	if keySession != nil {
		base := decide
		decide = func(state FactorState) (FactorChange, error) {
			state.Session = &keySession.Session
			if route == "/two-factor/enable" && state.PasswordHash == "" {
				return FactorChange{}, &APIError{403, "OWNER_SESSION_REQUIRED", "Credential enrollment requires an account password"}
			}
			ch, e := base(state)
			// An application key can enroll a factor after independent password
			// proof, but never upgrades itself to a durable browser session.
			ch.Session = nil
			op.issued = ""
			op.trustedCookie = nil
			if out, ok := op.out.(map[string]any); ok {
				if _, found := out["token"]; found {
					out["token"] = keySession.Session.Token
				}
			}
			return ch, e
		}
	}
	write := func(ctx context.Context) error { return a.factorStore.WithTwoFactor(ctx, subject, decide) }
	var err error
	if isSend {
		err = write(ctx)
	} else {
		// Proofs and factor changes may issue a session, which runs the session create hooks.
		err = a.planSignIn(ctx, write)
	}
	if errors.Is(err, ErrNotFound) {
		if subject.Challenge != "" {
			return nil, factorCookieError()
		}
		return nil, &APIError{401, "UNAUTHORIZED", "Unauthorized"}
	}
	if err == nil && op.issued != "" {
		err = a.afterDecidedSignIn(ctx, User{}, false, op.issued)
	}
	if err != nil {
		return nil, err
	}
	if op.mail != nil {
		if err := op.deliver(); err != nil {
			return nil, err
		}
	}
	if op.clearChallenge {
		c.ResponseHeader.Add("Set-Cookie", a.factorCookie("", -1).String())
	}
	if op.denied != nil {
		return nil, op.denied
	}
	if op.issued != "" {
		if a.anonymous != nil && subject.Challenge != "" {
			cookie := a.oauthCookie("guest_continuation", "", -1)
			if marker, err := r.Cookie(cookie.Name); err == nil {
				if guest, err := a.openRecord("guest-mfa:"+subject.Challenge, marker.Value); err == nil {
					r = r.WithContext(context.WithValue(r.Context(), anonymousSourceKey{}, string(guest)))
				}
				c.ResponseHeader.Add("Set-Cookie", cookie.String())
			}
		}
		if err := a.addSessionCookieHeaders(c.ResponseHeader, r, op.issued, remember); err != nil {
			return nil, err
		}
	}
	if op.trustedCookie != nil {
		c.ResponseHeader.Add("Set-Cookie", op.trustedCookie.String())
	}
	return op.out, nil
}

type factorRequest struct {
	deliveryID     string
	mail           *FactorOTPMessage
	trustedCookie  *http.Cookie
	auth           *Auth
	ctx            context.Context
	route          string
	body           wireBody
	subject        FactorSubject
	meta           RequestMeta
	out            any
	denied         error
	issued         string
	draft          *StoredSession
	clearChallenge bool
}

// sessionDraft returns the session this request issues to userID. The draft
// stays the same when a login plan runs the decision again.
func (p *factorRequest) sessionDraft(userID string) (StoredSession, string) {
	if p.draft == nil || p.draft.UserID != userID {
		ss, _ := p.auth.newSession(userID, p.meta)
		p.draft = &ss
	}
	return *p.draft, p.draft.Token
}

func (p *factorRequest) verify(state FactorState) (FactorChange, error) {
	var ch FactorChange

	code, err := requiredString(p.body, "code")
	if err != nil {
		return ch, err
	}
	disableSession := false
	if v, ok := p.body["disableSession"]; ok && p.route == "/two-factor/verify-backup-code" {
		var valid bool
		disableSession, valid = v.(bool)
		if !valid {
			return ch, fieldTypeError("disableSession", "boolean", p.body)
		}
	}
	trustDevice := false
	if v, ok := p.body["trustDevice"]; ok {
		var valid bool
		trustDevice, valid = v.(bool)
		if !valid {
			return ch, fieldTypeError("trustDevice", "boolean", p.body)
		}
	}
	if p.route == "/two-factor/verify-otp" && p.auth.factorOptions.OTP.Send == nil {
		return ch, &APIError{400, "OTP_NOT_CONFIGURED", "OTP is not available"}
	}
	if state.Record == nil {
		return ch, &APIError{400, "TOTP_NOT_ENABLED", "Two factor is not enabled"}
	}
	if p.subject.Challenge != "" && (!state.Enabled || (!state.Record.Verified && !(p.route == "/two-factor/verify-otp" && state.Record.hasPendingAuthenticator()))) {
		return ch, factorCookieError()
	}
	if !p.auth.factorOptions.Lockout.Disabled && state.Record.LockedUntil != nil && state.Record.LockedUntil.After(p.subject.Now) {
		return ch, &APIError{429, "ACCOUNT_TEMPORARILY_LOCKED", "Too many failed verification attempts. Your account is temporarily locked. Please try again later."}
	}
	record := *state.Record
	if record.LockedUntil != nil {
		record.Failures = 0
		record.LockedUntil = nil
	}
	valid := false
	if p.route == "/two-factor/verify-totp" {
		if p.auth.factorOptions.TOTP.Disabled || record.Secret == "" {
			return ch, &APIError{400, "TOTP_NOT_CONFIGURED", "TOTP is not available"}
		}
		raw, err := p.auth.openAuthenticator(record.Secret)
		if err != nil {
			return ch, err
		}
		step, matched, err := p.auth.factorOptions.TOTP.step(raw, code, p.subject.Now)
		valid = matched
		if p.subject.Challenge != "" && valid {
			previousPeriod := state.LastTOTPPeriod
			if previousPeriod == 0 {
				previousPeriod = 30 * time.Second
			}
			valid = state.LastTOTPStep < 0 || step*int64(p.auth.factorOptions.TOTP.Period/time.Second) > state.LastTOTPStep*int64(previousPeriod/time.Second)
			if valid {
				ch.UsedTOTPStep = &step
				ch.UsedTOTPPeriod = p.auth.factorOptions.TOTP.Period
			}
		}
		if err != nil {
			return ch, err
		}
	} else if p.route == "/two-factor/verify-otp" {
		if !state.Enabled || (!record.Verified && !record.hasPendingAuthenticator()) {
			return ch, &APIError{400, "OTP_NOT_ENABLED", "OTP not enabled"}
		}
		var early error
		valid, early = p.checkDelivery(state, code, &ch)
		if early != nil {
			p.denied = early
			return ch, nil
		}
	} else {
		if !state.Enabled || !record.Verified {
			return ch, &APIError{400, "TWO_FACTOR_NOT_ENABLED", "Two factor isn't enabled"}
		}
		if record.BackupCodes == "" {
			return ch, &APIError{400, "BACKUP_CODES_NOT_ENABLED", "Backup codes are not enabled"}
		}
		items, err := p.auth.readBackupCodes(p.ctx, record.BackupCodes)
		if err != nil {
			return ch, err
		}
		for i, s := range items {
			if subtle.ConstantTimeCompare([]byte(s), []byte(code)) == 1 {
				valid = true
				items = append(items[:i], items[i+1:]...)
				record.BackupCodes, err = p.auth.storeBackupCodes(p.ctx, items)
				if err != nil {
					return ch, err
				}
				break
			}
		}
	}
	if !valid {
		record.Failures++
		if !p.auth.factorOptions.Lockout.Disabled && record.Failures >= p.auth.factorOptions.Lockout.MaxFailedAttempts {
			until := p.subject.Now.Add(p.auth.factorOptions.Lockout.Duration)
			record.LockedUntil = &until
		}
		ch.SaveRecord = &record
		ch.IncrementAttempts = p.subject.Challenge != ""
		if ch.IncrementAttempts && state.Attempts+1 >= 5 {
			ch.ConsumeChallenge = true
			p.clearChallenge = true
		}
		p.denied = &APIError{401, "INVALID_CODE", "Invalid code"}
		if p.route == "/two-factor/verify-backup-code" {
			p.denied = &APIError{401, "INVALID_BACKUP_CODE", "Invalid backup code"}
		}
		return ch, nil
	}
	activating := !record.Verified && p.route == "/two-factor/verify-totp"
	if activating {
		record.Verified = true
		record.Secret = strings.TrimPrefix(record.Secret, pendingAuthenticatorPrefix)
	}
	record.Failures = 0
	record.LockedUntil = nil
	ch.SaveRecord = &record
	if activating {
		enabled := true
		ch.Enabled = &enabled
		ch.RevokeSessions = true
		state.User.TwoFactorEnabled = &enabled
	}
	if p.subject.Challenge != "" && disableSession {
		ch.ConsumeChallenge = true
		p.clearChallenge = true
		p.out = map[string]any{"user": state.User}
	} else if activating || p.subject.Challenge != "" {
		ss, raw := p.sessionDraft(state.User.ID)
		ch.Session = &ss
		p.issued = raw
		if trustDevice && p.subject.Challenge != "" {
			p.trustedCookie = p.auth.rotateTrustedGrant(&ch, state.User.ID, p.subject.Now)
		}
		ch.ConsumeChallenge = p.subject.Challenge != ""
		p.clearChallenge = ch.ConsumeChallenge
		p.out = map[string]any{"token": raw, "user": state.User}
	} else {
		p.out = map[string]any{"token": state.Session.Token, "user": state.User}
	}
	return ch, nil
}

func (p *factorRequest) manage(state FactorState) (FactorChange, error) {
	var ch FactorChange

	o := p.auth.factorOptions
	allowPasswordless := o.AllowPasswordless
	if p.route == "/two-factor/get-totp-uri" && o.TOTP.AllowPasswordless != nil {
		allowPasswordless = *o.TOTP.AllowPasswordless
	}
	if p.route == "/two-factor/generate-backup-codes" && o.Backup.AllowPasswordless != nil {
		allowPasswordless = *o.Backup.AllowPasswordless
	}
	if state.PasswordHash != "" || !allowPasswordless {
		password, err := requiredString(p.body, "password")
		if err != nil {
			return ch, err
		}
		if err := p.auth.validatePasswordLength(password, false); err != nil {
			return ch, err
		}
		if state.PasswordHash == "" {
			return ch, &APIError{400, "INVALID_PASSWORD", "Invalid password"}
		}
		valid, err := p.auth.checkCredential(p.ctx, state.PasswordHash, password)
		if err != nil {
			return ch, err
		}
		if !valid {
			return ch, &APIError{400, "INVALID_PASSWORD", "Invalid password"}
		}
	}
	if p.route == "/two-factor/enable" {
		if method, ok := p.body["method"]; ok && method != "totp" {
			if method != "otp" {
				return ch, validationError("Unknown two-factor enrollment method")
			}
			return p.enableOTP(state)
		}
		if o.TOTP.Disabled {
			return ch, &APIError{400, "TOTP_NOT_CONFIGURED", "TOTP is not available"}
		}
		if state.Record != nil && state.Record.Secret != "" && state.Record.Verified {
			return ch, &APIError{400, "TOTP_ALREADY_ENABLED", "TOTP is already enabled"}
		}
		secret := rand.Text()
		encrypted, err := p.auth.sealRecord("totp", []byte(secret))
		if err != nil {
			return ch, err
		}
		codes, err := p.auth.factorOptions.Backup.generate(p.ctx)
		if err != nil {
			return ch, err
		}
		backups, err := p.auth.storeBackupCodes(p.ctx, codes)
		if err != nil {
			return ch, err
		}
		ch.SaveRecord = &FactorRecord{ID: randomID(), Secret: encrypted, BackupCodes: backups}
		if state.Enabled && !o.SkipVerificationOnEnable && (state.Record == nil || state.Record.Secret == "" || state.Record.hasPendingAuthenticator()) {
			ch.SaveRecord.Secret = pendingAuthenticatorPrefix + encrypted
		}
		if o.SkipVerificationOnEnable {
			enabled := true
			ch.Enabled = &enabled
			ch.SaveRecord.Verified = true
			ch.RevokeSessions = true
			ss, token := p.sessionDraft(state.User.ID)
			ch.Session = &ss
			p.issued = token
		}
		issuer := p.auth.factorOptions.Issuer
		if v, ok := p.body["issuer"].(string); ok && v != "" {
			issuer = v
		}
		p.out = map[string]any{"method": "totp", "totpURI": p.auth.factorOptions.TOTP.uri(issuer, state.User.Email, []byte(secret)), "backupCodes": codes}
		return ch, nil
	}
	if state.Record == nil {
		return ch, &APIError{400, "TWO_FACTOR_NOT_ENABLED", "Two factor isn't enabled"}
	}
	switch p.route {
	case "/two-factor/disable":
		enabled := false
		ch.Enabled = &enabled
		ch.DeleteRecord = true
		ch.RevokeSessions = true
		ss, raw := p.sessionDraft(state.User.ID)
		ch.Session = &ss
		p.issued = raw
		p.out = map[string]bool{"status": true}
	case "/two-factor/get-totp-uri":
		if o.TOTP.Disabled || state.Record.Secret == "" {
			return ch, &APIError{400, "TOTP_NOT_CONFIGURED", "TOTP is not available"}
		}
		raw, err := p.auth.openAuthenticator(state.Record.Secret)
		if err != nil {
			return ch, err
		}
		p.out = map[string]string{"totpURI": p.auth.factorOptions.TOTP.uri(p.auth.factorOptions.Issuer, state.User.Email, raw)}
	case "/two-factor/generate-backup-codes":
		if !state.Enabled || !state.Record.Verified {
			return ch, &APIError{400, "TWO_FACTOR_NOT_ENABLED", "Two factor isn't enabled"}
		}
		codes, err := p.auth.factorOptions.Backup.generate(p.ctx)
		if err != nil {
			return ch, err
		}
		record := *state.Record
		record.BackupCodes, err = p.auth.storeBackupCodes(p.ctx, codes)
		if err != nil {
			return ch, err
		}
		ch.SaveRecord = &record
		p.out = map[string]any{"status": true, "backupCodes": codes}
	}
	return ch, nil
}

func factorCookieError() *APIError {
	return &APIError{401, "INVALID_TWO_FACTOR_COOKIE", "Invalid two factor cookie"}
}
