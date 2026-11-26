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
	// ChallengeID and ChallengeExpires are the stored row ID and expiry of
	// the challenge the subject names, and TrustedGrantID and
	// TrustedGrantExpires those of TrustedGrant. A FactorRecordReporter fills
	// them for the verification hooks.
	ChallengeID, TrustedGrantID           string
	ChallengeExpires, TrustedGrantExpires time.Time
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
	// ChallengeID and TrustedGrantID are the row IDs to store CreateChallenge
	// and CreateTrustedGrant under, which the verification hooks name them
	// by. A store that is not a FactorRecordReporter may choose its own.
	ChallengeID, TrustedGrantID string
}
type TwoFactorStore interface {
	FactorEnabled(context.Context, string) (bool, error)
	WithTwoFactor(ctx context.Context, subject FactorSubject, decide func(FactorState) (FactorChange, error)) error
}

// FactorRecordReporter is a TwoFactorStore whose WithTwoFactor the
// verification hooks can follow. New requires it for any verification
// database hook with the two-factor plugin. Its WithTwoFactor:
//   - fills FactorState's ChallengeID and ChallengeExpires from the
//     challenge row it locked, and TrustedGrantID and TrustedGrantExpires
//     from the remembered browser's row it locked;
//   - stores CreateChallenge under FactorChange.ChallengeID,
//     CreateTrustedGrant under FactorChange.TrustedGrantID and a delivered
//     code under its ID;
//   - calls decide once per transaction attempt, again only after rolling
//     an attempt back, and commits exactly the change the last call
//     returned, or nothing;
//   - writes nothing and returns decide's error when decide fails;
//   - for an empty change writes nothing but the normalizations any call
//     makes, such as lifting an expired ban.
type FactorRecordReporter interface{ ReportsFactorRecords() }
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
		// A lifetime under a second would set a cookie that expires at once;
		// the other runtime accepts any number of seconds.
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

// factorPins are the keys and row IDs one two-factor request may store,
// drawn once so that every run of its store call names the same records.
type factorPins struct {
	challenge, challengeID, grant, grantID, deliveryID string
	challengeExpires, grantUntil                       time.Time
}

func (a *Auth) newFactorPins(now time.Time) factorPins {
	o := a.factorOptions
	return factorPins{challenge: "2fa-" + randomID(), challengeID: randomID(), grant: "trust-device-" + randomID(), grantID: randomID(), deliveryID: randomID(),
		challengeExpires: now.Add(o.ChallengeLifetime), grantUntil: now.Add(o.TrustDeviceMaxAge)}
}

func (a *Auth) factorLogin(ctx context.Context, user User, expectedHash string, session StoredSession, signedDevice string) (AuthResult, error) {
	result := AuthResult{}
	subject := FactorSubject{UserID: user.ID, Now: a.now().UTC(), TrustedGrant: a.readTrustedGrant(signedDevice, user.ID)}
	pins, h := a.newFactorPins(subject.Now), a.newFactorHooks()
	err := a.runFactor(ctx, h, &subject, true, func(ctx context.Context) error {
		return a.planSignIn(ctx, nil, func(ctx context.Context) error {
			return a.factorStore.WithTwoFactor(ctx, subject, h.follow(a.factorLoginDecision(&result, h, pins, session, signedDevice, expectedHash)))
		})
	})
	if errors.Is(err, errPlannedSessionSkipped) {
		return AuthResult{}, &APIError{401, "FAILED_TO_CREATE_SESSION", "Failed to create session"}
	}
	if err == nil {
		// The records' after hooks run before the session's.
		if hookErr := h.after(ctx); hookErr != nil {
			err = hookErr
			if result.Token != "" {
				err = a.discardUnpublishedSession(ctx, result.Token, hookErr)
			}
		}
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
// factor or with a trusted device, and a challenge otherwise. With
// verification hooks, a remembered browser whose spend or replacement they
// declined asks for the second factor, and a declined challenge is answered
// but never stored.
func (a *Auth) factorLoginDecision(out *AuthResult, h *factorHooks, pins factorPins, session StoredSession, signedDevice, expectedHash string) func(FactorState) (FactorChange, error) {
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
		// An enabled account with no usable factor and no stored backup codes
		// is refused, even from a remembered browser, rather than given a
		// challenge it cannot complete; the other runtime issues a challenge,
		// or signs a remembered browser in.
		methods := a.factorMethods(state)
		if len(methods) == 0 && (state.Record == nil || !state.Record.Verified || state.Record.BackupCodes == "") {
			return FactorChange{}, &APIError{400, "TOTP_NOT_CONFIGURED", "TOTP is not available"}
		}
		uid, declined := state.User.ID, false
		if state.TrustedGrant != "" {
			spend := h.approval(roleSpend, factorRecord("trust-device", state.TrustedGrantID, uid, state.TrustedGrantExpires))
			grant := factorDeclined
			if spend != factorDeclined {
				grant = h.approval(roleGrant, factorRecord("trust-device", pins.grantID, uid, pins.grantUntil))
			}
			if spend == factorPending || grant == factorPending {
				return FactorChange{}, errFactorUnapproved
			}
			if spend == factorApproved && grant == factorApproved {
				change := FactorChange{Session: &session}
				result = AuthResult{User: state.User, Token: session.Token, TrustedDeviceCookie: a.rotateTrustedGrant(&change, uid, pins)}
				return change, nil
			}
			// A grant whose spend or replacement was declined never
			// authorizes a sign-in; it stays, with its cookie, for the next.
			declined = true
		}
		if signedDevice != "" && !declined {
			result.TrustedDeviceCookie = a.trustedDeviceCookie("", "", -1)
		}
		issue := h.approval(roleIssue, factorRecord("2fa", pins.challengeID, uid, pins.challengeExpires))
		if issue == factorPending {
			return FactorChange{}, errFactorUnapproved
		}
		result.Challenge = &LoginChallenge{Identifier: pins.challenge}
		result.TwoFactorRedirect = true
		result.TwoFactorMethods = methods
		if issue == factorDeclined {
			// A declined challenge is answered, but never stored, so its
			// cookie redeems nothing.
			return FactorChange{}, nil
		}
		return FactorChange{CreateChallenge: pins.challenge, ChallengeID: pins.challengeID, ChallengeExpires: pins.challengeExpires}, nil
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
	// trustDevice is accepted on send-otp as a boolean, checked before the
	// session or challenge as the body schema is, and otherwise ignored: the
	// browser is remembered only by the proof at /two-factor/verify-otp.
	if v, ok := c.Body["trustDevice"]; isSend && ok {
		if _, valid := v.(bool); !valid {
			return nil, fieldTypeError("trustDevice", "boolean", c.Body)
		}
	}
	if isSend && a.factorOptions.OTP.Send == nil {
		// Refused before the session or challenge is read, as the other
		// runtime does.
		return nil, &APIError{400, "OTP_NOT_CONFIGURED", "otp isn't configured"}
	}
	if route == "/two-factor/verify-totp" && a.factorOptions.TOTP.Disabled {
		// The body is checked, and then a disabled authenticator is refused
		// before any session, challenge, factor or lockout is read, as the
		// other runtime does.
		if _, err := requiredString(c.Body, "code"); err != nil {
			return nil, err
		}
		if v, ok := c.Body["trustDevice"]; ok {
			if _, valid := v.(bool); !valid {
				return nil, fieldTypeError("trustDevice", "boolean", c.Body)
			}
		}
		return nil, &APIError{400, "TOTP_NOT_CONFIGURED", "totp isn't configured"}
	}
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
		auth: a, ctx: ctx, route: route, body: c.Body, subject: subject, pins: a.newFactorPins(subject.Now), hooks: a.newFactorHooks(),
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
	// Each run reports afresh, so a run the store rolled back, such as a
	// login plan's dry run, never reaches the response.
	run := decide
	decide = op.hooks.follow(func(st FactorState) (FactorChange, error) {
		op.reset()
		return run(st)
	})
	write := func(ctx context.Context) error { return a.factorStore.WithTwoFactor(ctx, op.subject, decide) }
	call := write
	if !isSend {
		// Proofs and factor changes may issue a session, which runs the session create hooks.
		call = func(ctx context.Context) error { return a.planSignIn(ctx, nil, write) }
	}
	err := a.runFactor(ctx, op.hooks, &op.subject, !isSend, call)
	if errors.Is(err, errFactorSendDeclined) {
		// A declined code answers as sent, with nothing stored or sent.
		return map[string]bool{"status": true}, nil
	}
	if errors.Is(err, ErrNotFound) {
		if subject.Challenge != "" {
			return nil, factorCookieError()
		}
		return nil, &APIError{401, "UNAUTHORIZED", "Unauthorized"}
	}
	if err == nil {
		// The records' after hooks run before the session's and before the
		// code is sent.
		if hookErr := op.hooks.after(ctx); hookErr != nil {
			err = hookErr
			if op.issued != "" {
				err = a.discardUnpublishedSession(ctx, op.issued, hookErr)
			}
		}
	}
	if err == nil && op.issued != "" {
		err = a.afterDecidedSignIn(ctx, User{}, false, op.issued)
	}
	if err != nil {
		return nil, err
	}
	if op.mail != nil {
		// The code is stored before it is sent, so a sender error is logged,
		// never answered, and the code stays valid, as in the other runtime.
		// With BackgroundTasks the whole sender runs after the response; the
		// other runtime starts it first and hands off only its promise.
		mail, send := *op.mail, a.factorOptions.OTP.Send
		a.runInBackgroundOrAwait(ctx, "Failed to send two-factor OTP", func(ctx context.Context) error { return send(ctx, mail) })
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
		expireOtherScopes(c.ResponseHeader, c.Request, op.trustedCookie)
		c.ResponseHeader.Add("Set-Cookie", op.trustedCookie.String())
		// Remembering the browser also drops its don't-remember marker, so
		// the new session renews like a remembered one.
		a.writeRememberPreference(c.ResponseHeader, r, true)
	}
	return op.out, nil
}

type factorRequest struct {
	pins           factorPins
	hooks          *factorHooks
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

// reset clears what a run of the store call reports.
func (p *factorRequest) reset() {
	p.mail, p.trustedCookie, p.out, p.denied, p.issued, p.clearChallenge = nil, nil, nil, nil, "", false
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
	// A record without an authenticator or backup codes, kept for delivered
	// codes, stands for no record on the route that needs them.
	if state.Record == nil || (p.route == "/two-factor/verify-totp" && state.Record.Secret == "") || (p.route == "/two-factor/verify-backup-code" && state.Record.BackupCodes == "") {
		return ch, p.notEnabled(state)
	}
	// During sign-in an authenticator awaiting confirmation is not enabled,
	// nor are its backup codes; the other runtime accepts those backup codes.
	if p.subject.Challenge != "" && state.Enabled && !state.Record.Verified && p.route != "/two-factor/verify-otp" {
		return ch, p.notEnabled(state)
	}
	if p.subject.Challenge != "" && (!state.Enabled || (!state.Record.Verified && !(p.route == "/two-factor/verify-otp" && state.Record.hasPendingAuthenticator()))) {
		return ch, factorCookieError()
	}
	// The lock also refuses signed-in proofs, whose failures count toward
	// it; the other runtime locks sign-in proofs only.
	if !p.auth.factorOptions.Lockout.Disabled && state.Record.LockedUntil != nil && state.Record.LockedUntil.After(p.subject.Now) {
		return ch, &APIError{429, "ACCOUNT_TEMPORARILY_LOCKED", "Too many failed verification attempts. Your account is temporarily locked. Please try again later."}
	}
	record := *state.Record
	if record.LockedUntil != nil {
		record.Failures = 0
		record.LockedUntil = nil
	}
	// The refusals that compare nothing come before any comparison.
	switch p.route {
	case "/two-factor/verify-totp":
		// factorEndpoint refused a disabled authenticator, and the checks
		// above a missing or unconfirmed one.
	case "/two-factor/verify-otp":
		// Only /two-factor/enable with the password enrolls an account; the
		// other runtime also enrolls one through a verified code.
		if !state.Enabled || (!record.Verified && !record.hasPendingAuthenticator()) {
			return ch, &APIError{400, "OTP_NOT_ENABLED", "OTP not enabled"}
		}
		if early := p.deliveryReady(state, &ch); early != nil {
			p.denied = early
			return ch, nil
		}
	default:
		// Backup codes of an authenticator awaiting confirmation never
		// verify; the other runtime accepts them.
		if !state.Enabled || !record.Verified {
			return ch, &APIError{400, "BACKUP_CODES_NOT_ENABLED", "Backup codes aren't enabled"}
		}
	}
	// A grant is stored only by a correct proof that signs in.
	wantsGrant := trustDevice && !disableSession
	if err := p.gate(state, wantsGrant); err != nil {
		return FactorChange{}, err
	}
	valid := false
	if p.route == "/two-factor/verify-totp" {
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
			// A sign-in code must come from a later period than the last one a
			// sign-in accepted, so no code signs in twice. The other runtime
			// keeps no such record.
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
		var early error
		valid, early = p.checkDelivery(state, code, &ch)
		if early != nil {
			p.denied = early
			return ch, nil
		}
	} else {
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
		// The fifth failed proof of any kind ends the challenge at once; the
		// other runtime counts only authenticator and backup-code failures and
		// answers the next proof with TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE first.
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
		if wantsGrant && p.subject.Challenge != "" && p.hooks.allows(roleGrant) {
			p.trustedCookie = p.auth.rotateTrustedGrant(&ch, state.User.ID, p.pins)
		}
		ch.ConsumeChallenge = p.subject.Challenge != ""
		p.clearChallenge = ch.ConsumeChallenge
		p.out = map[string]any{"token": raw, "user": state.User}
	} else {
		p.out = map[string]any{"token": state.Session.Token, "user": state.User}
	}
	return ch, nil
}

// gate holds a guess until the delete before hooks of what it is judged
// against approved it, before anything compares it: the delivered code on
// /two-factor/verify-otp, then the challenge during sign-in. A remembered
// browser a correct proof would add waits for its create before hooks too.
// It returns errFactorUnapproved while hooks have yet to run, and refuses,
// uncompared and uncounted, a guess whose record changed since its hooks ran.
func (p *factorRequest) gate(st FactorState, wantsGrant bool) error {
	h := p.hooks
	if h == nil {
		return nil
	}
	uid, pending := st.User.ID, false
	if d := st.Delivery; p.route == "/two-factor/verify-otp" { // deliveryReady let only a live, active code through
		wait, changed := h.guess(&h.delivery, roleDelivery, factorRecord("2fa-otp", d.ID, uid, d.ExpiresAt))
		if changed {
			return otpUnavailable() // a code sent again since its hooks ran is left alone
		}
		pending = pending || wait
	}
	if p.subject.Challenge != "" {
		wait, changed := h.guess(&h.challenge, roleChallenge, factorRecord("2fa", st.ChallengeID, uid, st.ChallengeExpires))
		if changed {
			return factorCookieError()
		}
		pending = pending || wait
		if wantsGrant && h.approval(roleGrant, factorRecord("trust-device", p.pins.grantID, uid, p.pins.grantUntil)) == factorPending {
			pending = true
		}
	}
	if pending {
		return errFactorUnapproved
	}
	return nil
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
	// password is an optional string under a passwordless switch and a
	// required one otherwise, as the body schema has it.
	_, sent := p.body["password"]
	password := ""
	if sent || !allowPasswordless {
		var err error
		if password, err = requiredString(p.body, "password"); err != nil {
			return ch, err
		}
	}
	// The password is checked before each route's own refusals, so every
	// factor change answers the password first; the other runtime refuses
	// /two-factor/get-totp-uri, and /two-factor/generate-backup-codes for an
	// account without two-factor, before checking it.
	if state.PasswordHash != "" || !allowPasswordless {
		// An account with a password that leaves it out is refused like a
		// wrong one.
		if !sent {
			return ch, &APIError{400, "INVALID_PASSWORD", "Invalid password"}
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
	switch p.route {
	case "/two-factor/disable":
		// An account without a record, such as one enrolled by the user flag
		// alone, can still turn the factor off.
		enabled := false
		ch.Enabled = &enabled
		ch.DeleteRecord = true
		ch.RevokeSessions = true
		ss, raw := p.sessionDraft(state.User.ID)
		ch.Session = &ss
		p.issued = raw
		p.out = map[string]bool{"status": true}
	case "/two-factor/get-totp-uri":
		if o.TOTP.Disabled {
			return ch, &APIError{400, "TOTP_NOT_CONFIGURED", "totp isn't configured"}
		}
		// A record without an authenticator, kept for delivered codes, stands
		// for no record.
		if state.Record == nil || state.Record.Secret == "" {
			return ch, &APIError{400, "TOTP_NOT_ENABLED", "TOTP not enabled"}
		}
		raw, err := p.auth.openAuthenticator(state.Record.Secret)
		if err != nil {
			return ch, err
		}
		p.out = map[string]string{"totpURI": p.auth.factorOptions.TOTP.uri(p.auth.factorOptions.Issuer, state.User.Email, raw)}
	case "/two-factor/generate-backup-codes":
		// A record without an authenticator, kept for delivered codes, stands
		// for no record. Backup codes such an account already holds keep
		// verifying but are not replaced; the other runtime keeps none for it.
		if !state.Enabled || state.Record == nil || state.Record.Secret == "" {
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

// notEnabled refuses a proof that the account has no factor to judge by.
func (p *factorRequest) notEnabled(state FactorState) *APIError {
	switch p.route {
	case "/two-factor/verify-backup-code":
		return &APIError{400, "BACKUP_CODES_NOT_ENABLED", "Backup codes aren't enabled"}
	case "/two-factor/verify-otp":
		if !state.Enabled {
			return &APIError{400, "OTP_NOT_ENABLED", "OTP not enabled"}
		}
		// Sending a code stores a record, so an account without one has no code.
		return otpExpired()
	}
	return &APIError{400, "TOTP_NOT_ENABLED", "TOTP not enabled"}
}

func factorCookieError() *APIError {
	return &APIError{401, "INVALID_TWO_FACTOR_COOKIE", "Invalid two factor cookie"}
}
