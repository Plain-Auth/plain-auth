package fineauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// FactorSubject identifies an existing signed-in session, a login after a
// password check, or a short-lived first-factor challenge.
type FactorSubject struct {
	TrustedGrant                    string
	UserID, SessionToken, Challenge string
	Now                             time.Time
}
type FactorRecord struct {
	ID, Secret, BackupCodes string
	Verified                bool
	Failures                int
	LockedUntil             *time.Time
}
type FactorState struct {
	TrustedGrant string
	User         User
	Enabled      bool
	Record       *FactorRecord
	PasswordHash string
	Attempts     int
	LastTOTPStep int64
	Session      *Session
}

// FactorChange is committed under the same owner lock used to load FactorState.
// SaveRecord and DeleteRecord are mutually exclusive. Sessions are persisted
// only after the corresponding authentication decision succeeds.
type FactorChange struct {
	CreateTrustedGrant                  string
	TrustedUntil                        time.Time
	SaveRecord                          *FactorRecord
	DeleteRecord                        bool
	Enabled                             *bool
	CreateChallenge                     string
	ChallengeExpires                    time.Time
	IncrementAttempts, ConsumeChallenge bool
	UsedTOTPStep                        *int64
	RevokeSessions                      bool
	Session                             *StoredSession
}
type TwoFactorStore interface {
	FactorEnabled(context.Context, string) (bool, error)
	WithTwoFactor(ctx context.Context, subject FactorSubject, decide func(FactorState) (FactorChange, error)) error
}
type TwoFactorOptions struct {
	Issuer            string
	ChallengeLifetime time.Duration
	TrustDeviceMaxAge time.Duration
}

type LoginChallenge struct{ Identifier string }

const challengeLifetime = 10 * time.Minute

// NewTwoFactor implements credential login with authenticator codes or backup codes.
func NewTwoFactor(opts TwoFactorOptions) Plugin {
	if opts.Issuer == "" {
		opts.Issuer = "Auth"
	}
	if opts.ChallengeLifetime == 0 {
		opts.ChallengeLifetime = challengeLifetime
	}
	if opts.TrustDeviceMaxAge == 0 {
		opts.TrustDeviceMaxAge = 30 * 24 * time.Hour
	}
	p := Plugin{ID: "two-factor", factor: &opts, ValidateStore: func(Store) error {
		if opts.TrustDeviceMaxAge < time.Second || opts.ChallengeLifetime < time.Second {
			return errors.New("two-factor cookie lifetimes must be at least one second")
		}
		return nil
	}}
	for _, path := range []string{"/two-factor/enable", "/two-factor/disable", "/two-factor/get-totp-uri", "/two-factor/verify-totp", "/two-factor/verify-backup-code", "/two-factor/generate-backup-codes"} {
		p.Endpoints = append(p.Endpoints, Endpoint{Method: http.MethodPost, Path: path, Handler: func(c EndpointContext) (any, error) {
			return c.Auth.factorEndpoint(path, c)
		}})
	}
	return p
}

func (a *Auth) factorLogin(ctx context.Context, user User, expectedHash string, session StoredSession, signedDevice string) (AuthResult, error) {
	result := AuthResult{}
	subject := FactorSubject{UserID: user.ID, Now: a.now().UTC(), TrustedGrant: a.readTrustedGrant(signedDevice, user.ID)}
	err := a.factorStore.WithTwoFactor(ctx, subject, func(state FactorState) (FactorChange, error) {
		if state.PasswordHash != expectedHash {
			return FactorChange{}, &APIError{401, "INVALID_EMAIL_OR_PASSWORD", "Invalid email or password"}
		}
		if !state.Enabled {
			result = AuthResult{User: state.User, Token: session.Token}
			return FactorChange{Session: &session}, nil
		}
		// An enabled account with unavailable factor material must never fall
		// through to an authenticated session.
		if state.Record == nil || !state.Record.Verified {
			return FactorChange{}, &APIError{403, "TOTP_NOT_CONFIGURED", "TOTP is not available"}
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
		result.TwoFactorMethods = []string{"totp"}
		return FactorChange{CreateChallenge: id, ChallengeExpires: subject.Now.Add(a.factorOptions.ChallengeLifetime)}, nil
	})
	if err != nil {
		return AuthResult{}, err
	}
	return result, nil
}

// TwoFactorChallengeCookie serializes a pending native sign-in result for the
// browser to carry to the verification endpoint. It cannot authenticate GetSession.
func (a *Auth) TwoFactorChallengeCookie(challenge LoginChallenge) *http.Cookie {
	return a.factorCookie(challenge.Identifier, int(a.factorOptions.ChallengeLifetime.Seconds()))
}
func (a *Auth) factorCookie(id string, expires int) *http.Cookie {
	c := a.sessionCookie(id, false)
	c.Name = strings.TrimSuffix(c.Name, "session_token") + "two_factor"
	c.MaxAge = expires
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
	isProof := route == "/two-factor/verify-totp" || route == "/two-factor/verify-backup-code"
	if subject.SessionToken == "" {
		if !isProof {
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
	}
	err := a.factorStore.WithTwoFactor(ctx, subject, decide)

	if errors.Is(err, ErrNotFound) {
		if subject.Challenge != "" {
			return nil, factorCookieError()
		}
		return nil, &APIError{401, "UNAUTHORIZED", "Unauthorized"}
	}
	if err != nil {
		return nil, err
	}
	if op.clearChallenge {
		c.ResponseHeader.Add("Set-Cookie", a.factorCookie("", -1).String())
	}
	if op.denied != nil {
		return nil, op.denied
	}
	if op.trustedCookie != nil {
		c.ResponseHeader.Add("Set-Cookie", op.trustedCookie.String())
	}
	if op.issued != "" {
		a.addSessionCookieHeaders(c.ResponseHeader, r, op.issued, remember)
	}
	return op.out, nil
}

type factorRequest struct {
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
	clearChallenge bool
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
	if state.Record == nil {
		return ch, &APIError{400, "TOTP_NOT_ENABLED", "TOTP not enabled"}
	}
	if p.subject.Challenge != "" && (!state.Enabled || !state.Record.Verified) {
		return ch, factorCookieError()
	}
	if state.Record.LockedUntil != nil && state.Record.LockedUntil.After(p.subject.Now) {
		return ch, &APIError{429, "ACCOUNT_TEMPORARILY_LOCKED", "Too many failed verification attempts. Your account is temporarily locked. Please try again later."}
	}
	record := *state.Record
	if record.LockedUntil != nil {
		record.Failures = 0
		record.LockedUntil = nil
	}
	valid := false
	if p.route == "/two-factor/verify-totp" {
		raw, err := p.auth.openRecord("totp", record.Secret)
		if err != nil {
			return ch, err
		}
		step, matched, err := factorTOTPStep(raw, code, p.subject.Now)
		valid = matched
		if p.subject.Challenge != "" && valid {
			valid = step > state.LastTOTPStep
			if valid {
				ch.UsedTOTPStep = &step
			}
		}
		if err != nil {
			return ch, err
		}
	} else {
		if !state.Enabled || !record.Verified {
			return ch, &APIError{400, "TWO_FACTOR_NOT_ENABLED", "Two factor isn't enabled"}
		}
		items, err := p.auth.readBackupCodes(record.BackupCodes)
		if err != nil {
			return ch, err
		}
		for i, s := range items {
			if subtle.ConstantTimeCompare([]byte(s), []byte(code)) == 1 {
				valid = true
				items = append(items[:i], items[i+1:]...)
				record.BackupCodes, err = p.auth.storeBackupCodes(items)
				if err != nil {
					return ch, err
				}
				break
			}
		}
	}
	if !valid {
		record.Failures++
		if record.Failures >= 10 {
			until := p.subject.Now.Add(15 * time.Minute)
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
	activating := !record.Verified
	record.Verified = true
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
		ss, raw := p.auth.newSession(state.User.ID, p.meta)
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
	if p.route == "/two-factor/enable" {
		if method, ok := p.body["method"]; ok && method != "totp" {
			return ch, &APIError{400, "OTP_NOT_CONFIGURED", "Choose the authenticator app method"}
		}
		if state.Enabled {
			return ch, &APIError{400, "TOTP_ALREADY_ENABLED", "TOTP is already enabled"}
		}
		secret := rand.Text()
		encrypted, err := p.auth.sealRecord("totp", []byte(secret))
		if err != nil {
			return ch, err
		}
		codes := generateBackupCodes()
		backups, err := p.auth.storeBackupCodes(codes)
		if err != nil {
			return ch, err
		}
		ch.SaveRecord = &FactorRecord{ID: randomID(), Secret: encrypted, BackupCodes: backups}
		issuer := p.auth.factorOptions.Issuer
		if v, ok := p.body["issuer"].(string); ok && v != "" {
			issuer = v
		}
		p.out = map[string]any{"method": "totp", "totpURI": factorURI(issuer, state.User.Email, []byte(secret)), "backupCodes": codes}
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
		ss, raw := p.auth.newSession(state.User.ID, p.meta)
		ch.Session = &ss
		p.issued = raw
		p.out = map[string]bool{"status": true}
	case "/two-factor/get-totp-uri":
		raw, err := p.auth.openRecord("totp", state.Record.Secret)
		if err != nil {
			return ch, err
		}
		p.out = map[string]string{"totpURI": factorURI(p.auth.factorOptions.Issuer, state.User.Email, raw)}
	case "/two-factor/generate-backup-codes":
		if !state.Enabled || !state.Record.Verified {
			return ch, &APIError{400, "TWO_FACTOR_NOT_ENABLED", "Two factor isn't enabled"}
		}
		codes := generateBackupCodes()
		record := *state.Record
		record.BackupCodes, err = p.auth.storeBackupCodes(codes)
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
func generateBackupCodes() []string {
	codes := make([]string, 10)
	for i := range codes {
		s := strings.ToLower(rand.Text()[:10])
		codes[i] = s[:5] + "-" + s[5:]
	}
	return codes
}
func (a *Auth) storeBackupCodes(codes []string) (string, error) {
	raw, err := json.Marshal(codes)
	if err != nil {
		return "", err
	}
	return a.sealRecord("backup-codes", raw)
}
func (a *Auth) readBackupCodes(data string) ([]string, error) {
	raw, err := a.openRecord("backup-codes", data)
	if err != nil {
		return nil, err
	}
	var codes []string
	err = json.Unmarshal(raw, &codes)
	return codes, err
}
func factorURI(issuer, email string, secret []byte) string {
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	q := url.Values{"secret": {encoded}, "issuer": {issuer}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape(issuer) + ":" + url.PathEscape(email) + "?" + q.Encode()
}

// Match a six-digit RFC 6238 value and identify its time step so independent
// login challenges cannot spend the same authenticator value twice.
func factorTOTPStep(raw []byte, code string, now time.Time) (int64, bool, error) {
	if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
		return 0, false, nil
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	for _, offset := range []time.Duration{0, -30 * time.Second, 30 * time.Second} {
		at := now.Add(offset)
		valid, err := totp.ValidateCustom(code, secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err != nil || valid {
			return at.Unix() / 30, valid, err
		}
	}
	return 0, false, nil
}
