package plainauth

import (
	"crypto/subtle"
	"errors"
	"strings"
	"time"
)

// FactorDelivery is a single-use out-of-band code scoped to an existing login challenge or session.
type FactorDelivery struct {
	ID                   string
	Pending              bool // a code an earlier release staged while its sender ran; a guess at it is refused
	Stored               string
	Attempts             int
	CreatedAt, ExpiresAt time.Time
}

func (a *Auth) factorMethods(st FactorState) []string {
	methods := []string{}
	if st.Record != nil && !st.Record.Verified && !st.Record.hasPendingAuthenticator() {
		return methods
	}
	if st.Record != nil && st.Record.Verified && st.Record.Secret != "" && !a.factorOptions.TOTP.Disabled {
		methods = append(methods, "totp")
	}
	if a.factorOptions.OTP.Send != nil {
		methods = append(methods, "otp")
	}
	return methods
}
func (p *factorRequest) enableOTP(state FactorState) (FactorChange, error) {
	var ch FactorChange
	if p.auth.factorOptions.OTP.Send == nil {
		return ch, &APIError{400, "OTP_NOT_CONFIGURED", "OTP is not available"}
	}
	enabled := true
	ch.Enabled = &enabled
	ch.RevokeSessions = true
	if state.Record == nil || !state.Record.Verified {
		ch.SaveRecord = &FactorRecord{ID: randomID(), Verified: true}
	}
	ss, token := p.sessionDraft(state.User.ID)
	ch.Session = &ss
	p.issued = token
	p.out = map[string]string{"method": "otp"}
	return ch, nil
}
func (p *factorRequest) sendOTP(st FactorState) (FactorChange, error) {
	var ch FactorChange
	o := p.auth.factorOptions.OTP
	if o.Send == nil {
		return ch, &APIError{400, "OTP_NOT_CONFIGURED", "OTP is not available"}
	}
	// Only /two-factor/enable with the password enrolls an account; the other
	// runtime sends a code to any session and enrolls it on a verified code.
	if !st.Enabled || (st.Record != nil && !st.Record.Verified && !st.Record.hasPendingAuthenticator()) {
		return ch, &APIError{400, "OTP_NOT_ENABLED", "OTP not enabled"}
	}
	// The lock also refuses a new code; the other runtime keeps no lock here.
	if st.Record != nil && !p.auth.factorOptions.Lockout.Disabled && st.Record.LockedUntil != nil && st.Record.LockedUntil.After(p.subject.Now) {
		return ch, &APIError{429, "ACCOUNT_TEMPORARILY_LOCKED", "Too many failed verification attempts. Your account is temporarily locked. Please try again later."}
	}
	// The code's create before hooks run before it is drawn or transformed.
	switch p.hooks.approval(roleSend, factorRecord("2fa-otp", p.pins.deliveryID, st.User.ID, p.subject.Now.Add(o.Period))) {
	case factorPending:
		return ch, errFactorUnapproved
	case factorDeclined:
		return ch, errFactorSendDeclined
	}
	// Existing databases can represent delivered-code-only enrollment with
	// the user flag alone. Materialize the lockout counter under the owner lock.
	if st.Record == nil {
		ch.SaveRecord = &FactorRecord{ID: randomID(), Verified: true}
	}
	code, err := randomDecimalCode(o.Digits)
	if err != nil {
		return ch, err
	}
	stored := code
	switch o.Store {
	case "hashed":
		if o.Hash != nil {
			stored, err = o.Hash(p.ctx, code)
		} else {
			stored = hashEmailOTP(code)
		}
	case "encrypted":
		if o.Encrypt != nil {
			stored, err = o.Encrypt(p.ctx, code)
		} else {
			stored, err = p.auth.sealRecord("two-factor-otp", []byte(code))
		}
	}
	if err != nil {
		return ch, err
	}
	if stored == "" {
		return ch, errors.New("empty stored factor code")
	}
	ch.SaveDelivery = &FactorDelivery{ID: p.pins.deliveryID, Stored: stored, CreatedAt: p.subject.Now, ExpiresAt: p.subject.Now.Add(o.Period)}
	p.mail = &FactorOTPMessage{User: st.User, Code: code}
	p.out = map[string]bool{"status": true}
	return ch, nil
}
func otpExpired() *APIError { return &APIError{400, "OTP_HAS_EXPIRED", "OTP has expired"} }

// otpUnavailable answers a code still being sent, or sent again since its
// hooks ran, like an expired one.
func otpUnavailable() *APIError { return &APIError{400, "OTP_HAS_EXPIRED", "OTP has expired"} }

// deliveryReady refuses a guess at a code an earlier release left pending,
// and removes one that is missing or expired, before anything compares it.
func (p *factorRequest) deliveryReady(st FactorState, ch *FactorChange) error {
	if st.Delivery != nil && st.Delivery.Pending {
		return otpUnavailable()
	}
	if st.Delivery == nil || !st.Delivery.ExpiresAt.After(p.subject.Now) {
		ch.RemoveDelivery = true
		return otpExpired()
	}
	return nil
}

// checkDelivery removes a code that ran out of attempts and otherwise
// compares the guess with the live code deliveryReady let through.
func (p *factorRequest) checkDelivery(st FactorState, code string, ch *FactorChange) (bool, error) {
	o := p.auth.factorOptions.OTP
	if st.Delivery.Attempts >= o.AllowedAttempts {
		ch.RemoveDelivery = true
		return false, &APIError{400, "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE", "Too many attempts. Please request a new code."}
	}
	got, want := code, st.Delivery.Stored
	var err error
	switch o.Store {
	case "hashed":
		if o.Hash != nil {
			got, err = o.Hash(p.ctx, got)
		} else {
			got = hashEmailOTP(got)
		}
	case "encrypted":
		if o.Decrypt != nil {
			want, err = o.Decrypt(p.ctx, want)
		} else {
			var raw []byte
			raw, err = p.auth.openRecord("two-factor-otp", want)
			want = string(raw)
		}
	}
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
		ch.RemoveDelivery = true
		return true, nil
	}
	next := *st.Delivery
	next.Attempts++
	ch.SaveDelivery = &next
	return false, nil
}

// The old delivered-code enrollment stays active during an authenticator upgrade.
// The marker never authorizes TOTP until its separate verification succeeds.
const pendingAuthenticatorPrefix = "pending-authenticator:"

func (r *FactorRecord) hasPendingAuthenticator() bool {
	return r != nil && strings.HasPrefix(r.Secret, pendingAuthenticatorPrefix)
}
func (a *Auth) openAuthenticator(secret string) ([]byte, error) {
	return a.openRecord("totp", strings.TrimPrefix(secret, pendingAuthenticatorPrefix))
}
