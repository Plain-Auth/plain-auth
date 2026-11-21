package frostauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"
	"time"
)

// FactorDelivery is a single-use out-of-band code scoped to an existing login challenge or session.
type FactorDelivery struct {
	ID                   string
	Pending              bool
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
	ss, token := p.auth.newSession(state.User.ID, p.meta)
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
	if !st.Enabled || (st.Record != nil && !st.Record.Verified && !st.Record.hasPendingAuthenticator()) {
		return ch, &APIError{400, "OTP_NOT_ENABLED", "OTP not enabled"}
	}
	if st.Record != nil && !p.auth.factorOptions.Lockout.Disabled && st.Record.LockedUntil != nil && st.Record.LockedUntil.After(p.subject.Now) {
		return ch, &APIError{429, "ACCOUNT_TEMPORARILY_LOCKED", "Too many failed verification attempts. Your account is temporarily locked. Please try again later."}
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
	p.deliveryID = randomID()
	ch.SaveDelivery = &FactorDelivery{ID: p.deliveryID, Pending: true, Stored: stored, CreatedAt: p.subject.Now, ExpiresAt: p.subject.Now.Add(o.Period)}
	p.mail = &FactorOTPMessage{User: st.User, Code: code}
	p.out = map[string]bool{"status": true}
	return ch, nil
}
func (p *factorRequest) checkDelivery(st FactorState, code string, ch *FactorChange) (bool, error) {
	o := p.auth.factorOptions.OTP
	if st.Delivery != nil && st.Delivery.Pending {
		return false, &APIError{400, "OTP_HAS_EXPIRED", "OTP is unavailable"}
	}
	if st.Delivery == nil || !st.Delivery.ExpiresAt.After(p.subject.Now) {
		ch.RemoveDelivery = true
		return false, &APIError{400, "OTP_HAS_EXPIRED", "OTP has expired"}
	}
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

// A send replaces the old proof with a pending row. Publish the new code only
// after the sender succeeds. Its ID prevents a slow sender from replacing a
// more recent code or deleting it after a late failure.
func (p *factorRequest) deliver() error {
	sendErr := p.auth.factorOptions.OTP.Send(p.ctx, *p.mail)
	ctx := p.ctx
	if sendErr != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
	}
	subject := p.subject
	subject.Now = p.auth.now().UTC()
	err := p.auth.factorStore.WithTwoFactor(ctx, subject, func(state FactorState) (FactorChange, error) {
		saved := state.Delivery
		if saved == nil || saved.ID != p.deliveryID || !saved.Pending {
			return FactorChange{}, nil
		}
		if sendErr != nil || !saved.ExpiresAt.After(subject.Now) {
			return FactorChange{RemoveDelivery: true}, nil
		}
		active := *saved
		active.Pending = false
		return FactorChange{SaveDelivery: &active}, nil
	})
	if errors.Is(err, ErrNotFound) && sendErr == nil {
		if subject.Challenge != "" {
			return factorCookieError()
		}
		return &APIError{401, "UNAUTHORIZED", "Unauthorized"}
	}
	return errors.Join(sendErr, err)
}
