package plainauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
)

// EmailVerificationAttempt is a validated ordinary address proof. A nil NewSession
// requests verification only. ExistingToken, when present, came from a signed
// browser cookie. ProofID is a digest of the signed proof, never the raw link.
type EmailVerificationAttempt struct {
	ProfileUpdatedAtMillis                 *int64
	OwnerID, Email, ProofID, ExistingToken string
	Now, IssuedAt, ExpiresAt               time.Time
	NewSession                             *StoredSession
	// The explicit OTP sign-in route issues a new session even for its current owner.
	AlwaysCreateSession bool
}

// MatchesProfileRevision checks the signed profile revision before issuing a
// browser session. Older proofs have only a whole-second issue time. Within
// that second, only an account whose original profile is unchanged qualifies.
func (v EmailVerificationAttempt) MatchesProfileRevision(created, updated time.Time) bool {
	if v.IssuedAt.IsZero() || created.IsZero() || updated.IsZero() {
		return false
	}
	if v.ProfileUpdatedAtMillis != nil {
		return updated.UnixMilli() == *v.ProfileUpdatedAtMillis
	}
	if !updated.After(v.IssuedAt) {
		return true
	}
	return created.Equal(updated) && created.Truncate(time.Second).Equal(v.IssuedAt)
}

// EmailVerificationSessionStore atomically verifies the exact owner and address
// and spends the proof until expiry. A first eligible browser verification may
// return a direct existing token for that owner or insert the requested session.
// Replays, active bans, MFA enrollment and restricted sessions return no token.
// A missing or reassigned owner/address returns ErrNotFound.
type EmailVerificationSessionStore interface {
	CompleteEmailVerification(context.Context, EmailVerificationAttempt) (string, error)
}

func (a *Auth) consumeVerification(ctx context.Context, claims verificationClaims, raw string, browser *http.Request) (string, bool, error) {
	// Digest the authenticated header and payload; signature encoding aliases
	// represent the same proof. parseEmailProof has already verified the signature.
	signed := raw[:strings.LastIndexByte(raw, '.')]
	digest := sha256.Sum256([]byte(signed))
	v := EmailVerificationAttempt{OwnerID: claims.UserID, Email: claims.Email, ProfileUpdatedAtMillis: claims.ProfileUpdatedAtMillis,
		ProofID: base64.RawURLEncoding.EncodeToString(digest[:]), Now: a.now().UTC(), ExpiresAt: claims.ExpiresAt.Time}
	if claims.IssuedAt != nil {
		v.IssuedAt = claims.IssuedAt.Time
		if v.IssuedAt.After(v.Now) {
			return "", false, &APIError{401, "INVALID_TOKEN", "Invalid token"}
		}
	}
	if a.opts.AutoSignInAfterVerification && browser != nil {
		if existing, ok := a.verificationBrowserCredential(ctx, browser); ok {
			v.ExistingToken = existing
			row, _ := a.newSession(v.OwnerID, RequestMeta{IPAddress: a.clientIP(browser), UserAgent: browser.UserAgent()})
			v.NewSession = &row
		}
	}
	var token string
	var err error
	if a.hasVerificationObservers() {
		token, err = a.observeAddressVerification(ctx, v, browser)
	} else {
		token, err = a.opts.Store.(EmailVerificationSessionStore).CompleteEmailVerification(ctx, v)
	}
	if errors.Is(err, ErrNotFound) {
		err = &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	created := v.NewSession != nil && token != "" && token == v.NewSession.Token
	return token, created, err
}

func (a *Auth) verifyEmailBrowser(r *http.Request, h http.Header, claims verificationClaims, raw string) error {
	token, created, err := a.consumeVerification(r.Context(), claims, raw, r)
	if err != nil || token == "" {
		return err
	}
	persistent := !a.dontRemember(r)
	err = a.addSessionCookieHeaders(h, r, token, persistent)
	if err != nil {
		if created {
			return a.discardUnpublishedSession(r.Context(), token, err)
		}
		return err
	}
	a.writeRememberPreference(h, r, persistent)
	return nil
}

// Only a direct browser session, or a browser without credentials, can receive
// a login from mailbox verification. The store checks live session authority.
func (a *Auth) verificationBrowserCredential(ctx context.Context, r *http.Request) (string, bool) {
	if ctx.Value(credentialSessionKey{a}) != nil || r.Header.Get("Authorization") != "" {
		return "", false
	}
	cookies := r.CookiesNamed(a.cookieName())
	var token string
	if len(cookies) == 1 {
		token = a.VerifySignedSessionToken(cookies[0].Value)
	}
	return token, (len(cookies) == 0 || len(cookies) == 1 && token != "") && a.cookieToken(r.Header) == token
}

func (a *Auth) discardUnpublishedSession(ctx context.Context, token string, cause error) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return errors.Join(cause, a.opts.Store.DeleteSession(cleanup, token))
}
