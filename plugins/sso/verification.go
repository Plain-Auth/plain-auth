package sso

import (
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// VerificationGater is a Store whose SSO methods ask the request's
// plainauth.VerificationGate before they write a verification record, so that
// the records' database hooks run outside the store's transactions. New
// requires it for verification hooks with SAML single logout or SSO domain
// verification. Following the gate's rules:
//   - a SAML sign-in that stores a logout binding asks Create with
//     LogoutSessionRecord once the session row is stored as planned, and on
//     a decline signs in without one;
//   - StartSAMLLogout asks Create with LogoutRequestRecord and Delete with
//     the binding's LogoutSessionRecord after its checks; a declined request
//     is not stored, a declined binding is kept, and the session ends either
//     way;
//   - ConsumeSAMLLogout asks Delete with LogoutRequestRecord once the
//     response matched; a decline returns ErrSAMLLogoutResponse and keeps the
//     request;
//   - RevokeSAMLIDPSessions asks Delete for every binding it would remove,
//     after its replay check, and keeps a declined binding while its session
//     still ends;
//   - RefreshSession reports an extended binding with Update, carrying the
//     renewed expiry;
//   - CreateSSODomainProvider and SSODomainChallenge ask Create with
//     DomainChallengeRecord before they store a new token, dated from the
//     gate's Now. A declined token is returned but not stored: registration
//     still stores the provider as pending, and a declined reissue writes
//     nothing.
type VerificationGater interface{ GatesSSOVerifications() }

// LogoutSessionRecord is a SAML logout binding as a verification record: the
// link single logout keeps between a SAML sign-in's session and the IdP
// session that issued it. id is the stored row's ID. It names the session's
// user and never carries the NameID, SessionIndex or token digest the row
// stores.
func LogoutSessionRecord(id, userID string, expiresAt time.Time) auth.VerificationRecord {
	return auth.VerificationRecord{ID: id, Identifier: "saml-logout-session", UserID: userID, ExpiresAt: expiresAt.UTC().Truncate(time.Millisecond)}
}

// LogoutRequestRecord is a pending SP-initiated logout as a verification
// record. It binds a browser rather than an account, so it names no owner, and
// it never carries the request ID, RelayState, browser digest or return URL.
func LogoutRequestRecord(id string, expiresAt time.Time) auth.VerificationRecord {
	return auth.VerificationRecord{ID: id, Identifier: "saml-logout-request", ExpiresAt: expiresAt.UTC().Truncate(time.Millisecond)}
}

// DomainChallengeRecord is a provider's DNS verification token as a
// verification record. It proves a domain rather than an account, so it names
// no owner, and it never carries the token or the DNS name it is published at.
func DomainChallengeRecord(id string, expiresAt time.Time) auth.VerificationRecord {
	return auth.VerificationRecord{ID: id, Identifier: "sso-domain-verification", ExpiresAt: expiresAt.UTC().Truncate(time.Millisecond)}
}
