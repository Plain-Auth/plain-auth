package sso

import (
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// VerificationGater is a Store whose SSO methods ask the request's
// plainauth.VerificationGate before they write a verification record, so that
// the records' database hooks run outside the store's transactions. New
// requires it for verification hooks with SSO domain verification. Following
// the gate's rules, CreateSSODomainProvider and SSODomainChallenge ask Create
// with DomainChallengeRecord before they store a new token, dated from the
// gate's Now. A declined token is returned but not stored: registration still
// stores the provider as pending, and a declined reissue writes nothing.
type VerificationGater interface{ GatesSSOVerifications() }

// DomainChallengeRecord is a provider's DNS verification token as a
// verification record. It proves a domain rather than an account, so it names
// no owner, and it never carries the token or the DNS name it is published at.
func DomainChallengeRecord(id string, expiresAt time.Time) auth.VerificationRecord {
	return auth.VerificationRecord{ID: id, Identifier: "sso-domain-verification", ExpiresAt: expiresAt.UTC().Truncate(time.Millisecond)}
}
