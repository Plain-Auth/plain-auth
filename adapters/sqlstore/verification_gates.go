package sqlstore

import (
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/plugins/sso"
)

var (
	_ op.AuthorizationCodeGater = (*Store)(nil)
	_ sso.VerificationGater     = (*Store)(nil)
)

// GatesSSOVerifications marks the store as one whose SSO methods ask the
// request's VerificationGate.
func (*Store) GatesSSOVerifications() {}

// GatesAuthorizationCodes marks the store as one whose authorization code
// methods ask the request's VerificationGate.
func (*Store) GatesAuthorizationCodes() {}
