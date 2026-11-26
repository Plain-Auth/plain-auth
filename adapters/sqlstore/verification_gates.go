package sqlstore

import op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"

var _ op.AuthorizationCodeGater = (*Store)(nil)

// GatesAuthorizationCodes marks the store as one whose authorization code
// methods ask the request's VerificationGate.
func (*Store) GatesAuthorizationCodes() {}
