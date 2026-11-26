package scim

import (
	"context"

	auth "github.com/Plain-Org/plain-auth"
)

// UserExternalIDReference names one connection's User by its exact,
// case-sensitive externalId.
type UserExternalIDReference = auth.SCIMUserReference

// ActiveUserLink is an active SCIM User and the account it links.
type ActiveUserLink struct{ SCIMUserID, UserID string }

// ActiveUserLinkStore finds the account an active SCIM User links, for an
// SSO resolver. The SQL store implements it.
type ActiveUserLinkStore interface {
	// SCIMActiveUserLink returns the active SCIM User with exactly this
	// connection ID and externalId, and its account. It never falls back to
	// userName, email, another connection or a deleted User, and returns
	// ErrNotFound when the User is missing, inactive, tombstoned or orphaned
	// or its connection is retired.
	SCIMActiveUserLink(ctx context.Context, ref UserExternalIDReference) (ActiveUserLink, error)
}
