package scim

import (
	"context"
	"errors"
)

// Identity links incoming directory Users to existing accounts.
type Identity struct {
	// ResolveUser decides whether POST /Users creates an account or links an
	// existing one. It runs before the directory transaction, so it may read
	// through the store or the application's database, and not at all for a
	// POST whose externalId reclaims an inactive SCIM User or a deleted
	// User's account. Never link by an unverified email match. An error, a
	// panic or an invalid decision answers 500 with "SCIM identity
	// resolution failed"; a *Error is answered as is.
	ResolveUser func(context.Context, IdentityResolutionInput) (IdentityResolution, error)
}

// IdentityResolutionInput is the incoming User ResolveUser maps to an
// account. Resource is a copy of the normalized User: userName,
// displayName, externalId, primary email, active and the canonical
// attributes.
type IdentityResolutionInput struct {
	ConnectionID, ProvisioningDomainID string
	Resource                           Profile
}

// IdentityResolution is a ResolveUser decision. The zero value, or Action
// "create", creates an account managed by the source. Action "link"
// attaches the source to the existing account UserID; Profile "manage" lets
// this source own the account's email and name and "preserve" leaves them
// unchanged. Only one source manages an account.
type IdentityResolution struct {
	Action, UserID, Profile string
}

func (r IdentityResolution) valid() bool {
	switch r.Action {
	case "", "create":
		return true
	case "link":
		return identifier(r.UserID) && (r.Profile == "manage" || r.Profile == "preserve")
	}
	return false
}

// IdentityStore applies a resolver's decision.
type IdentityStore interface {
	// SCIMReuse reports, outside any write, whether creating p reclaims an
	// inactive SCIM User or a deleted User's account through its
	// externalId, so that no resolver runs; it returns ErrConflict when an
	// active SCIM User holds that externalId or the userName is taken.
	SCIMReuse(ctx context.Context, d Directory, p Profile) (bool, error)
	// SCIMCreateResolved is SCIMCreate with a resolver's decision; a link to
	// a missing account returns ErrResolvedUserMissing and a link the data no
	// longer allows, such as an externalId reclaimed meanwhile, ErrConflict.
	SCIMCreateResolved(ctx context.Context, d Directory, p Profile, r IdentityResolution) (Record, error)
}

// ErrResolvedUserMissing answers a link to an account that does not exist.
var ErrResolvedUserMissing = &Error{409, "", "The resolved user does not exist"}

var errIdentityResolution = &Error{500, "", "SCIM identity resolution failed"}

// resolve runs ResolveUser outside any transaction. A *Error passes through;
// any other error, a panic or an invalid decision fails closed without
// logging the decision.
func (h *Handler) resolve(ctx context.Context, d Directory, p Profile) (r IdentityResolution, err error) {
	defer func() {
		if recover() != nil {
			h.host.Logger().ErrorContext(ctx, "scim: identity resolution failed", "connectionId", d.ID)
			r, err = IdentityResolution{}, errIdentityResolution
		}
	}()
	copied, err := normalize(profileObject(p))
	if err != nil {
		return IdentityResolution{}, err
	}
	r, err = h.resolveUser(ctx, IdentityResolutionInput{ConnectionID: d.ID, ProvisioningDomainID: d.ProvisioningDomainID, Resource: copied})
	var se *Error
	if errors.As(err, &se) {
		return IdentityResolution{}, se
	}
	if err != nil || !r.valid() {
		h.host.Logger().ErrorContext(ctx, "scim: identity resolution failed", "connectionId", d.ID)
		return IdentityResolution{}, errIdentityResolution
	}
	return r, nil
}
