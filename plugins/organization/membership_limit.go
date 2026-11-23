package organization

import (
	"context"
	"errors"

	auth "github.com/Plain-Auth/plain-auth"
)

// MembershipLimit controls admission to an organization. Set Maximum for a
// fixed limit or Resolve to decide from the candidate account and destination.
// An empty policy uses 100. Returning zero from Resolve denies admission.
type MembershipLimit struct {
	Maximum int
	Resolve func(context.Context, auth.User, Organization) (int, error)
}

func (p MembershipLimit) Validate() error {
	if p.Maximum < 0 || (p.Maximum != 0 && p.Resolve != nil) {
		return errors.New("organization: choose a nonnegative fixed membership limit or a resolver")
	}
	return nil
}

// DefaultPageSize is also the fixed admission limit when Resolve is nil.
func (p MembershipLimit) DefaultPageSize() int {
	if p.Maximum > 0 {
		return p.Maximum
	}
	return 100
}

// MembershipLimitStoreProvider gives each service its own admission policy.
// The returned store must apply it atomically to direct grants and accepted invitations.
type MembershipLimitStoreProvider interface {
	WithOrganizationMembershipLimit(MembershipLimit) (Store, error)
}

// ErrMembershipPolicyChanged leaves the grant uncommitted when the candidate
// or destination has changed while the application was resolving a limit.
var ErrMembershipPolicyChanged = problem(409, "MEMBERSHIP_POLICY_INPUT_CHANGED", "Membership policy inputs changed. Retry the request.")
