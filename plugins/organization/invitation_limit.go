package organization

import (
	"context"
	"errors"

	auth "github.com/Plain-Org/plain-auth"
)

// InvitationLimit controls the number of live pending invitations in one
// organization. A nil option uses 100. An explicit Maximum of zero prevents issuance.
type InvitationLimit struct {
	Maximum int
	Resolve func(context.Context, InvitationLimitInput) (int, error)
}

type InvitationLimitInput struct {
	User         auth.User
	Organization Organization
	Member       Member
}

func (p InvitationLimit) Validate() error {
	if p.Maximum < 0 || p.Maximum != 0 && p.Resolve != nil {
		return errors.New("organization: choose a nonnegative invitation limit or a resolver")
	}
	return nil
}

type InvitationLimitStoreProvider interface {
	WithOrganizationInvitationLimit(InvitationLimit) (Store, error)
}

var (
	ErrInvitationLimit        = problem(403, "INVITATION_LIMIT_REACHED", "Invitation limit reached")
	ErrInvitationLimitChanged = problem(409, "INVITATION_POLICY_INPUT_CHANGED", "Invitation policy inputs changed. Retry the request.")
)
