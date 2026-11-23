package organization

import (
	"context"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

// InvitationDraft contains the normalized values proposed by the issuing member.
type InvitationDraft struct {
	Email          string   `json:"email"`
	Role           string   `json:"role"`
	OrganizationID string   `json:"organizationId"`
	InviterID      string   `json:"inviterId"`
	TeamIDs        []string `json:"teamIds"`
	TeamID         *string  `json:"teamId,omitempty"` // First targeted team.
}

type InvitationCreationEvent struct {
	Invitation   InvitationDraft `json:"invitation"`
	Organization Organization    `json:"organization"`
	Inviter      auth.User       `json:"inviter"`
}

// InvitationChanges overrides the proposed grant. Nil fields preserve the
// proposal. A non-nil empty TeamIDs removes all team targets.
type InvitationChanges struct {
	Email     *string
	Roles     []string
	TeamIDs   []string
	ExpiresAt *time.Time
}

type InvitationCreationHook func(context.Context, InvitationCreationEvent) (*InvitationChanges, error)

// Apply validates host changes and returns the resulting grant.
func (changes *InvitationChanges) Apply(inv Invitation) (Invitation, error) {
	return (RolePolicy{}).ApplyInvitationChanges(inv, changes)
}

// ApplyInvitationChanges validates the host's final roles against its policy.
func (p RolePolicy) ApplyInvitationChanges(inv Invitation, changes *InvitationChanges) (Invitation, error) {
	if changes == nil {
		return inv, nil
	}
	if changes.Email != nil {
		inv.Email = strings.ToLower(*changes.Email)
		if !invitationEmailPattern.MatchString(inv.Email) {
			return Invitation{}, problem(400, "INVALID_EMAIL", "Invalid email")
		}
	}
	var err error
	if changes.Roles != nil {
		inv.Role, err = p.ParseInvitationRoles(changes.Roles...)
		if err != nil {
			return Invitation{}, err
		}
	}
	if changes.TeamIDs != nil {
		inv.TeamID, err = (InvitationTeamTargets{IDs: changes.TeamIDs}).StoredValue()
		if err != nil {
			return Invitation{}, err
		}
	}
	if changes.ExpiresAt != nil {
		inv.ExpiresAt = changes.ExpiresAt.UTC().Truncate(time.Millisecond)
	}
	return inv, nil
}

// InvitationIssueOptions describes how to handle a pending grant and whether
// the client selected the destination using its current session.
type InvitationIssueOptions struct {
	Resend, Replace       bool
	UseActiveOrganization bool
	// TeamTargets holds the original request when the client supplied teamId.
	TeamTargets *InvitationTeamTargets
}

// PreparedInvitationStore resolves requested teams on fresh grants and keeps
// existing targets on resends. It runs an optional hook outside database locks after
// checking eligibility. It revalidates and commits the final grant atomically.
type PreparedInvitationStore interface {
	IssuePreparedInvitation(context.Context, Invitation, auth.Session, InvitationIssueOptions, InvitationCreationHook) (*InvitationDelivery, error)
}

var ErrInvitationCreationChanged = problem(409, "INVITATION_CREATION_CHANGED", "The invitation inputs changed. Retry the request.")

func (o Options) creationHook(user auth.User) InvitationCreationHook {
	if o.BeforeCreateInvitation == nil {
		return nil
	}
	return func(ctx context.Context, event InvitationCreationEvent) (*InvitationChanges, error) {
		actor, err := invitationActor(user, event.Inviter)
		if err != nil {
			return nil, err
		}
		event.Inviter = actor
		event, err = detachedInvitationEvent(event)
		if err != nil {
			return nil, err
		}
		return o.BeforeCreateInvitation(ctx, event)
	}
}
