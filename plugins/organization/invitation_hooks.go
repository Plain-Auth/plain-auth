package organization

import (
	"context"
	"encoding/json"
	"errors"

	auth "github.com/Plain-Auth/plain-auth"
)

// InvitationDecision identifies a recipient rejection or an administrative cancellation.
type InvitationDecision string

const (
	RejectInvitation InvitationDecision = "rejected"
	CancelInvitation InvitationDecision = "canceled"
)

// InvitationDecisionEvent contains the acting account, the destination, and
// the invitation as observed before or after the decision.
type InvitationDecisionEvent struct {
	Invitation   Invitation
	Organization Organization
	Actor        auth.User
	// Member is populated after acceptance commits.
	Member *Member
}

type InvitationDecisionHook func(context.Context, InvitationDecisionEvent) error

// ObservedInvitationDecisionStore releases database locks before invoking
// before and revalidates the authorized snapshot before committing. It calls
// before at most once and returns the committed event.
type ObservedInvitationDecisionStore interface {
	InvitationRejectionStore
	InvitationCancellationStore
	ObserveInvitationDecision(ctx context.Context, session auth.Session, id string, decision InvitationDecision, requireVerified bool, before InvitationDecisionHook) (*InvitationDecisionEvent, error)
}

// ObservedInvitationAcceptanceStore checks eligibility before the hook, releases
// database locks while it runs, then commits membership, teams and selection together.
type ObservedInvitationAcceptanceStore interface {
	ObserveInvitationAcceptance(ctx context.Context, session auth.Session, id string, requireVerified bool, before InvitationDecisionHook) (*InvitationDecisionEvent, error)
}

var ErrInvitationDecisionChanged = problem(409, "INVITATION_DECISION_CHANGED", "The invitation decision inputs changed. Retry the request.")

// The store supplies the current core profile. Include the plugin and public
// application fields from the authenticated request. A hook owns its copy.
func decisionHook(hook InvitationDecisionHook, user auth.User) InvitationDecisionHook {
	if hook == nil {
		return nil
	}
	return func(ctx context.Context, event InvitationDecisionEvent) error {
		profile := user
		core := event.Actor
		if profile.ID != core.ID || !profile.CreatedAt.Equal(core.CreatedAt) {
			return ErrUnauthenticated
		}
		profile.ID, profile.Name, profile.Email, profile.EmailVerified = core.ID, core.Name, core.Email, core.EmailVerified
		profile.Image, profile.CreatedAt, profile.UpdatedAt = core.Image, core.CreatedAt, core.UpdatedAt
		event.Actor = profile
		encoded, err := json.Marshal(event)
		if err != nil {
			return err
		}
		var detached InvitationDecisionEvent
		if err := json.Unmarshal(encoded, &detached); err != nil {
			return err
		}
		return hook(ctx, detached)
	}
}

func (o Options) observedInvitation(ctx context.Context, session *auth.SessionResult, id string, decision InvitationDecision, before, after InvitationDecisionHook) (*Invitation, error) {
	store := o.Store.(ObservedInvitationDecisionStore)
	event, err := store.ObserveInvitationDecision(ctx, session.Session, id, decision, o.RequireVerifiedEmail, decisionHook(before, session.User))
	if err != nil {
		return nil, err
	}
	if after != nil {
		if err := decisionHook(after, session.User)(ctx, *event); err != nil {
			return nil, err
		}
	}
	return &event.Invitation, nil
}

func (o Options) acceptWithHooks(ctx context.Context, session *auth.SessionResult, id string) (Invitation, Member, error) {
	store := o.Store.(ObservedInvitationAcceptanceStore)
	event, err := store.ObserveInvitationAcceptance(ctx, session.Session, id, o.RequireVerifiedEmail, decisionHook(o.BeforeAcceptInvitation, session.User))
	if err != nil {
		return Invitation{}, Member{}, err
	}
	if event == nil || event.Member == nil {
		return Invitation{}, Member{}, errors.New("organization: acceptance store returned no committed member")
	}
	if after := decisionHook(o.AfterAcceptInvitation, session.User); after != nil {
		if err := after(ctx, *event); err != nil {
			return Invitation{}, Member{}, err
		}
	}
	return event.Invitation, *event.Member, nil
}
