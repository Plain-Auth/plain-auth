package organization

import (
	"context"
	"errors"
	"net/http"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/jsjson"
)

// InvitationReplacementStore issues a fresh grant and cancels the previous
// live invitation for the same mailbox and organization in one transaction.
type InvitationReplacementStore interface {
	ReplaceOrganizationInvitation(ctx context.Context, inv Invitation, sessionID string) (Invitation, error)
}

// InvitationRejectionStore verifies the live owner session and mailbox in the
// transaction that declines the invitation.
type InvitationRejectionStore interface {
	RejectOrganizationInvitation(ctx context.Context, actor auth.Session, id string, requireVerified bool) (*Invitation, error)
}

func invitationAction(c auth.EndpointContext, action string) (string, *auth.SessionResult, error) {
	value, exists := c.Body["invitationId"]
	id, ok := value.(string)
	if !ok {
		kind := "undefined"
		if exists {
			kind = jsjson.TypeName(value)
		}
		return "", nil, problem(400, "VALIDATION_ERROR", "[body.invitationId] Invalid input: expected string, received "+kind)
	}
	session, err := endpointSession(c, http.MethodPost, action)
	return id, session, err
}

func (o Options) rejectInvitationEndpoint(store InvitationRejectionStore) auth.Endpoint {
	return auth.Endpoint{Method: http.MethodPost, Path: "/organization/reject-invitation", Handler: func(c auth.EndpointContext) (any, error) {
		id, session, err := invitationAction(c, "reject-invitation")
		if err != nil {
			return nil, err
		}
		var inv *Invitation
		if o.BeforeRejectInvitation != nil || o.AfterRejectInvitation != nil {
			inv, err = o.observedInvitation(c.Request.Context(), session, id, RejectInvitation, o.BeforeRejectInvitation, o.AfterRejectInvitation)
		} else {
			inv, err = store.RejectOrganizationInvitation(c.Request.Context(), session.Session, id, o.RequireVerifiedEmail)
		}
		switch {
		case errors.Is(err, ErrInvitation):
			return nil, problem(400, ErrInvitation.Code, "Invitation not found!")
		case errors.Is(err, ErrUnverified):
			return nil, problem(403, ErrUnverified.Code, "Email verification required before accepting or rejecting invitation")
		case err != nil:
			return nil, err
		}
		return map[string]any{"invitation": o.invitationRow(*inv), "member": nil}, nil
	}}
}

func (o Options) invitationRow(inv Invitation) any {
	if o.Teams != nil {
		return teamInvitationRow{Invitation: inv, TeamID: inv.TeamID}
	}
	inv.TeamID = nil
	return inv
}

// InvitationCancellationStore checks the acting member's live role in the
// invitation's organization before recording cancellation.
type InvitationCancellationStore interface {
	CancelOrganizationInvitation(ctx context.Context, actor auth.Session, id string) (*Invitation, error)
}

var ErrCancelDenied = problem(403, "YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION", "You are not allowed to cancel this invitation")

func (o Options) cancelInvitationEndpoint(store InvitationCancellationStore) auth.Endpoint {
	return auth.Endpoint{Method: http.MethodPost, Path: "/organization/cancel-invitation", Handler: func(c auth.EndpointContext) (any, error) {
		id, session, err := invitationAction(c, "cancel-invitation")
		if err != nil {
			return nil, err
		}
		var inv *Invitation
		if o.BeforeCancelInvitation != nil || o.AfterCancelInvitation != nil {
			inv, err = o.observedInvitation(c.Request.Context(), session, id, CancelInvitation, o.BeforeCancelInvitation, o.AfterCancelInvitation)
		} else {
			inv, err = store.CancelOrganizationInvitation(c.Request.Context(), session.Session, id)
		}
		if err != nil {
			return nil, err
		}
		return o.invitationRow(*inv), nil
	}}
}
