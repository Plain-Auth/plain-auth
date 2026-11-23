package organization

import (
	"context"
	"errors"
	"net/http"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/jsjson"
)

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
		inv, err := store.RejectOrganizationInvitation(c.Request.Context(), session.Session, id, o.RequireVerifiedEmail)
		switch {
		case errors.Is(err, ErrInvitation):
			return nil, problem(400, ErrInvitation.Code, "Invitation not found!")
		case errors.Is(err, ErrUnverified):
			return nil, problem(403, ErrUnverified.Code, "Email verification required before accepting or rejecting invitation")
		case err != nil:
			return nil, err
		}
		var row any = *inv
		if o.Teams != nil {
			row = teamInvitationRow{Invitation: *inv, TeamID: inv.TeamID}
		} else if inv.TeamID != nil {
			plain := *inv
			plain.TeamID = nil
			row = plain
		}
		return map[string]any{"invitation": row, "member": nil}, nil
	}}
}
