package organization

import (
	"context"
	"errors"
	"net/http"

	auth "github.com/Plain-Auth/plain-auth"
)

type InvitationDetails struct {
	ReceivedInvitation
	OrganizationSlug string `json:"organizationSlug"`
	InviterEmail     string `json:"inviterEmail"`
}

type InvitationDetailsStore interface {
	OrganizationInvitation(ctx context.Context, sessionID, userID, invitationID string, requireVerified, includeTeams bool) (*InvitationDetails, error)
}

var (
	ErrInvitationSignIn = problem(401, "", "Not authenticated")
	ErrInviterRemoved   = problem(400, "INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION", "Inviter is no longer a member of the organization")
)

func (o Options) invitationDetailsEndpoint(store InvitationDetailsStore) auth.Endpoint {
	return auth.Endpoint{Method: http.MethodGet, Path: "/organization/get-invitation", Handler: func(c auth.EndpointContext) (any, error) {
		ids := c.Request.URL.Query()["id"]
		if len(ids) != 1 {
			reason := "undefined"
			if len(ids) > 1 {
				reason = "array"
			}
			return nil, problem(400, "VALIDATION_ERROR", "[query.id] Invalid input: expected string, received "+reason)
		}
		s, err := endpointSession(c, http.MethodGet, "get-invitation")
		if errors.Is(err, ErrUnauthenticated) {
			return nil, ErrInvitationSignIn
		}
		if err != nil {
			return nil, err
		}
		result, err := store.OrganizationInvitation(c.Request.Context(), s.Session.ID, s.User.ID, ids[0], o.RequireVerifiedEmail, o.Teams != nil)
		if err != nil || o.Teams == nil {
			return result, err
		}
		return struct {
			*InvitationDetails
			TeamID *string `json:"teamId"`
		}{result, result.TeamID}, nil
	}}
}
