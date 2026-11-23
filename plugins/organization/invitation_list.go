package organization

import (
	"context"
	"net/http"

	auth "github.com/Plain-Org/plain-auth"
)

type InvitationListStore interface {
	ListOrganizationInvitations(ctx context.Context, sessionID, userID, organizationID string, includeTeams bool) ([]Invitation, error)
}

var (
	ErrInvitationOrganizationRequired = problem(400, "", "Organization ID is required")
	ErrInvitationListNonmember        = problem(403, "", "You are not a member of this organization")
	ErrInvitationListDenied           = problem(403, "YOU_ARE_NOT_ALLOWED_TO_LIST_INVITATIONS", "You are not allowed to list invitations for this organization")
)

// A team-enabled schema distinguishes an org-wide (null) teamId from a
// schema without a teamId field. The Go client uses nil for both cases.
type teamInvitationRow struct {
	Invitation
	TeamID *string `json:"teamId"`
}

func teamInvitationRows(invitations []Invitation) []teamInvitationRow {
	items := make([]teamInvitationRow, len(invitations))
	for i, inv := range invitations {
		items[i] = teamInvitationRow{Invitation: inv, TeamID: inv.TeamID}
	}
	return items
}

func (o Options) invitationListEndpoint(store InvitationListStore) auth.Endpoint {
	return auth.Endpoint{Method: http.MethodGet, Path: "/organization/list-invitations", Handler: func(c auth.EndpointContext) (any, error) {
		query := c.Request.URL.Query()
		if len(query["organizationId"]) > 1 {
			return nil, problem(400, "VALIDATION_ERROR", "[query.organizationId] Invalid input: expected string, received array")
		}
		s, err := endpointSession(c, http.MethodGet, "list-invitations")
		if err != nil {
			return nil, err
		}
		list, err := store.ListOrganizationInvitations(c.Request.Context(), s.Session.ID, s.User.ID, query.Get("organizationId"), o.Teams != nil)
		if err != nil {
			return nil, err
		}
		if o.Teams != nil {
			return teamInvitationRows(list), nil
		}
		return list, nil
	}}
}
