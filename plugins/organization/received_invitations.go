package organization

import (
	"context"
	"errors"
	"net/http"

	auth "github.com/Plain-Org/plain-auth"
)

// ReceivedInvitation includes the destination's display name for the recipient.
type ReceivedInvitation struct {
	Invitation
	OrganizationName string `json:"organizationName"`
}

type ReceivedInvitationStore interface {
	ListReceivedInvitations(ctx context.Context, sessionID, userID string, includeTeams bool) ([]ReceivedInvitation, error)
	ListInvitationsForEmail(ctx context.Context, email string, includeTeams bool) ([]ReceivedInvitation, error)
}

var (
	ErrInvitationEmailRequired     = problem(400, "", "Missing session headers, or email query parameter.")
	ErrInvitationAccountUnverified = problem(403, "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION", "Email verification required to view or list invitations for the session email")
)

// ListInvitationsForEmail lists a recipient's pending invitations for trusted
// application code. The HTTP endpoint derives the mailbox from a verified session.
func (s *Service) ListInvitationsForEmail(ctx context.Context, email string) ([]ReceivedInvitation, error) {
	store, ok := s.options.Store.(ReceivedInvitationStore)
	if !ok {
		return nil, errors.New("organization: store does not support recipient invitation lookup")
	}
	return store.ListInvitationsForEmail(ctx, email, s.options.Teams != nil)
}

func (o Options) receivedInvitationsEndpoint(store ReceivedInvitationStore) auth.Endpoint {
	return auth.Endpoint{Method: http.MethodGet, Path: "/organization/list-user-invitations", Handler: func(c auth.EndpointContext) (any, error) {
		v := c.Request.URL.Query()["email"]
		if len(v) > 1 {
			return nil, problem(400, "VALIDATION_ERROR", "[query.email] Invalid input: expected string, received array")
		}
		if len(v) == 1 && v[0] != "" {
			return nil, problem(400, "", "User email cannot be passed for client side API calls.")
		}
		s, err := endpointSession(c, http.MethodGet, "list-user-invitations")
		if errors.Is(err, ErrUnauthenticated) {
			return nil, ErrInvitationEmailRequired
		}
		if err != nil {
			return nil, err
		}
		items, err := store.ListReceivedInvitations(c.Request.Context(), s.Session.ID, s.User.ID, o.Teams != nil)
		if err != nil || o.Teams == nil {
			return items, err
		}
		type row struct {
			teamInvitationRow
			OrganizationName string `json:"organizationName"`
		}
		out := make([]row, len(items))
		for i, inv := range items {
			out[i] = row{teamInvitationRow{inv.Invitation, inv.TeamID}, inv.OrganizationName}
		}
		return out, nil
	}}
}
