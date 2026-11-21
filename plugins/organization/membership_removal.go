package organization

import (
	"context"
	"net/http"

	auth "github.com/Stonewrit/stonewrit-auth"
)

// MemberUser is the public user returned by email lookup and self-leave.
type MemberUser struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Email string  `json:"email"`
	Image *string `json:"image"`
}

type RemovedMember struct {
	Member
	User *MemberUser `json:"user,omitempty"`
}

type MemberRemovalStore interface {
	RemoveOrganizationMember(ctx context.Context, userID, sessionToken, organizationID, memberIDOrEmail string) (*RemovedMember, error)
	LeaveOrganization(ctx context.Context, userID, sessionToken, organizationID string) (*RemovedMember, error)
}

var (
	ErrMemberMissing = problem(400, "MEMBER_NOT_FOUND", "Member not found")
	ErrLastOwner     = problem(400, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER", "You cannot leave the organization as the only owner")
	ErrMemberRemove  = problem(401, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER", "You are not allowed to delete this member")
)

func (o Options) memberRemovalEndpoints(store MemberRemovalStore) []auth.Endpoint {
	return []auth.Endpoint{
		o.endpoint(http.MethodPost, "remove-member", func(c auth.EndpointContext, s *auth.SessionResult) (any, error) {
			target, ok := c.Body["memberIdOrEmail"].(string)
			if !ok {
				return nil, validation("memberIdOrEmail")
			}
			group, ok := c.Body["organizationId"].(string)
			if _, provided := c.Body["organizationId"]; provided && !ok {
				return nil, validation("organizationId")
			}
			m, err := store.RemoveOrganizationMember(c.Request.Context(), s.User.ID, s.Session.Token, group, target)
			if err != nil {
				return nil, err
			}
			return map[string]any{"member": m}, nil
		}),
		o.endpoint(http.MethodPost, "leave", func(c auth.EndpointContext, s *auth.SessionResult) (any, error) {
			group, ok := c.Body["organizationId"].(string)
			if !ok {
				return nil, validation("organizationId")
			}
			return store.LeaveOrganization(c.Request.Context(), s.User.ID, s.Session.Token, group)
		}),
	}
}
