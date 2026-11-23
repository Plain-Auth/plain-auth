package organization

import (
	"context"
	"errors"
	"net/http"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
)

// UpdateMemberRoleRequest replaces all roles on one membership. An empty
// OrganizationID selects the actor's current session organization.
type UpdateMemberRoleRequest struct {
	OrganizationID string
	MemberID       string
	Roles          []string
}

type MemberRoleStore interface {
	UpdateOrganizationMemberRole(ctx context.Context, userID, sessionToken string, request UpdateMemberRoleRequest) (*Member, error)
}

// MemberRoleQuery selects an organization by slug, ID, or current session, in
// that order. An empty UserID selects the signed-in user's own membership.
type MemberRoleQuery struct {
	OrganizationSlug, OrganizationID, UserID string
}

// MemberRoleReader requires both users to belong to the resolved organization
// at the time of the read.
type MemberRoleReader interface {
	OrganizationMemberRole(ctx context.Context, sessionID, actorID string, query MemberRoleQuery) (string, error)
}

func (o Options) readMemberRoleEndpoint(store MemberRoleReader) auth.Endpoint {
	endpoint := o.endpoint(http.MethodGet, "get-active-member-role", func(c auth.EndpointContext, s *auth.SessionResult) (any, error) {
		q := c.Request.URL.Query()
		query := MemberRoleQuery{UserID: q.Get("userId"), OrganizationID: q.Get("organizationId"), OrganizationSlug: q.Get("organizationSlug")}
		role, err := store.OrganizationMemberRole(c.Request.Context(), s.Session.ID, s.User.ID, query)
		if err != nil {
			return nil, err
		}
		return map[string]string{"role": role}, nil
	})
	// Reject ambiguous selectors before running session middleware.
	authenticated := endpoint.Handler
	endpoint.Handler = func(c auth.EndpointContext) (any, error) {
		q := c.Request.URL.Query()
		var issues []string
		for _, key := range []string{"userId", "organizationId", "organizationSlug"} {
			if len(q[key]) > 1 {
				issues = append(issues, "[query."+key+"] Invalid input: expected string, received array")
			}
		}
		if len(issues) != 0 {
			return nil, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: strings.Join(issues, "; ")}
		}
		return authenticated(c)
	}
	return endpoint
}

var (
	ErrRoleReadDenied    = problem(403, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION", "You are not a member of this organization")
	ErrMemberRoleDenied  = problem(403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER", "You are not allowed to update this member")
	ErrSoleOwnerDemotion = problem(400, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER", "You cannot leave the organization without an owner")
	ErrEmptyRole         = auth.StatusOnlyError(http.StatusBadRequest)
)

// NormalizedRoles splits comma-separated entries and keeps their submitted order.
func (r UpdateMemberRoleRequest) NormalizedRoles() []string {
	return NormalizeRoles(r.Roles...)
}

// NormalizeRoles splits stored or submitted role lists, trims whitespace, and
// preserves the order of nonempty entries.
func NormalizeRoles(roles ...string) []string {
	var normalized []string
	for _, entry := range roles {
		for role := range strings.SplitSeq(entry, ",") {
			if role = strings.TrimSpace(role); role != "" {
				normalized = append(normalized, role)
			}
		}
	}
	return normalized
}

// UpdateMemberRole authorizes an authenticated actor against the current
// session and membership inside the same transaction as the update.
func (service *Service) UpdateMemberRole(ctx context.Context, session auth.Session, request UpdateMemberRoleRequest) (*Member, error) {
	store, ok := service.options.Store.(MemberRoleStore)
	if !ok {
		return nil, errors.New("organization: store does not support member role updates")
	}
	if session.IsApplicationCredential() || session.UserID == "" || session.Token == "" {
		return nil, ErrUnauthenticated
	}
	if err := session.RequireOwner(); err != nil {
		return nil, err
	}
	return store.UpdateOrganizationMemberRole(ctx, session.UserID, session.Token, request)
}

func (service *Service) memberRoleEndpoint() auth.Endpoint {
	return service.options.endpoint(http.MethodPost, "update-member-role", func(c auth.EndpointContext, s *auth.SessionResult) (any, error) {
		id, ok := c.Body["memberId"].(string)
		if !ok {
			return nil, validation("memberId")
		}
		group, ok := c.Body["organizationId"].(string)
		if _, provided := c.Body["organizationId"]; provided && !ok {
			return nil, validation("organizationId")
		}
		request := UpdateMemberRoleRequest{MemberID: id, OrganizationID: group}
		switch value := c.Body["role"].(type) {
		case string:
			if value == "" {
				return nil, ErrEmptyRole
			}
			request.Roles = []string{value}
		case []any:
			for _, value := range value {
				role, ok := value.(string)
				if !ok {
					return nil, validation("role")
				}
				request.Roles = append(request.Roles, role)
			}
		default:
			return nil, validation("role")
		}
		return service.UpdateMemberRole(c.Request.Context(), s.Session, request)
	})
}
