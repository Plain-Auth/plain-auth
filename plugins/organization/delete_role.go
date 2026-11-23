package organization

import (
	"context"
	"net/http"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
)

// RoleDeletionStore removes an unused stored role after checking the live
// owner's session and its current ac.delete permission.
type RoleDeletionStore interface {
	DeleteOrganizationRole(ctx context.Context, userID, sessionToken string, query RoleQuery) error
}

var (
	ErrDeleteRoleDenied = problem(403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE", "You are not allowed to delete a role")
	ErrPredefinedRole   = problem(400, "CANNOT_DELETE_A_PRE_DEFINED_ROLE", "Cannot delete a pre-defined role")
	ErrRoleAssigned     = problem(400, "ROLE_IS_ASSIGNED_TO_MEMBERS", "Cannot delete a role that is assigned to members. Please reassign the members to a different role first")
)

func deleteRoleEndpoint(store RoleDeletionStore) auth.Endpoint {
	return auth.Endpoint{Method: http.MethodPost, Path: "/organization/delete-role", Handler: func(c auth.EndpointContext) (any, error) {
		group, issues := roleOrganizationInput(c.Body)
		query := RoleQuery{OrganizationID: group}
		if issue := query.selectRole(c.Body["roleName"], c.Body["roleId"], "body"); issue != "" {
			issues = append(issues, issue)
		}
		if len(issues) > 0 {
			return nil, problem(400, "VALIDATION_ERROR", strings.Join(issues, "; "))
		}
		s, err := endpointSession(c, http.MethodPost, "delete-role")
		if err != nil {
			return nil, err
		}
		if _, explicit := c.Body["organizationId"]; explicit && query.OrganizationID == "" {
			return nil, ErrNoActiveOrg
		}
		if err := store.DeleteOrganizationRole(c.Request.Context(), s.User.ID, s.Session.Token, query); err != nil {
			return nil, err
		}
		return map[string]bool{"success": true}, nil
	}}
}
