package organization

import (
	"context"
	"net/http"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/access"
)

// RoleUpdate replaces the stored grant map when Permission is non-nil. A
// nonempty RoleName renames the definition. Memberships keep their own labels.
type RoleUpdate struct {
	RoleName         string
	Permission       access.Statements
	AdditionalFields map[string]any
}

type UpdatedRole struct {
	Success  bool           `json:"success"`
	RoleData RoleDefinition `json:"roleData"`
}

// RoleUpdateStore authorizes both the edit and the grants it delegates before
// changing a tenant's role definition.
type RoleUpdateStore interface {
	UpdateOrganizationRole(ctx context.Context, userID, token string, query RoleQuery, change RoleUpdate, control access.Control) (*RoleDefinition, error)
}

var ErrUpdateRoleDenied = problem(403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE", "You are not allowed to update a role")

func roleUpdateInput(body map[string]any, defs map[string]RoleField) (RoleQuery, RoleUpdate, error) {
	group, issues := roleOrganizationInput(body)
	query := RoleQuery{OrganizationID: group}
	change := RoleUpdate{}
	raw, present := body["data"]
	data, ok := raw.(map[string]any)
	if !ok {
		issues = append(issues, bodyTypeIssue("data", "object", raw, present))
	} else {
		var err error
		change.AdditionalFields, err = ParseRoleFieldInput(defs, data, true)
		if err != nil {
			issues = append(issues, err.Error())
		}
		if grants, has := data["permission"]; has {
			var invalid []string
			change.Permission, invalid = rolePermissionInput("data.permission", grants, true)
			issues = append(issues, invalid...)
		}
		if name, has := data["roleName"]; has {
			if change.RoleName, ok = name.(string); !ok {
				issues = append(issues, bodyTypeIssue("data.roleName", "string", name, true))
			}
		}
	}
	if issue := query.selectRole(body["roleName"], body["roleId"], "body"); issue != "" {
		issues = append(issues, issue)
	}
	if len(issues) > 0 {
		return query, change, problem(400, "VALIDATION_ERROR", strings.Join(issues, "; "))
	}
	return query, change, nil
}

func (o Options) updateRoleEndpoint(store RoleUpdateStore) auth.Endpoint {
	return auth.Endpoint{Method: http.MethodPost, Path: "/organization/update-role", Handler: func(c auth.EndpointContext) (any, error) {
		q, change, err := roleUpdateInput(c.Body, o.RoleAdditionalFields)
		if err != nil {
			return nil, err
		}
		s, err := endpointSession(c, http.MethodPost, "update-role")
		if err != nil {
			return nil, err
		}
		if o.RoleControl == nil {
			return nil, ErrRoleControlMissing
		}
		if _, explicit := c.Body["organizationId"]; explicit && q.OrganizationID == "" {
			return nil, ErrNoActiveOrg
		}
		row, err := store.UpdateOrganizationRole(c.Request.Context(), s.User.ID, s.Session.Token, q, change, *o.RoleControl)
		if err != nil {
			return nil, err
		}
		return UpdatedRole{Success: true, RoleData: *row}, nil
	}}
}
