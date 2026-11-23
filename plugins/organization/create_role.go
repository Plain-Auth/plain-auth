package organization

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/jsjson"
	"github.com/Plain-Auth/plain-auth/plugins/access"
)

// DefaultRoleControl defines the built-in organization, member, invitation, team and ac resources.
func DefaultRoleControl() *access.Control {
	control := access.New(defaultPermissions["owner"])
	return &control
}

// RoleLimit limits stored definitions per organization. A nil option is unlimited.
// Resolve runs outside the database transaction and may return zero to deny creation.
type RoleLimit struct {
	Maximum int
	Resolve func(context.Context, string) (int, error)
}

type CreateRoleRequest struct {
	OrganizationID string
	Role           string
	Permission     access.Statements
}

type CreatedRole struct {
	Success    bool              `json:"success"`
	RoleData   RoleDefinition    `json:"roleData"`
	Statements access.Statements `json:"statements"`
}

// RoleCreationStore checks current authority, grant delegation, capacity and
// tenant-local name uniqueness when saving a new role.
type RoleCreationStore interface {
	CreateOrganizationRole(ctx context.Context, session auth.Session, request CreateRoleRequest, control access.Control, limit *RoleLimit) (*RoleDefinition, error)
}

var (
	ErrRoleControlMissing = problem(501, "MISSING_AC_INSTANCE", "Dynamic Access Control requires a pre-defined ac instance on the server auth plugin. Read server logs for more information")
	ErrCreateRoleNoOrg    = problem(400, "YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE", "You must be in an organization to create a role")
	ErrCreateRoleDenied   = problem(403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE", "You are not allowed to create a role")
	ErrRoleNameTaken      = problem(400, "ROLE_NAME_IS_ALREADY_TAKEN", "That role name is already taken")
	ErrTooManyRoles       = problem(400, "TOO_MANY_ROLES", "This organization has too many roles")
	ErrInvalidResource    = problem(400, "INVALID_RESOURCE", "The provided permission includes an invalid resource")
	ErrRoleScopeChanged   = problem(409, "ROLE_ORGANIZATION_CHANGED", "The selected organization changed. Retry the request.")
)

// CheckDelegation requires every named action to be available to the actor.
// A different membership role can authorize each action.
func (p RolePolicy) CheckDelegation(actorRole string, grants access.Statements, control access.Control, denied *auth.APIError) error {
	var missing []string
	for _, resource := range slices.Sorted(maps.Keys(grants)) {
		if !control.HasResource(resource) {
			return ErrInvalidResource
		}
		for _, action := range grants[resource] {
			if !control.HasAction(resource, action) || !p.HasAction(actorRole, resource, action) {
				missing = append(missing, resource+":"+action)
			}
		}
	}
	if len(missing) > 0 {
		return &auth.MissingPermissionsError{APIError: denied, MissingPermissions: missing}
	}
	return nil
}

func roleInputTypeIssue(path, expected string, value any, present bool) string {
	got := "undefined"
	if present {
		got = jsjson.TypeName(value)
	}
	return "[body." + path + "] Invalid input: expected " + expected + ", received " + got
}

func rolePermissionInput(path string, raw any, present bool) (access.Statements, []string) {
	fields, ok := raw.(map[string]any)
	if !ok {
		return nil, []string{roleInputTypeIssue(path, "record", raw, present)}
	}
	grants := make(access.Statements, len(fields))
	var issues []string
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		field := path + "." + key
		list, ok := fields[key].([]any)
		if !ok {
			issues = append(issues, roleInputTypeIssue(field, "array", fields[key], true))
			continue
		}
		actions := make([]string, len(list))
		for i, value := range list {
			if actions[i], ok = value.(string); !ok {
				issues = append(issues, roleInputTypeIssue(fmt.Sprintf("%s.%d", field, i), "string", value, true))
			}
		}
		grants[key] = actions
	}
	return grants, issues
}

func roleOrganizationInput(body map[string]any) (string, []string) {
	if raw, present := body["organizationId"]; present {
		if id, ok := raw.(string); ok {
			return id, nil
		}
		return "", []string{roleInputTypeIssue("organizationId", "string", raw, true)}
	}
	return "", nil
}

func roleCreationInput(body map[string]any) (CreateRoleRequest, error) {
	group, issues := roleOrganizationInput(body)
	q := CreateRoleRequest{OrganizationID: group}
	role, present := body["role"]
	var ok bool
	if q.Role, ok = role.(string); !ok {
		issues = append(issues, roleInputTypeIssue("role", "string", role, present))
	}
	permission, present := body["permission"]
	var invalid []string
	q.Permission, invalid = rolePermissionInput("permission", permission, present)
	issues = append(issues, invalid...)
	if raw, supplied := body["additionalFields"]; supplied {
		if _, ok := raw.(map[string]any); !ok {
			issues = append(issues, roleInputTypeIssue("additionalFields", "object", raw, true))
		}
	}
	if len(issues) > 0 {
		return q, problem(400, "VALIDATION_ERROR", strings.Join(issues, "; "))
	}
	return q, nil
}

func (o Options) createRoleEndpoint(store RoleCreationStore) auth.Endpoint {
	return auth.Endpoint{Method: http.MethodPost, Path: "/organization/create-role", Handler: func(c auth.EndpointContext) (any, error) {
		q, err := roleCreationInput(c.Body)
		if err != nil {
			return nil, err
		}
		s, err := endpointSession(c, http.MethodPost, "create-role")
		if err != nil {
			return nil, err
		}
		if o.RoleControl == nil {
			return nil, ErrRoleControlMissing
		}
		if _, explicit := c.Body["organizationId"]; explicit && q.OrganizationID == "" {
			return nil, ErrCreateRoleNoOrg
		}
		row, err := store.CreateOrganizationRole(c.Request.Context(), s.Session, q, *o.RoleControl, o.RoleLimit)
		if err != nil {
			return nil, err
		}
		return CreatedRole{Success: true, RoleData: *row, Statements: row.Permission}, nil
	}}
}
