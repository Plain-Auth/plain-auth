package organization

import (
	"context"
	"errors"
	"net/http"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/jsjson"
	"github.com/Plain-Auth/plain-auth/plugins/access"
)

// The built-in permission vocabulary is shared by server and local role checks.
var defaultPermissions = map[string]access.Statements{
	"owner": {
		"organization": {"update", "delete"},
		"member":       {"create", "update", "delete"},
		"invitation":   {"create", "cancel"},
		"team":         {"create", "update", "delete"},
		"ac":           {"create", "read", "update", "delete"},
	},
	"admin": {
		"organization": {"update"},
		"member":       {"create", "update", "delete"},
		"invitation":   {"create", "cancel"},
		"team":         {"create", "update", "delete"},
		"ac":           {"create", "read", "update", "delete"},
	},
	"member": {"ac": {"read"}},
}

// DefaultRoleHasPermission reports whether one of the supplied built-in roles
// grants every requested action. An empty request or action list returns false.
func DefaultRoleHasPermission(roles string, permissions access.Statements) bool {
	return (RolePolicy{}).HasPermission(roles, permissions)
}

func permissionStatements(value any) (access.Statements, bool) {
	raw, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	request := make(access.Statements, len(raw))
	for resource, list := range raw {
		actions, ok := list.([]any)
		if !ok {
			return nil, false
		}
		names := make([]string, len(actions))
		for i, action := range actions {
			name, ok := action.(string)
			if !ok {
				return nil, false
			}
			names[i] = name
		}
		request[resource] = names
	}
	return request, true
}

func permissionQuery(body map[string]any) (string, access.Statements, error) {
	var id string
	var issues []string
	if v, ok := body["organizationId"]; ok {
		if id, ok = v.(string); !ok {
			issues = append(issues, "[body.organizationId] Invalid input: expected string, received "+jsjson.TypeName(v))
		}
	}
	modern, hasModern := permissionStatements(body["permissions"])
	_, hasLegacy := permissionStatements(body["permission"])
	switch {
	case hasModern && hasLegacy:
		issues = append(issues, "[body] Invalid input: more than one option matched")
	case !hasModern && !hasLegacy:
		issues = append(issues, "[body] Invalid input")
	}
	if len(issues) > 0 {
		return "", nil, problem(400, "VALIDATION_ERROR", strings.Join(issues, "; "))
	}
	return id, modern, nil
}

func (p RolePolicy) checkMemberPermission(ctx context.Context, store MemberRoleReader, session auth.Session, id string, permissions access.Statements) (bool, error) {
	if live, ok := store.(OrganizationPermissionStore); ok {
		return live.CheckOrganizationPermission(ctx, session.ID, session.UserID, id, permissions)
	}
	role, err := store.OrganizationMemberRole(ctx, session.ID, session.UserID, MemberRoleQuery{OrganizationID: id})
	return p.HasPermission(role, permissions), err
}

func (p RolePolicy) permissionEndpoint(store MemberRoleReader) auth.Endpoint {
	return auth.Endpoint{Method: http.MethodPost, Path: "/organization/has-permission", Handler: func(c auth.EndpointContext) (any, error) {
		id, permissions, err := permissionQuery(c.Body)
		if err != nil {
			return nil, err
		}
		session, err := endpointSession(c, http.MethodPost, "has-permission")
		if err != nil {
			return nil, err
		}
		allowed, err := p.checkMemberPermission(c.Request.Context(), store, session.Session, id, permissions)
		if errors.Is(err, ErrRoleReadDenied) {
			return nil, problem(401, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION", "User is not a member of the organization")
		}
		if err != nil {
			return nil, err
		}
		return map[string]any{"success": allowed, "error": nil}, nil
	}}
}
