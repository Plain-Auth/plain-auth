package organization

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/access"
)

// RoleDefinition is a stored permission definition in a single organization.
type RoleDefinition struct {
	ID             string            `json:"id"`
	OrganizationID string            `json:"organizationId"`
	Role           string            `json:"role"`
	Permission     access.Statements `json:"permission"`
	CreatedAt      time.Time         `json:"createdAt"`
	UpdatedAt      *time.Time        `json:"updatedAt"`
}

func (r RoleDefinition) MarshalJSON() ([]byte, error) {
	const millis = "2006-01-02T15:04:05.000Z"
	var updated *string
	if r.UpdatedAt != nil {
		value := r.UpdatedAt.UTC().Format(millis)
		updated = &value
	}
	type fields RoleDefinition
	return json.Marshal(struct {
		fields
		CreatedAt string  `json:"createdAt"`
		UpdatedAt *string `json:"updatedAt"`
	}{fields(r), r.CreatedAt.UTC().Format(millis), updated})
}

// RoleQuery selects a stored definition by exact name or ID. Name takes precedence.
// An empty OrganizationID uses the current session selection.
type RoleQuery struct {
	OrganizationID, RoleName, RoleID string
}

// RoleDirectoryStore checks live session membership and ac.read together with the role lookup.
type RoleDirectoryStore interface {
	ListOrganizationRoles(ctx context.Context, sessionID, actorID, organizationID string) ([]RoleDefinition, error)
	GetOrganizationRole(ctx context.Context, sessionID, actorID string, query RoleQuery) (*RoleDefinition, error)
}

var (
	ErrRoleNotFound   = problem(400, "ROLE_NOT_FOUND", "Role not found")
	ErrListRoleDenied = problem(403, "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE", "You are not allowed to list a role")
	ErrGetRoleDenied  = problem(403, "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE", "You are not allowed to read a role")
)

func directoryRoleQuery(q url.Values, lookup bool) (RoleQuery, error) {
	var issues []string
	query := RoleQuery{OrganizationID: q.Get("organizationId")}
	if len(q["organizationId"]) > 1 {
		issues = append(issues, "[query.organizationId] Invalid input: expected string, received array")
	}
	if lookup {
		names, ids := q["roleName"], q["roleId"]
		switch {
		case len(names) == 1 && names[0] != "":
			query.RoleName = names[0]
		case len(ids) == 1 && ids[0] != "":
			query.RoleID = ids[0]
		case len(names) == 1 && len(ids) != 1:
			issues = append(issues, "[query.roleName] Too small: expected string to have >=1 characters")
		case len(ids) == 1 && len(names) != 1:
			issues = append(issues, "[query.roleId] Too small: expected string to have >=1 characters")
		default:
			issues = append(issues, "[query] Invalid input")
		}
	}
	if len(issues) != 0 {
		return RoleQuery{}, problem(400, "VALIDATION_ERROR", strings.Join(issues, "; "))
	}
	return query, nil
}

func roleDirectoryEndpoint(action string, store RoleDirectoryStore) auth.Endpoint {
	return auth.Endpoint{Method: http.MethodGet, Path: "/organization/" + action, Handler: func(c auth.EndpointContext) (any, error) {
		params := c.Request.URL.Query()
		lookup := action == "get-role"
		query, err := directoryRoleQuery(params, lookup)
		if err != nil {
			return nil, err
		}
		s, err := endpointSession(c, http.MethodGet, action)
		if err != nil {
			return nil, err
		}
		if params.Has("organizationId") && query.OrganizationID == "" {
			return nil, ErrNoActiveOrg
		}
		if lookup {
			return store.GetOrganizationRole(c.Request.Context(), s.Session.ID, s.User.ID, query)
		}
		return store.ListOrganizationRoles(c.Request.Context(), s.Session.ID, s.User.ID, query.OrganizationID)
	}}
}
