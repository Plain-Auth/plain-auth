package organization

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/sessionfields"
	"github.com/Plain-Auth/plain-auth/plugins/access"
)

// RoleDefinition is a stored permission definition in a single organization.
type RoleDefinition struct {
	AdditionalFields map[string]any    `json:"-"`
	ID               string            `json:"id"`
	OrganizationID   string            `json:"organizationId"`
	Role             string            `json:"role"`
	Permission       access.Statements `json:"permission"`
	CreatedAt        time.Time         `json:"createdAt"`
	UpdatedAt        *time.Time        `json:"updatedAt"`
}

func (r RoleDefinition) MarshalJSON() ([]byte, error) {
	const millis = "2006-01-02T15:04:05.000Z"
	var updated *string
	if r.UpdatedAt != nil {
		value := r.UpdatedAt.UTC().Format(millis)
		updated = &value
	}
	type fields RoleDefinition
	base, err := json.Marshal(struct {
		fields
		CreatedAt string  `json:"createdAt"`
		UpdatedAt *string `json:"updatedAt"`
	}{fields(r), r.CreatedAt.UTC().Format(millis), updated})
	if err != nil || len(r.AdditionalFields) == 0 {
		return base, err
	}
	extras := make(map[string]any)
	for name, value := range r.AdditionalFields {
		if sessionfields.RoleNameOK(name) {
			extras[name] = value
		}
	}
	if len(extras) == 0 {
		return base, nil
	}
	b, err := json.Marshal(extras)
	if err != nil {
		return nil, err
	}
	base[len(base)-1] = ','
	return append(base, b[1:]...), nil
}

// UnmarshalJSON retains the logical custom field names returned by the server.
func (r *RoleDefinition) UnmarshalJSON(b []byte) error {
	type fields RoleDefinition
	var fixed fields
	if err := json.Unmarshal(b, &fixed); err != nil {
		return err
	}
	var extra map[string]any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&extra); err != nil {
		return err
	}
	for name, value := range extra {
		if !sessionfields.RoleNameOK(name) {
			delete(extra, name)
		} else if n, ok := value.(json.Number); ok {
			if v, err := n.Int64(); err == nil {
				extra[name] = v
			}
		}
	}
	if len(extra) > 0 {
		fixed.AdditionalFields = extra
	}
	*r = RoleDefinition(fixed)
	return nil
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

// selectRole parses the two alternatives shared by lookups and changes.
func (q *RoleQuery) selectRole(nameValue, idValue any, location string) string {
	name, hasName := nameValue.(string)
	id, hasID := idValue.(string)
	switch {
	case name != "":
		q.RoleName = name
	case id != "":
		q.RoleID = id
	case hasName && !hasID:
		return "[" + location + ".roleName] Too small: expected string to have >=1 characters"
	case hasID && !hasName:
		return "[" + location + ".roleId] Too small: expected string to have >=1 characters"
	default:
		return "[" + location + "] Invalid input"
	}
	return ""
}

func directoryRoleQuery(q url.Values, lookup bool) (RoleQuery, error) {
	var issues []string
	query := RoleQuery{OrganizationID: q.Get("organizationId")}
	if len(q["organizationId"]) > 1 {
		issues = append(issues, "[query.organizationId] Invalid input: expected string, received array")
	}
	if lookup {
		var name, id any
		if len(q["roleName"]) == 1 {
			name = q.Get("roleName")
		}
		if len(q["roleId"]) == 1 {
			id = q.Get("roleId")
		}
		if issue := query.selectRole(name, id, "query"); issue != "" {
			issues = append(issues, issue)
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
