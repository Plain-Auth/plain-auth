package client

import (
	"context"
	"github.com/Plain-Org/plain-auth/internal/sessionfields"
	"net/http"
	"net/url"

	"github.com/Plain-Org/plain-auth/plugins/access"
	"github.com/Plain-Org/plain-auth/plugins/organization"
)

// ListOrganizationRoles returns stored roles visible to this session. An empty
// organizationID uses the session's active organization.
func (c *Client) ListOrganizationRoles(ctx context.Context, organizationID string) ([]organization.RoleDefinition, error) {
	path := organizationRoute("list-roles", url.Values{"organizationId": {organizationID}})
	var out []organization.RoleDefinition
	err := c.Do(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

// GetOrganizationRole looks up a stored role by exact name or ID.
func (c *Client) GetOrganizationRole(ctx context.Context, q organization.RoleQuery) (*organization.RoleDefinition, error) {
	path := organizationRoute("get-role", url.Values{"organizationId": {q.OrganizationID}, "roleName": {q.RoleName}, "roleId": {q.RoleID}})
	var out organization.RoleDefinition
	if err := c.Do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteOrganizationRole removes a stored role after its last member is reassigned.
func (c *Client) DeleteOrganizationRole(ctx context.Context, q organization.RoleQuery) error {
	body := roleSelectorBody(q)
	return c.Do(ctx, http.MethodPost, "/organization/delete-role", body, nil)
}

// CreateOrganizationRole creates a stored role with the given grants.
func (c *Client) CreateOrganizationRole(ctx context.Context, q organization.CreateRoleRequest) (*organization.CreatedRole, error) {
	body := map[string]any{"role": q.Role, "permission": nil}
	if q.AdditionalFields != nil {
		body["additionalFields"] = q.AdditionalFields
	}
	if q.Permission != nil {
		body["permission"] = organizationPermissionObject(q.Permission)
	}
	if q.OrganizationID != "" {
		body["organizationId"] = q.OrganizationID
	}
	var out organization.CreatedRole
	if err := c.Do(ctx, http.MethodPost, "/organization/create-role", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Encode every action list as a JSON array, including a nil Go slice.
func organizationPermissionObject(grants access.Statements) access.Statements {
	out := make(access.Statements, len(grants))
	for resource, actions := range grants {
		if actions == nil {
			actions = []string{}
		}
		out[resource] = actions
	}
	return out
}

func roleSelectorBody(q organization.RoleQuery) map[string]any {
	body := map[string]any{}
	if q.RoleName != "" {
		body["roleName"] = q.RoleName
	}
	if q.RoleID != "" {
		body["roleId"] = q.RoleID
	}
	if q.OrganizationID != "" {
		body["organizationId"] = q.OrganizationID
	}
	return body
}

// UpdateOrganizationRole replaces grants, renames a definition, or does both in one request.
func (c *Client) UpdateOrganizationRole(ctx context.Context, q organization.RoleQuery, change organization.RoleUpdate) (*organization.UpdatedRole, error) {
	body := roleSelectorBody(q)
	data := map[string]any{}
	for name, value := range change.AdditionalFields {
		if sessionfields.RoleNameOK(name) {
			data[name] = value
		}
	}
	if change.RoleName != "" {
		data["roleName"] = change.RoleName
	}
	if change.Permission != nil {
		data["permission"] = organizationPermissionObject(change.Permission)
	}
	body["data"] = data
	var out organization.UpdatedRole
	if err := c.Do(ctx, http.MethodPost, "/organization/update-role", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
