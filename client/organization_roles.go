package client

import (
	"context"
	"net/http"
	"net/url"

	"github.com/Plain-Auth/plain-auth/plugins/access"
	"github.com/Plain-Auth/plain-auth/plugins/organization"
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
	body := map[string]string{}
	if q.RoleName != "" {
		body["roleName"] = q.RoleName
	}
	if q.RoleID != "" {
		body["roleId"] = q.RoleID
	}
	if q.OrganizationID != "" {
		body["organizationId"] = q.OrganizationID
	}
	return c.Do(ctx, http.MethodPost, "/organization/delete-role", body, nil)
}

// CreateOrganizationRole creates a stored role with the given grants.
func (c *Client) CreateOrganizationRole(ctx context.Context, q organization.CreateRoleRequest) (*organization.CreatedRole, error) {
	body := map[string]any{"role": q.Role, "permission": nil}
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
