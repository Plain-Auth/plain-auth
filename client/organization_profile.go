package client

import (
	"context"
	"net/http"

	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

// UpdateOrganization changes an explicit or currently active organization's public profile.
func (c *Client) UpdateOrganization(ctx context.Context, organizationID string, update org.ProfileUpdate) (*org.Organization, error) {
	body := struct {
		OrganizationID string            `json:"organizationId,omitempty"`
		Data           org.ProfileUpdate `json:"data"`
	}{organizationID, update}
	var result org.Organization
	if err := c.Do(ctx, http.MethodPost, "/organization/update", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteOrganization deletes an organization the caller may delete and returns
// its final profile. Its members, invitations and teams are removed with it.
func (c *Client) DeleteOrganization(ctx context.Context, organizationID string) (*org.Organization, error) {
	var result org.Organization
	if err := c.Do(ctx, http.MethodPost, "/organization/delete", map[string]string{"organizationId": organizationID}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CheckOrganizationSlug returns an API error for a slug already in use.
func (c *Client) CheckOrganizationSlug(ctx context.Context, slug string) (bool, error) {
	var result struct {
		Status bool `json:"status"`
	}
	err := c.Do(ctx, http.MethodPost, "/organization/check-slug", map[string]string{"slug": slug}, &result)
	return result.Status, err
}

// SetActiveOrganization selects by ID or slug for this login. Pass nil to clear
// the selection, or an empty OrganizationSelection to return the current one.
func (c *Client) SetActiveOrganization(ctx context.Context, selection *org.OrganizationSelection) (*org.Organization, error) {
	var input any = selection
	if selection == nil {
		input = map[string]any{"organizationId": nil}
	}
	var selected *org.Organization
	if err := c.Do(ctx, http.MethodPost, "/organization/set-active", input, &selected); err != nil {
		return nil, err
	}
	return selected, nil
}
