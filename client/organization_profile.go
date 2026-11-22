package client

import (
	"context"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"net/http"
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

// CheckOrganizationSlug returns an API error for a slug already in use.
func (c *Client) CheckOrganizationSlug(ctx context.Context, slug string) (bool, error) {
	var result struct {
		Status bool `json:"status"`
	}
	err := c.Do(ctx, http.MethodPost, "/organization/check-slug", map[string]string{"slug": slug}, &result)
	return result.Status, err
}
