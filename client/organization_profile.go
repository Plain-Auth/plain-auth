package client

import (
	"context"
	"net/http"
	"net/url"

	org "github.com/Plain-Org/plain-auth/plugins/organization"
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

// CreateOrganizationRequest describes a new organization. The signed-in user
// becomes its creator. KeepCurrentActiveOrganization leaves the session's
// current selection in place instead of selecting the new organization.
type CreateOrganizationRequest struct {
	Name                          string
	Slug                          string
	Logo                          *string
	Metadata                      map[string]any
	KeepCurrentActiveOrganization bool
}

// CreatedOrganization is the new organization with its creator's membership.
type CreatedOrganization = org.CreatedOrganization

// CreateOrganization creates an organization owned by the signed-in user.
func (c *Client) CreateOrganization(ctx context.Context, request CreateOrganizationRequest) (*CreatedOrganization, error) {
	body := map[string]any{"name": request.Name, "slug": request.Slug}
	if request.Logo != nil {
		body["logo"] = *request.Logo
	}
	if request.Metadata != nil {
		body["metadata"] = request.Metadata
	}
	if request.KeepCurrentActiveOrganization {
		body["keepCurrentActiveOrganization"] = true
	}
	var result CreatedOrganization
	if err := c.Do(ctx, http.MethodPost, "/organization/create", body, &result); err != nil {
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

// Organization reads an organization the caller belongs to, by ID or slug. With
// neither, it reads the session's selection and returns nil when there is none.
// A lookup the caller is refused clears the session's selection.
func (c *Client) Organization(ctx context.Context, organizationID, organizationSlug string) (*org.Organization, error) {
	query := url.Values{}
	if organizationID != "" {
		query.Set("organizationId", organizationID)
	}
	if organizationSlug != "" {
		query.Set("organizationSlug", organizationSlug)
	}
	route := "/organization/get-organization"
	if len(query) > 0 {
		route += "?" + query.Encode()
	}
	var result *org.Organization
	if err := c.Do(ctx, http.MethodGet, route, nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}
