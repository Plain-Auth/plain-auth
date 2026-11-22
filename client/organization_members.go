package client

import (
	"context"
	"net/http"

	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

// RemoveOrganizationMember removes a member by membership ID or email. An empty
// organizationID uses the calling session's active organization.
func (c *Client) RemoveOrganizationMember(ctx context.Context, memberIDOrEmail, organizationID string) (*org.RemovedMember, error) {
	body := map[string]string{"memberIdOrEmail": memberIDOrEmail}
	if organizationID != "" {
		body["organizationId"] = organizationID
	}
	var out struct {
		Member org.RemovedMember `json:"member"`
	}
	if err := c.Do(ctx, http.MethodPost, "/organization/remove-member", body, &out); err != nil {
		return nil, err
	}
	return &out.Member, nil
}

// LeaveOrganization removes the signed-in user's membership.
func (c *Client) LeaveOrganization(ctx context.Context, organizationID string) (*org.RemovedMember, error) {
	var out org.RemovedMember
	if err := c.Do(ctx, http.MethodPost, "/organization/leave", map[string]string{"organizationId": organizationID}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateOrganizationMemberRole replaces the membership's roles. Leave the
// organization ID empty to use the caller's active organization.
func (c *Client) UpdateOrganizationMemberRole(ctx context.Context, request org.UpdateMemberRoleRequest) (*org.Member, error) {
	roles := request.Roles
	if roles == nil {
		roles = []string{}
	}
	body := map[string]any{"memberId": request.MemberID, "role": roles}
	if request.OrganizationID != "" {
		body["organizationId"] = request.OrganizationID
	}
	var out org.Member
	if err := c.Do(ctx, http.MethodPost, "/organization/update-member-role", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
