package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Plain-Auth/plain-auth/plugins/access"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

// ListOrganizationMembers returns a filtered page and its full matching count.
func (c *Client) ListOrganizationMembers(ctx context.Context, q org.MemberListQuery) (*org.MemberPage, error) {
	params := url.Values{}
	for k, v := range map[string]string{"organizationId": q.OrganizationID, "organizationSlug": q.OrganizationSlug, "sortBy": q.SortBy, "sortDirection": q.SortDirection, "filterField": q.FilterField, "filterOperator": q.FilterOperator} {
		if v != "" {
			params.Set(k, v)
		}
	}
	if q.Limit != 0 {
		params.Set("limit", strconv.Itoa(q.Limit))
	}
	if q.Offset != 0 {
		params.Set("offset", strconv.Itoa(q.Offset))
	}
	params["filterValue"] = q.FilterValues
	path := "/organization/list-members"
	if query := params.Encode(); query != "" {
		path += "?" + query
	}
	var out org.MemberPage
	if err := c.Do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// OrganizationMemberRole reads the role of a user in a shared organization.
// An empty query reads the caller's role in the current session selection.
func (c *Client) OrganizationMemberRole(ctx context.Context, query org.MemberRoleQuery) (string, error) {
	route := organizationRoute("get-active-member-role", url.Values{"organizationSlug": {query.OrganizationSlug}, "organizationId": {query.OrganizationID}, "userId": {query.UserID}})
	var out struct{ Role string }
	err := c.Do(ctx, http.MethodGet, route, nil, &out)
	return out.Role, err
}

// ActiveOrganizationMember returns the signed-in user's membership in the
// organization selected by this client's session.
func (c *Client) ActiveOrganizationMember(ctx context.Context) (*org.ActiveMember, error) {
	var out org.ActiveMember
	if err := c.Do(ctx, http.MethodGet, "/organization/get-active-member", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

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

// FullOrganization returns the visible members, invitations and configured teams.
// It returns nil when the session has no selected organization and no selector is supplied.
func (c *Client) FullOrganization(ctx context.Context, q org.FullOrganizationQuery) (*org.FullOrganization, error) {
	params := url.Values{"organizationId": {q.OrganizationID}, "organizationSlug": {q.OrganizationSlug}}
	if q.MembersLimit != 0 {
		params.Set("membersLimit", strconv.Itoa(q.MembersLimit))
	}
	var out *org.FullOrganization
	err := c.Do(ctx, http.MethodGet, organizationRoute("get-full-organization", params), nil, &out)
	return out, err
}

// ListOrganizationInvitations returns invitations the member can manage,
// including accepted, canceled and rejected invitations. An empty ID uses
// the session's active organization.
func (c *Client) ListOrganizationInvitations(ctx context.Context, organizationID string) ([]org.Invitation, error) {
	var list []org.Invitation
	err := c.Do(ctx, http.MethodGet, organizationRoute("list-invitations", url.Values{"organizationId": {organizationID}}), nil, &list)
	return list, err
}

// ListUserInvitations reads pending invitations for the authenticated account's verified email.
func (c *Client) ListUserInvitations(ctx context.Context) ([]org.ReceivedInvitation, error) {
	var out []org.ReceivedInvitation
	err := c.Do(ctx, http.MethodGet, "/organization/list-user-invitations", nil, &out)
	return out, err
}

// OrganizationInvitation reads a pending, unexpired invitation by its opaque ID.
func (c *Client) OrganizationInvitation(ctx context.Context, invitationID string) (*org.InvitationDetails, error) {
	var view org.InvitationDetails
	path := "/organization/get-invitation?" + url.Values{"id": {invitationID}}.Encode()
	if err := c.Do(ctx, http.MethodGet, path, nil, &view); err != nil {
		return nil, err
	}
	return &view, nil
}

// AcceptedInvitation contains the invitation and the membership it granted.
type AcceptedInvitation struct {
	Invitation org.Invitation `json:"invitation"`
	Member     org.Member     `json:"member"`
}

// InviteOrganizationMemberRequest describes a grant. An empty OrganizationID
// uses the caller's active organization. TeamIDs can select several teams.
type InviteOrganizationMemberRequest struct {
	Email          string
	Roles          []string
	OrganizationID string
	TeamIDs        []string
	Resend         bool
}

// InviteOrganizationMember issues an invitation or renews it when Resend is set.
func (c *Client) InviteOrganizationMember(ctx context.Context, request InviteOrganizationMemberRequest) (*org.Invitation, error) {
	roles := request.Roles
	if roles == nil {
		roles = []string{}
	}
	body := map[string]any{"email": request.Email, "role": roles}
	if request.OrganizationID != "" {
		body["organizationId"] = request.OrganizationID
	}
	if len(request.TeamIDs) != 0 {
		body["teamId"] = request.TeamIDs
	}
	if request.Resend {
		body["resend"] = true
	}
	var inv org.Invitation
	if err := c.Do(ctx, http.MethodPost, "/organization/invite-member", body, &inv); err != nil {
		return nil, err
	}
	return &inv, nil
}

// AcceptOrganizationInvitation joins the organization and selects it on the calling session.
func (c *Client) AcceptOrganizationInvitation(ctx context.Context, invitationID string) (*AcceptedInvitation, error) {
	var out AcceptedInvitation
	if err := c.Do(ctx, http.MethodPost, "/organization/accept-invitation", map[string]string{"invitationId": invitationID}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RejectOrganizationInvitation declines a pending invitation for the signed-in recipient.
func (c *Client) RejectOrganizationInvitation(ctx context.Context, invitationID string) (*org.Invitation, error) {
	var out struct {
		Invitation org.Invitation `json:"invitation"`
	}
	if err := c.Do(ctx, http.MethodPost, "/organization/reject-invitation", map[string]string{"invitationId": invitationID}, &out); err != nil {
		return nil, err
	}
	return &out.Invitation, nil
}

// CancelOrganizationInvitation withdraws an invitation as an authorized organization member.
func (c *Client) CancelOrganizationInvitation(ctx context.Context, invitationID string) (*org.Invitation, error) {
	var out org.Invitation
	if err := c.Do(ctx, http.MethodPost, "/organization/cancel-invitation", map[string]string{"invitationId": invitationID}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HasOrganizationPermission checks the caller's live membership. An empty
// organizationID uses the active organization on this session.
func (c *Client) HasOrganizationPermission(ctx context.Context, organizationID string, permissions access.Statements) (bool, error) {
	body := map[string]any{"permissions": organizationPermissionObject(permissions)}
	if organizationID != "" {
		body["organizationId"] = organizationID
	}
	var response struct {
		Success bool `json:"success"`
	}
	err := c.Do(ctx, http.MethodPost, "/organization/has-permission", body, &response)
	return response.Success, err
}
