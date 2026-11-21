package client

import (
	"context"
	"net/http"
	"net/url"

	org "github.com/FineStack/finestack-auth/plugins/organization"
)

// TeamMembershipRequest identifies one explicit team membership. An empty
// OrganizationID selects the organization active in the calling session.
type TeamMembershipRequest struct {
	OrganizationID string `json:"organizationId,omitempty"`
	TeamID         string `json:"teamId"`
	UserID         string `json:"userId"`
}

func (c *Client) CreateTeam(ctx context.Context, name, organizationID string) (*org.Team, error) {
	body := map[string]string{"name": name}
	if organizationID != "" {
		body["organizationId"] = organizationID
	}
	var t org.Team
	if err := c.Do(ctx, http.MethodPost, "/organization/create-team", body, &t); err != nil {
		return nil, err
	}
	return &t, nil
}
func (c *Client) UpdateTeam(ctx context.Context, teamID, name, organizationID string) (*org.Team, error) {
	data := map[string]string{"name": name}
	if organizationID != "" {
		data["organizationId"] = organizationID
	}
	var t org.Team
	if err := c.Do(ctx, http.MethodPost, "/organization/update-team", map[string]any{"teamId": teamID, "data": data}, &t); err != nil {
		return nil, err
	}
	return &t, nil
}
func (c *Client) RemoveTeam(ctx context.Context, teamID, organizationID string) error {
	body := map[string]string{"teamId": teamID}
	if organizationID != "" {
		body["organizationId"] = organizationID
	}
	return c.Do(ctx, http.MethodPost, "/organization/remove-team", body, nil)
}

// SetActiveTeam chooses a team in the active organization. Passing nil clears the selection.
func (c *Client) SetActiveTeam(ctx context.Context, teamID *string) (*org.Team, error) {
	var t *org.Team
	err := c.Do(ctx, http.MethodPost, "/organization/set-active-team", map[string]*string{"teamId": teamID}, &t)
	return t, err
}

func teamRoute(name string, values url.Values) string {
	path := "/organization/" + name
	for key := range values {
		if values.Get(key) == "" {
			values.Del(key)
		}
	}
	if query := values.Encode(); query != "" {
		return path + "?" + query
	}
	return path
}
func (c *Client) ListOrganizationTeams(ctx context.Context, organizationID string) ([]org.Team, error) {
	var out []org.Team
	err := c.Do(ctx, http.MethodGet, teamRoute("list-teams", url.Values{"organizationId": {organizationID}}), nil, &out)
	return out, err
}
func (c *Client) ListUserTeams(ctx context.Context, organizationID, userID string) ([]org.Team, error) {
	var out []org.Team
	err := c.Do(ctx, http.MethodGet, teamRoute("list-user-teams", url.Values{"organizationId": {organizationID}, "userId": {userID}}), nil, &out)
	return out, err
}
func (c *Client) ListTeamMembers(ctx context.Context, teamID string) ([]org.TeamMember, error) {
	var out []org.TeamMember
	err := c.Do(ctx, http.MethodGet, teamRoute("list-team-members", url.Values{"teamId": {teamID}}), nil, &out)
	return out, err
}
func (c *Client) AddTeamMember(ctx context.Context, request TeamMembershipRequest) (*org.TeamMember, error) {
	var m org.TeamMember
	if err := c.Do(ctx, http.MethodPost, "/organization/add-team-member", request, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
func (c *Client) RemoveTeamMember(ctx context.Context, request TeamMembershipRequest) error {
	return c.Do(ctx, http.MethodPost, "/organization/remove-team-member", request, nil)
}
