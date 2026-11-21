package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	authn "github.com/Stonewrit/stonewrit-auth"
)

type AdminCreateUserRequest struct {
	Name     string         `json:"name"`
	Email    string         `json:"email"`
	Password string         `json:"password,omitempty"`
	Role     []string       `json:"role,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

func (c *Client) adminUser(ctx context.Context, operation string, body any) (*authn.User, error) {
	var out struct {
		User authn.User `json:"user"`
	}
	if err := c.Do(ctx, http.MethodPost, "/admin/"+operation, body, &out); err != nil {
		return nil, err
	}
	return &out.User, nil
}
func (c *Client) AdminCreateUser(ctx context.Context, in AdminCreateUserRequest) (*authn.User, error) {
	return c.adminUser(ctx, "create-user", in)
}
func (c *Client) AdminGetUser(ctx context.Context, id string) (*authn.User, error) {
	var u authn.User
	if err := c.Do(ctx, http.MethodGet, "/admin/get-user?id="+url.QueryEscape(id), nil, &u); err != nil {
		return nil, err
	}
	return &u, nil
}
func (c *Client) AdminUpdateUser(ctx context.Context, id string, fields map[string]any) (*authn.User, error) {
	var u authn.User
	if err := c.Do(ctx, http.MethodPost, "/admin/update-user", map[string]any{"userId": id, "data": fields}, &u); err != nil {
		return nil, err
	}
	return &u, nil
}
func (c *Client) AdminSetRole(ctx context.Context, id string, roles ...string) (*authn.User, error) {
	return c.adminUser(ctx, "set-role", map[string]any{"userId": id, "role": roles})
}
func (c *Client) AdminBanUser(ctx context.Context, id, reason string, duration time.Duration) (*authn.User, error) {
	return c.adminUser(ctx, "ban-user", map[string]any{"userId": id, "banReason": reason, "banExpiresIn": duration.Seconds()})
}
func (c *Client) AdminUnbanUser(ctx context.Context, id string) (*authn.User, error) {
	return c.adminUser(ctx, "unban-user", map[string]string{"userId": id})
}
func (c *Client) AdminListUsers(ctx context.Context, q authn.AdminQuery) (*authn.AdminPage, error) {
	raw := url.Values{}
	for k, v := range map[string]string{"searchField": q.SearchField, "searchValue": q.SearchValue, "searchOperator": q.SearchOperator, "filterField": q.FilterField, "filterOperator": q.FilterOperator, "sortBy": q.SortBy, "sortDirection": q.SortDirection} {
		if v != "" {
			raw.Set(k, v)
		}
	}
	for _, v := range q.FilterValues {
		raw.Add("filterValue", v)
	}
	if q.Limit != 0 {
		raw.Set("limit", strconv.Itoa(q.Limit))
	}
	if q.Offset != 0 {
		raw.Set("offset", strconv.Itoa(q.Offset))
	}
	var page authn.AdminPage
	if err := c.Do(ctx, http.MethodGet, "/admin/list-users?"+raw.Encode(), nil, &page); err != nil {
		return nil, err
	}
	return &page, nil
}
func (c *Client) AdminHasPermission(ctx context.Context, want authn.AdminPermissions) (bool, error) {
	var out struct {
		Success bool `json:"success"`
	}
	err := c.Do(ctx, http.MethodPost, "/admin/has-permission", map[string]any{"permissions": want}, &out)
	return out.Success, err
}
func (c *Client) AdminSetPassword(ctx context.Context, id, password string) error {
	return c.Do(ctx, http.MethodPost, "/admin/set-user-password", map[string]string{"userId": id, "newPassword": password}, nil)
}
func (c *Client) AdminRemoveUser(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodPost, "/admin/remove-user", map[string]string{"userId": id}, nil)
}
func (c *Client) AdminListUserSessions(ctx context.Context, id string) ([]authn.Session, error) {
	var out struct {
		Sessions []authn.Session `json:"sessions"`
	}
	err := c.Do(ctx, http.MethodPost, "/admin/list-user-sessions", map[string]string{"userId": id}, &out)
	return out.Sessions, err
}
func (c *Client) AdminRevokeSession(ctx context.Context, token string) error {
	return c.Do(ctx, http.MethodPost, "/admin/revoke-user-session", map[string]string{"sessionToken": token}, nil)
}
func (c *Client) AdminRevokeUserSessions(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodPost, "/admin/revoke-user-sessions", map[string]string{"userId": id}, nil)
}
func (c *Client) AdminImpersonate(ctx context.Context, id string) (*authn.SessionResult, error) {
	var out authn.SessionResult
	if err := c.Do(ctx, http.MethodPost, "/admin/impersonate-user", map[string]string{"userId": id}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
func (c *Client) AdminStopImpersonating(ctx context.Context) (*authn.SessionResult, error) {
	var out authn.SessionResult
	if err := c.Do(ctx, http.MethodPost, "/admin/stop-impersonating", struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
