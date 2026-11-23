package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Plain-Org/plain-auth/plugins/apikey"
)

// CreateAPIKeyRequest sets client-editable fields. ExpiresIn is in seconds.
type CreateAPIKeyRequest struct {
	OrganizationID string         `json:"organizationId,omitempty"`
	ConfigID       string         `json:"configId,omitempty"`
	Name           string         `json:"name,omitempty"`
	Prefix         string         `json:"prefix,omitempty"`
	ExpiresIn      *int64         `json:"expiresIn,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type UpdateAPIKeyRequest struct {
	KeyID           string         `json:"keyId"`
	ConfigID        string         `json:"configId,omitempty"`
	Name            *string        `json:"name,omitempty"`
	Enabled         *bool          `json:"enabled,omitempty"`
	ExpiresIn       *int64         `json:"expiresIn,omitempty"`
	ClearExpiration bool           `json:"-"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

func (c *Client) CreateAPIKey(ctx context.Context, input CreateAPIKeyRequest) (*apikey.Created, error) {
	var result apikey.Created
	if err := c.Do(ctx, http.MethodPost, "/api-key/create", input, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
func (c *Client) GetAPIKey(ctx context.Context, id, configID string) (*apikey.Key, error) {
	q := url.Values{"id": {id}}
	if configID != "" {
		q.Set("configId", configID)
	}
	var result apikey.Key
	if err := c.Do(ctx, http.MethodGet, "/api-key/get?"+q.Encode(), nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
func (c *Client) UpdateAPIKey(ctx context.Context, input UpdateAPIKeyRequest) (*apikey.Key, error) {
	body := map[string]any{"keyId": input.KeyID}
	if input.ConfigID != "" {
		body["configId"] = input.ConfigID
	}
	if input.Name != nil {
		body["name"] = *input.Name
	}
	if input.Enabled != nil {
		body["enabled"] = *input.Enabled
	}
	if input.ClearExpiration {
		body["expiresIn"] = nil
	} else if input.ExpiresIn != nil {
		body["expiresIn"] = *input.ExpiresIn
	}
	if input.Metadata != nil {
		body["metadata"] = input.Metadata
	}
	var result apikey.Key
	if err := c.Do(ctx, http.MethodPost, "/api-key/update", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
func (c *Client) DeleteAPIKey(ctx context.Context, id, configID string) error {
	body := map[string]string{"keyId": id}
	if configID != "" {
		body["configId"] = configID
	}
	return c.Do(ctx, http.MethodPost, "/api-key/delete", body, nil)
}
func (c *Client) ListAPIKeys(ctx context.Context, configID string, o apikey.PageOptions) (*apikey.Page, error) {
	q := url.Values{}
	if o.OrganizationID != "" {
		q.Set("organizationId", o.OrganizationID)
	}
	if configID != "" {
		q.Set("configId", configID)
	}
	if o.Limit != nil {
		q.Set("limit", strconv.Itoa(*o.Limit))
	}
	if o.Offset != nil {
		q.Set("offset", strconv.Itoa(*o.Offset))
	}
	if o.SortBy != "" {
		q.Set("sortBy", o.SortBy)
	}
	if o.SortDirection != "" {
		q.Set("sortDirection", o.SortDirection)
	}
	var page apikey.Page
	if err := c.Do(ctx, http.MethodGet, "/api-key/list?"+q.Encode(), nil, &page); err != nil {
		return nil, err
	}
	return &page, nil
}
