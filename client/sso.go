package client

import (
	"context"
	"net/http"
	"net/url"

	"github.com/Stonewrit/stonewrit-auth/plugins/sso"
)

type RegisterOIDCProviderRequest struct {
	ProviderID       string           `json:"providerId"`
	Domain           string           `json:"domain"`
	Issuer           string           `json:"issuer"`
	OrganizationID   string           `json:"organizationId,omitempty"`
	OverrideUserInfo bool             `json:"overrideUserInfo,omitempty"`
	OIDC             OIDCRegistration `json:"oidcConfig"`
}
type OIDCRegistration struct {
	sso.Config
	SkipDiscovery bool `json:"skipDiscovery,omitempty"`
}

// RegisterOIDCProvider registers an enterprise provider using the owner's session.
// The result includes the confidential client configuration submitted by the caller.
func (c *Client) RegisterOIDCProvider(ctx context.Context, in RegisterOIDCProviderRequest) (sso.Registered, error) {
	var out sso.Registered
	err := c.Do(ctx, http.MethodPost, "/sso/register", in, &out)
	return out, err
}
func (c *Client) ListSSOProviders(ctx context.Context) ([]sso.PublicProvider, error) {
	var out struct {
		Providers []sso.PublicProvider `json:"providers"`
	}
	err := c.Do(ctx, http.MethodGet, "/sso/providers", nil, &out)
	return out.Providers, err
}
func (c *Client) GetSSOProvider(ctx context.Context, id string) (sso.PublicProvider, error) {
	var out sso.PublicProvider
	err := c.Do(ctx, http.MethodGet, "/sso/get-provider?"+url.Values{"providerId": {id}}.Encode(), nil, &out)
	return out, err
}
