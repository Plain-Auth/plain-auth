package client

import (
	"context"
	"net/http"
	"net/url"

	"github.com/Plain-Org/plain-auth/plugins/sso"
)

type RegisterSAMLProviderRequest struct {
	ProviderID     string         `json:"providerId"`
	Domain         string         `json:"domain"`
	Issuer         string         `json:"issuer"`
	OrganizationID string         `json:"organizationId,omitempty"`
	SAML           sso.SAMLConfig `json:"samlConfig"`
}

func (c *Client) RegisterSAMLProvider(ctx context.Context, in RegisterSAMLProviderRequest) (sso.Registered, error) {
	var out sso.Registered
	err := c.Do(ctx, http.MethodPost, "/sso/register", in, &out)
	return out, err
}

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

// SSOSignInRequest selects a persisted enterprise provider and trusted application
// return destinations. CallbackURL is required.
type SSOSignInRequest struct {
	// OAuthQuery is the verified issuer login query to resume after OIDC sign-in.
	OAuthQuery         string            `json:"oauth_query,omitempty"`
	ProviderType       string            `json:"providerType,omitempty"`
	ProviderID         string            `json:"providerId,omitempty"`
	OrganizationSlug   string            `json:"organizationSlug,omitempty"`
	Domain             string            `json:"domain,omitempty"`
	Email              string            `json:"email,omitempty"`
	CallbackURL        string            `json:"callbackURL"`
	NewUserCallbackURL string            `json:"newUserCallbackURL,omitempty"`
	ErrorCallbackURL   string            `json:"errorCallbackURL,omitempty"`
	LoginHint          string            `json:"loginHint,omitempty"`
	Scopes             []string          `json:"scopes,omitempty"`
	AdditionalParams   map[string]string `json:"additionalParams,omitempty"`
	RequestSignUp      bool              `json:"requestSignUp,omitempty"`
}
type SSOAuthorization struct {
	URL      string `json:"url"`
	Redirect bool   `json:"redirect"`
}

// SignInSSO starts authorization for the browser that owns the client's cookie jar.
func (c *Client) SignInSSO(ctx context.Context, in SSOSignInRequest) (SSOAuthorization, error) {
	var result SSOAuthorization
	err := c.Do(ctx, http.MethodPost, "/sign-in/sso", in, &result)
	return result, err
}

// DeleteSSOProvider deletes a managed provider and its linked accounts.
func (c *Client) DeleteSSOProvider(ctx context.Context, providerID string) error {
	return c.Do(ctx, http.MethodPost, "/sso/delete-provider", map[string]string{"providerId": providerID}, nil)
}

// RequestSSODomainVerification returns the current seven-day DNS challenge.
func (c *Client) RequestSSODomainVerification(ctx context.Context, providerID string) (string, error) {
	var out struct {
		Token string `json:"domainVerificationToken"`
	}
	err := c.Do(ctx, http.MethodPost, "/sso/request-domain-verification", map[string]string{"providerId": providerID}, &out)
	return out.Token, err
}

// VerifySSODomain confirms DNS ownership of every domain in the provider registration.
func (c *Client) VerifySSODomain(ctx context.Context, providerID string) error {
	return c.Do(ctx, http.MethodPost, "/sso/verify-domain", map[string]string{"providerId": providerID}, nil)
}

// UpdateSAMLMetadata rotates the trusted inline IdP metadata for a managed directory.
func (c *Client) UpdateSAMLMetadata(ctx context.Context, id, metadata string) (sso.PublicProvider, error) {
	var result sso.PublicProvider
	err := c.Do(ctx, "POST", "/sso/update-provider", map[string]any{"providerId": id, "samlConfig": map[string]any{"idpMetadata": map[string]string{"metadata": metadata}}}, &result)
	return result, err
}
