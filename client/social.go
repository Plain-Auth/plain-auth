package client

import (
	"context"
	"net/http"

	auth "github.com/Plain-Org/plain-auth"
)

// SocialSignInRequest starts a browser flow or exchanges a provider's ID token.
// RequestSignUp opts in to creating a new account for this sign-in.
type SocialSignInRequest struct {
	// OAuthQuery resumes a host-issued authorization request after sign-in.
	OAuthQuery         string            `json:"oauth_query,omitempty"`
	Provider           string            `json:"provider"`
	CallbackURL        string            `json:"callbackURL,omitempty"`
	NewUserCallbackURL string            `json:"newUserCallbackURL,omitempty"`
	ErrorCallbackURL   string            `json:"errorCallbackURL,omitempty"`
	RequestSignUp      bool              `json:"requestSignUp,omitempty"`
	DisableRedirect    bool              `json:"disableRedirect,omitempty"`
	Scopes             []string          `json:"scopes,omitempty"`
	LoginHint          string            `json:"loginHint,omitempty"`
	AdditionalParams   map[string]string `json:"additionalParams,omitempty"`
	// AdditionalData is application data the server keeps with a browser
	// flow and hands to its callback. An ID-token request ignores it.
	AdditionalData map[string]any `json:"additionalData,omitempty"`
	IDToken        *SocialIDToken `json:"idToken,omitempty"`
}

type SocialIDToken struct {
	Token string `json:"token"`
	Nonce string `json:"nonce"`
	// AccessToken repeats Token when Token is a provider access token, such
	// as a Facebook access token. Beside an ID token it, like RefreshToken,
	// only reaches the account-field mapper.
	AccessToken  string `json:"accessToken,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
}

type SocialSignInResult struct {
	Status   bool       `json:"status"`
	URL      string     `json:"url"`
	Redirect bool       `json:"redirect"`
	Token    string     `json:"token"`
	User     *auth.User `json:"user"`
}

// SignInSocial calls the provider registered under in.Provider.
// For browser sign-in present the returned URL in the browser that owns the state cookie.
func (c *Client) SignInSocial(ctx context.Context, in SocialSignInRequest) (*SocialSignInResult, error) {
	var result SocialSignInResult
	if err := c.Do(ctx, http.MethodPost, "/sign-in/social", in, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// LinkSocial adds an identity to the user who owns this client's session.
func (c *Client) LinkSocial(ctx context.Context, in SocialSignInRequest) (*SocialSignInResult, error) {
	var result SocialSignInResult
	if err := c.Do(ctx, http.MethodPost, "/link-social", in, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ProviderSignOutRequest selects a trusted application return address and the
// optional state the identity provider should pass back after sign-out.
type ProviderSignOutRequest struct {
	CallbackURL     string `json:"callbackURL,omitempty"`
	DisableRedirect bool   `json:"disableRedirect,omitempty"`
	State           string `json:"state,omitempty"`
}

func (c *Client) SignOutProvider(ctx context.Context, in ProviderSignOutRequest) (*auth.ProviderLogoutResult, error) {
	var result auth.ProviderLogoutResult
	if err := c.Do(ctx, http.MethodPost, "/sign-out", in, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
