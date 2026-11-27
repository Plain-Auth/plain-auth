package client

import (
	"context"
	"net/http"
)

// EndOAuthSession holds the RP-Initiated Logout parameters.
type EndOAuthSession struct {
	IDTokenHint           string `json:"id_token_hint,omitempty"`
	ClientID              string `json:"client_id,omitempty"`
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri,omitempty"`
	State                 string `json:"state,omitempty"`
}

// EndOAuthSession asks the OAuth provider to end a session with an ID token
// hint. It returns the registered post-logout redirect URL, or "" when there
// is none. A request that needs the user's confirmation fails.
func (c *Client) EndOAuthSession(ctx context.Context, in EndOAuthSession) (string, error) {
	var result *struct {
		URL string `json:"url"`
	}
	if err := c.Do(ctx, http.MethodPost, "/oauth2/end-session", in, &result); err != nil || result == nil {
		return "", err
	}
	return result.URL, nil
}
