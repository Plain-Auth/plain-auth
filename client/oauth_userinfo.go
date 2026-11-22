package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// OAuthUserInfo reads claims for an OpenID Connect access token. For a
// sender-bound token, pass a fresh DPoP proof signed for a GET to the public
// UserInfo URL. Response headers include any OAuth authentication challenge.
func (c *Client) OAuthUserInfo(ctx context.Context, token, proof string) (map[string]json.RawMessage, http.Header, error) {
	if token == "" {
		return nil, nil, errors.New("plainauth/client: UserInfo requires an access token")
	}
	scheme := "Bearer"
	headers := make(http.Header)
	if proof != "" {
		scheme = "DPoP"
		headers.Set("DPoP", proof)
	}
	headers.Set("Authorization", scheme+" "+token)
	var claims map[string]json.RawMessage
	response, err := c.doWithHeaders(ctx, http.MethodGet, "/oauth2/userinfo", nil, &claims, headers)
	return claims, response, err
}
