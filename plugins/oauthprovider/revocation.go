package oauthprovider

import (
	"context"
	"errors"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
)

// ErrInvalidRefreshToken means a configured decoder did not recognize the value.
var ErrInvalidRefreshToken = errors.New("oauthprovider: unrecognized refresh token")

type StoredTokenKind string

const (
	StoredAccessToken  StoredTokenKind = "access_token"
	StoredRefreshToken StoredTokenKind = "refresh_token"
)

// RevocationStore locks the registration, calls check, and revokes an owned
// token in one transaction. Replaying an owned revoked refresh token removes
// the refresh family for that client and user. Return false for a missing row.
type RevocationStore interface {
	MachineClientReader
	RevokeOAuthToken(ctx context.Context, clientID, digest string, kind StoredTokenKind, check func(MachineClient) error) (bool, error)
}

const revocationOperation = `{
  "summary":"Revoke an OAuth access or refresh token",
  "description":"Use the registered client's authentication method. A public client supplies its client ID.",
  "security":[{"clientSecretBasic":[]},{}],
  "requestBody":{"required":true,"content":{"application/x-www-form-urlencoded":{"schema":{
    "type":"object","required":["token"],"properties":{"token":{"type":"string"},"token_type_hint":{"type":"string"},
      "client_id":{"type":"string"},"client_secret":{"type":"string","format":"password"},"client_assertion_type":{"type":"string","enum":["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]},
      "client_assertion":{"type":"string","format":"jwt"}}
  }}}},
  "responses":{"200":{"description":"Revocation processed. The body is empty."},
  "400":{"description":"Invalid request, rejected credentials or unsupported self-contained access token"},
  "401":{"description":"Client authentication required"},"415":{"description":"Unsupported request media type"}}
}`

func (opts Options) revoke(c auth.EndpointContext) (any, error) {
	req, err := readTokenAction(c, false)
	if err != nil {
		return nil, err
	}
	store, ok := c.Store().(RevocationStore)
	if !ok {
		return nil, &auth.APIError{Status: 501, Code: "OAUTH_REVOCATION_STORE_UNAVAILABLE", Message: "The configured store does not support OAuth token revocation"}
	}
	ctx := c.Request.Context()
	first, err := opts.authenticateClient(c, store, req.client, "/oauth2/revoke")
	if err != nil {
		return nil, tokenEndpointError(c.ResponseHeader, req.challenge, err)
	}
	check := func(current MachineClient) error { return req.client.recheckClient(first, current) }
	kinds := [2]StoredTokenKind{StoredAccessToken, StoredRefreshToken}
	if req.hint == string(StoredRefreshToken) {
		kinds[0], kinds[1] = kinds[1], kinds[0]
	}
	for _, kind := range kinds {
		if kind == StoredAccessToken && strings.Count(req.token, ".") == 2 {
			handled, jwtErr := checkRevocationJWT(c, req.token)
			if handled || jwtErr != nil {
				err := req.checkCurrent(ctx, store, first)
				if err != nil {
					return nil, tokenEndpointError(c.ResponseHeader, req.challenge, err)
				}
				return auth.EmptyResponse{}, jwtErr
			}
		}
		digest, err := opts.Tokens.storedTokenDigest(ctx, req.token, kind)
		if err != nil {
			return nil, err
		}
		if digest == "" {
			continue
		}
		found, err := store.RevokeOAuthToken(ctx, req.client.id, digest, kind, check)
		if err != nil {
			return nil, tokenEndpointError(c.ResponseHeader, req.challenge, err)
		}
		if found {
			return auth.EmptyResponse{}, nil
		}
	}
	return auth.EmptyResponse{}, tokenEndpointError(c.ResponseHeader, req.challenge, req.checkCurrent(ctx, store, first))
}

func (req tokenAction) checkCurrent(ctx context.Context, store MachineClientReader, first MachineClient) error {
	current, err := store.LookupMachineClient(ctx, req.client.id)
	if err != nil {
		return err
	}
	return req.client.recheckClient(first, current)
}

func checkRevocationJWT(c auth.EndpointContext, token string) (bool, error) {
	return c.CheckOAuthJWTRevocation(token, func(ctx context.Context, audience string) (bool, error) {
		store, ok := c.Store().(interface {
			OAuthResource(context.Context, string) (Resource, error)
		})
		if !ok {
			return false, errors.New("oauthprovider: resource lookup unavailable")
		}
		resource, err := store.OAuthResource(ctx, audience)
		if errors.Is(err, auth.ErrNotFound) {
			return false, nil
		}
		return resource.Identifier == audience, err
	})
}

func (opts TokenOptions) storedTokenDigest(ctx context.Context, token string, kind StoredTokenKind) (string, error) {
	if kind == StoredAccessToken {
		raw, ok := strings.CutPrefix(token, opts.OpaquePrefix)
		if !ok || raw == "" {
			return "", nil
		}
		return opts.storedOpaque(ctx, raw)
	}
	raw, ok := strings.CutPrefix(token, opts.RefreshPrefix)
	if !ok || raw == "" {
		return "", nil
	}
	if opts.DecodeRefreshToken != nil {
		var err error
		raw, err = opts.DecodeRefreshToken(ctx, raw)
		if errors.Is(err, ErrInvalidRefreshToken) {
			return "", nil
		}
		if err != nil || raw == "" {
			return "", err
		}
	}
	return opts.storedRefresh(ctx, raw)
}

func (opts TokenOptions) storedRefresh(ctx context.Context, raw string) (string, error) {
	if opts.HashRefreshToken == nil {
		return tokenDigest(raw), nil
	}
	digest, err := opts.HashRefreshToken(ctx, raw)
	if err == nil && digest == "" {
		return "", errors.New("oauthprovider: empty stored refresh token")
	}
	return digest, err
}
