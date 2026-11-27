package oauthprovider

import (
	auth "github.com/Plain-Org/plain-auth"
)

// ValidateAccessToken returns an access token's introspection payload,
// which may be inactive, as another runtime's validateAccessToken does. A
// non-empty clientID sees the token as that client would at the
// introspection endpoint, the issuer or a client linked to one of its
// resources, without authenticating it; an empty one sees it as the issuer
// does. A refresh token is never active here, and an unknown token is
// inactive, where another runtime refuses it (simplicity).
func (p *ProviderAPI) ValidateAccessToken(token, clientID string) (map[string]any, error) {
	if clientID == "" {
		return p.issuerView(token)
	}
	c, opts := p.c, p.opts
	ctx := c.Request.Context()
	inactive := map[string]any{"active": false}
	userInfoURL := c.Auth.PublicURL() + "/oauth2/userinfo"
	claims, signed, err := c.OAuthJWTPayload(token)
	if err != nil {
		return nil, err
	}
	if signed {
		grant, valid := signedGrant(claims)
		store, ok := c.Store().(SignedAccessIntrospectionStore)
		if !valid || !ok {
			return inactive, nil
		}
		_, owner, err := store.InspectSignedAccessGrant(ctx, clientID, userInfoURL, grant)
		if err != nil || owner == nil {
			return inactive, err
		}
		claims["active"], claims["client_id"], claims["token_type"] = true, grant.ClientID, "Bearer"
		sub, _ := claims["sub"].(string)
		cnf, _ := claims["cnf"].(map[string]any)
		return opts.addTokenIdentity(claims, grant.ClientID, sub, owner.SubjectType, owner.RedirectURIs, cnf)
	}
	store, ok := c.Store().(OpaqueAccessIntrospectionStore)
	if !ok {
		return nil, &auth.APIError{Status: 501, Code: "OAUTH_INTROSPECTION_STORE_UNAVAILABLE", Message: "The configured store does not support OAuth token introspection"}
	}
	digest, err := opts.Tokens.storedTokenDigest(ctx, token, StoredAccessToken)
	if err != nil || digest == "" {
		return inactive, err
	}
	_, access, _, err := store.InspectOpaqueAccessToken(ctx, clientID, digest, userInfoURL)
	if err != nil {
		return nil, err
	}
	claims = opaqueAccessClaims(access, digest, c.Auth.OAuthIssuer(), userInfoURL)
	if claims["active"] != true {
		return claims, nil
	}
	return opts.addTokenIdentity(claims, access.ClientID, access.UserID, access.SubjectType, access.RedirectURIs, nil)
}

// issuerView validates a token through the issuer's own lookup, the one
// UserInfo uses.
func (p *ProviderAPI) issuerView(token string) (map[string]any, error) {
	c, opts := p.c, p.opts
	store, ok := c.Store().(UserInfoStore)
	if !ok {
		return nil, &auth.APIError{Status: 501, Code: "OAUTH_USERINFO_STORE_UNAVAILABLE", Message: "The configured store does not support OAuth UserInfo"}
	}
	record, claims, err := opts.userInfoAccess(c, store, token, c.Auth.PublicURL()+"/oauth2/userinfo")
	if err != nil || record == nil {
		return map[string]any{"active": false}, err
	}
	if access := record.Opaque; access != nil {
		return opts.addTokenIdentity(claims, access.ClientID, access.UserID, access.SubjectType, access.RedirectURIs, nil)
	}
	client, _ := claims["client_id"].(string)
	sub, _ := claims["sub"].(string)
	return opts.addTokenIdentity(claims, client, sub, record.Issuer.SubjectType, record.Issuer.RedirectURIs, nil)
}

// RequireActiveAccessToken returns an active token's payload, as
// ValidateAccessToken does, and refuses any other with 401 invalid_token
// and a Bearer challenge. It checks the token, not a DPoP proof.
func (p *ProviderAPI) RequireActiveAccessToken(token, clientID string) (map[string]any, error) {
	claims, err := p.ValidateAccessToken(token, clientID)
	if err != nil {
		return nil, err
	}
	if claims["active"] != true {
		p.c.ResponseHeader.Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Invalid access token"`)
		return nil, registrationProblem(401, "invalid_token", "Invalid access token")
	}
	return claims, nil
}
