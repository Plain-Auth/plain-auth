package oauthprovider

import (
	"errors"
	"slices"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// issueUserTokens issues an extension grant's tokens for a user, as a code
// exchange does without a code: an access token, an ID token for openid
// and a refresh token for offline_access when the client may refresh.
func (p *ProviderAPI) issueUserTokens(params TokenIssueParams) (TokenResponse, error) {
	c, opts := p.c, p.opts
	ctx := c.Request.Context()
	store, ok := c.Store().(GrantTokenStore)
	if !ok {
		return TokenResponse{}, &auth.APIError{Status: 501, Code: "OAUTH_GRANT_TOKEN_STORE_UNAVAILABLE", Message: "The configured store cannot issue user tokens for extension grants"}
	}
	resources := distinct(params.Resources)
	userInfo := c.Auth.PublicURL() + "/oauth2/userinfo"
	ids := slices.DeleteFunc(slices.Clone(resources), func(id string) bool { return id == userInfo })
	// The resources' policies are read outside the store's transaction, as
	// a code exchange reads them.
	var policy codeResources
	if len(ids) > 0 {
		var err error
		if policy, err = opts.readCodeResources(c, params.ClientID, ids); err != nil {
			return TokenResponse{}, err
		}
	}
	cnf, err := p.binding(params, false)
	if err != nil {
		return TokenResponse{}, err
	}
	var thumb string
	var other *Confirmation
	if cnf != nil && cnf.JKT != "" {
		thumb = cnf.JKT
	} else {
		other = cnf
	}
	issued, stored, err := opts.Tokens.newOpaqueToken(ctx)
	if err != nil {
		return TokenResponse{}, err
	}
	var reference *string
	if params.ReferenceID != "" {
		reference = &params.ReferenceID
	}
	now := time.Now().UTC().Truncate(time.Second)
	var token MachineToken
	var signing *delegatedSigning
	prepare := func(client AuthorizationCodeClient) (DelegatedAccessRecord, error) {
		signing = nil
		scopes := params.Scopes
		lifetime, err := opts.Tokens.scopeLifetime(opts.Tokens.AccessLifetime, scopes, now)
		if err != nil {
			return DelegatedAccessRecord{}, err
		}
		refreshLifetime := opts.Tokens.RefreshLifetime
		bound := client.RequireDPoP
		if len(resources) > 0 {
			granted, err := opts.Tokens.resourcePolicy(client.ClientID, false, scopes, ids, policy.rows, lifetime)
			if err != nil {
				return DelegatedAccessRecord{}, err
			}
			bound = bound || granted.bound
			if opts.signsResourceTokens(c) {
				signing = newDelegatedSigning(c, granted, resources, scopes)
				signing.claims, signing.cnf = params.AccessTokenClaims, cnf
			}
			scopes, lifetime, refreshLifetime = granted.scopes, granted.lifetime, granted.refreshLifetime(refreshLifetime)
		}
		if bound && thumb == "" {
			return DelegatedAccessRecord{}, proofError("DPoP proof header is required")
		}
		var claims []string
		if slices.Contains(scopes, "openid") {
			supported := opts.supportedUserInfoClaims()
			claims = slices.DeleteFunc(slices.Clone(params.RequestedUserInfoClaims), func(name string) bool { return !slices.Contains(supported, name) })
		}
		token = machineResponse(issued, thumb, scopes, now, lifetime)
		record := DelegatedAccessRecord{
			MachineTokenRecord: MachineTokenRecord{StoredToken: stored, Scopes: scopes, IssuedAt: now, ExpiresAt: now.Add(lifetime)},
			UserID:             params.UserID, SessionID: params.SessionID, ReferenceID: reference,
			RequestedUserInfoClaims: claims, Resources: resources, Thumbprint: thumb, Confirmation: other,
		}
		// A client without a secret gets no ID token when the secret signs it.
		if slices.Contains(scopes, "openid") && (!opts.DisableJWTPlugin || p.request.secret != "") {
			if !opts.canIssueIDToken(c) {
				return DelegatedAccessRecord{}, registrationProblem(501, "server_error", "ID token issuance is unavailable")
			}
			if opts.Tokens.CustomIDTokenClaims != nil || opts.extendsIDTokens() {
				record.IDTokenUserFields = c.TrustedUserFields()
			}
			record.IDToken, err = opts.idTokenGrant(client, params.UserID, params.SessionID, params.Nonce, params.AuthTime)
			if err != nil {
				return DelegatedAccessRecord{}, err
			}
		}
		if signing != nil {
			record.StoredToken, record.Deferred = "", true
			if opts.contributesAccessClaims() && record.IDTokenUserFields == nil {
				record.IDTokenUserFields = c.TrustedUserFields()
			}
		}
		if opts.Tokens.CustomTokenResponseFields != nil {
			record.Deferred = true
			if record.IDTokenUserFields == nil {
				record.IDTokenUserFields = c.TrustedUserFields()
			}
		}
		// The refresh token follows the requested scopes, as in another
		// runtime, and only for a client that may refresh.
		if slices.Contains(params.Scopes, "offline_access") && clientAllowsGrant(client.GrantTypes, "refresh_token") {
			record.Refresh = &InitialRefreshGrant{ExpiresAt: now.Add(refreshLifetime), Resources: resources}
			if !params.AuthTime.IsZero() {
				at := params.AuthTime.UTC()
				record.Refresh.AuthTime = &at
			}
		}
		return record, nil
	}
	var fields map[string]any
	var access, idToken, refresh string
	issue := func(grant DelegatedTokenIssue) (string, error) {
		if opts.Tokens.CustomTokenResponseFields != nil {
			input, err := claimsResponseInput(p.grant, grant.IDToken.ClaimsInput, nil)
			if err != nil {
				return "", err
			}
			if fields, err = opts.Tokens.responseFields(ctx, input); err != nil {
				return "", err
			}
		}
		// The ID token's at_hash covers the access token sent, signed or not.
		access = issued
		if signing != nil {
			if access, err = opts.signDelegated(c, signing, p.grant, params.ClientID, params.UserID, grant.SessionID, thumb, grant.IDToken.ClaimsInput, now); err != nil {
				return "", err
			}
		}
		if grant.IDToken.Subject != "" {
			contributors := opts.idTokenContributors(p.grant)
			contributors.claims = params.IDTokenClaims
			if idToken, err = opts.Tokens.signIDToken(c, params.ClientID, access, grant.IDToken, now, opts.idTokenSecret(p.request), contributors); err != nil {
				return "", err
			}
		}
		if !grant.Refresh {
			return "", nil
		}
		wire, digest, err := opts.Tokens.issueRefreshToken(ctx, grant.SessionID)
		refresh = wire
		return digest, err
	}
	err = store.StoreGrantTokens(ctx, params.ClientID, p.checkRegistration, prepare, issue)
	switch {
	case errors.Is(err, ErrAuthorizationUserMissing):
		err = registrationProblem(400, "invalid_user", "missing user, user may have been deleted")
	case errors.Is(err, ErrAuthorizationSessionExpired):
		err = registrationProblem(400, "invalid_request", "session no longer exists")
	case errors.Is(err, ErrGrantChanged):
		err = registrationProblem(400, "invalid_request", "grant changed during issuance, retry the request")
	}
	if err != nil {
		return TokenResponse{}, err
	}
	if access == "" {
		access = issued
	}
	return TokenResponse{AccessToken: access, TokenType: token.TokenType, ExpiresIn: token.ExpiresIn, ExpiresAt: token.ExpiresAt,
		Scope: token.Scope, RefreshToken: refresh, IDToken: idToken, Fields: params.responseFields(fields)}, nil
}
