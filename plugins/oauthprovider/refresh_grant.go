package oauthprovider

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// RefreshGrant describes the stored permissions and session at exchange time.
type RefreshGrant struct {
	Scopes, Resources              []string
	SessionID, AuthorizationCodeID string
	SessionLive, SenderBound       bool
	UserID                         string
	AuthTime                       time.Time
}

// RefreshGrantDigests contains only the storage keys of the credentials issued
// for a refresh exchange. Refresh is empty for an access-only exchange.
type RefreshGrantDigests struct{ Access, Refresh string }

// RefreshGrantStore authenticates the current registration before reading the
// grant, rejects expired or foreign credentials and serializes reuse handling.
// prepare is a local policy check. After validation the store calls issue
// outside database locks, revalidates and atomically records the
// parent revocation and both replacements. It copies user, session, reference,
// authorization code, authentication time and requested claims from the parent.
type RefreshGrantStore interface {
	MachineClientReader
	ExchangeRefreshGrant(ctx context.Context, clientID, digest string, checkClient func(MachineClient) error, prepare func(AuthorizationCodeClient, RefreshGrant) (DelegatedAccessRecord, error), issue func(sessionID string, rotate bool) (RefreshGrantDigests, error)) error
}

func (opts Options) exchangeRefreshGrant(c auth.EndpointContext, in tokenRequest, form url.Values) (DelegatedToken, error) {
	var result DelegatedToken
	if len(form["refresh_token"]) != 1 || form.Get("refresh_token") == "" {
		return result, registrationProblem(400, "invalid_request", "a single refresh_token is required")
	}
	if len(c.Request.Header.Values("DPoP")) > 1 {
		return result, proofError("DPoP proof header must not be repeated")
	}
	store, ok := c.Store().(RefreshGrantStore)
	if !ok {
		return result, &auth.APIError{Status: 501, Code: "OAUTH_REFRESH_STORE_UNAVAILABLE", Message: "The configured store does not support refresh-token exchange"}
	}
	first, err := opts.authenticateClient(c, store, in, "/oauth2/token")
	if err != nil {
		return result, err
	}
	checkClient := func(client MachineClient) error {
		if err := in.recheckClient(first, client); err != nil {
			return err
		}
		if len(client.GrantTypes) > 0 && !slices.Contains(client.GrantTypes, "authorization_code") && !slices.Contains(client.GrantTypes, "refresh_token") {
			return registrationProblem(400, "unauthorized_client", "client is not authorized to use grant type refresh_token")
		}
		return nil
	}
	if err := checkClient(first); err != nil {
		return result, err
	}
	ctx := c.Request.Context()
	digest, err := opts.Tokens.storedTokenDigest(ctx, form.Get("refresh_token"), StoredRefreshToken)
	if err != nil {
		return result, err
	}
	if digest == "" {
		return result, registrationProblem(400, "invalid_grant", "invalid refresh token")
	}
	var access string
	now := time.Now().UTC().Truncate(time.Second)
	openidStore, supportsOpenID := store.(OpenIDGrantStore)
	prepare := func(client AuthorizationCodeClient, grant RefreshGrant) (DelegatedAccessRecord, error) {
		scopes, err := grant.scopesForRefresh(client, in)
		if err != nil {
			return DelegatedAccessRecord{}, err
		}
		ttl, err := opts.Tokens.scopeLifetime(opts.Tokens.AccessLifetime, scopes, now)
		if err != nil {
			return DelegatedAccessRecord{}, err
		}
		result.MachineToken = machineResponse("", "", scopes, now, ttl)
		record := DelegatedAccessRecord{MachineTokenRecord: MachineTokenRecord{Scopes: scopes, IssuedAt: now, ExpiresAt: now.Add(ttl)}}
		if slices.Contains(scopes, "openid") && (!opts.DisableJWTPlugin || in.secret != "") {
			if !opts.canIssueIDToken(c) {
				return DelegatedAccessRecord{}, registrationProblem(501, "server_error", "ID token issuance is unavailable")
			}
			var sid string
			if grant.SessionLive {
				sid = grant.SessionID
			}
			if opts.Tokens.CustomIDTokenClaims != nil {
				record.IDTokenUserFields = c.TrustedUserFields()
			}
			record.IDToken, err = opts.idTokenGrant(client, grant.UserID, sid, "", grant.AuthTime)
			if err != nil {
				return DelegatedAccessRecord{}, err
			}
		}
		if slices.Contains(grant.Scopes, "offline_access") {
			record.Refresh = &InitialRefreshGrant{ExpiresAt: now.Add(opts.Tokens.RefreshLifetime)}
		}
		return record, nil
	}
	issue := func(sid string, rotate bool) (RefreshGrantDigests, error) {
		var keys RefreshGrantDigests
		var err error
		access, keys.Access, err = opts.Tokens.newOpaqueToken(ctx)
		if err == nil && rotate {
			result.RefreshToken, keys.Refresh, err = opts.Tokens.issueRefreshToken(ctx, sid)
		}
		return keys, err
	}
	if supportsOpenID {
		err = openidStore.ExchangeOpenIDRefresh(ctx, in.id, digest, checkClient, prepare, func(grant DelegatedTokenIssue) (RefreshGrantDigests, error) {
			keys, err := issue(grant.SessionID, grant.Refresh)
			if err == nil && grant.IDToken.Subject != "" {
				result.IDToken, err = opts.Tokens.signIDToken(c, in.id, access, grant.IDToken, now, opts.idTokenSecret(in))
			}
			return keys, err
		})
	} else {
		err = store.ExchangeRefreshGrant(ctx, in.id, digest, checkClient, prepare, issue)
	}
	if errors.Is(err, ErrInvalidRefreshToken) {
		err = registrationProblem(400, "invalid_grant", "invalid refresh token")
	}
	if err != nil {
		return DelegatedToken{}, err
	}
	result.AccessToken = access
	return result, nil
}

func (grant RefreshGrant) scopesForRefresh(client AuthorizationCodeClient, in tokenRequest) ([]string, error) {
	scopes := grant.Scopes
	if in.scopes != nil {
		scopes = in.scopes
		for _, scope := range scopes {
			if !slices.Contains(grant.Scopes, scope) {
				return nil, registrationProblem(400, "invalid_scope", "unable to issue scope "+scope)
			}
		}
	}
	for _, scope := range scopes {
		if client.Scopes != nil && !slices.Contains(client.Scopes, scope) {
			return nil, registrationProblem(400, "invalid_scope", "client does not allow scope "+scope)
		}
	}
	if !grant.SessionLive && (grant.SessionID != "" || grant.AuthorizationCodeID != "") && !slices.Contains(scopes, "offline_access") {
		return nil, ErrInvalidRefreshToken
	}
	if grant.SenderBound || in.proof != "" || client.RequireDPoP {
		if in.proof == "" {
			return nil, proofError("sender proof is required")
		}
		return nil, registrationProblem(501, "server_error", "sender-bound refresh issuance is unavailable")
	}
	if len(grant.Resources) > 0 || len(in.resources) > 0 {
		return nil, registrationProblem(501, "server_error", "resource-targeted refresh issuance is unavailable")
	}
	return scopes, nil
}
