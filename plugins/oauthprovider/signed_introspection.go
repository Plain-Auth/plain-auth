package oauthprovider

import (
	"context"

	auth "github.com/Plain-Org/plain-auth"
)

// SignedAccessGrant contains the authorization context of a verified JWT.
type SignedAccessGrant struct {
	ClientID, SessionID string
	Audiences           []string
}

// SignedGrantClient supplies the issuing registration's subject policy.
type SignedGrantClient struct {
	SubjectType  string
	RedirectURIs []string
}

// SignedAccessIntrospectionStore reads the caller, issuer, audience links and
// session in a single snapshot. Return a nil issuer for an inactive grant or
// unauthorized caller. Treat the UserInfo URL as an implicit audience only.
type SignedAccessIntrospectionStore interface {
	MachineClientReader
	InspectSignedAccessGrant(ctx context.Context, callerID, userInfoURL string, grant SignedAccessGrant) (MachineClient, *SignedGrantClient, error)
}

func (opts Options) introspectSigned(c auth.EndpointContext, req tokenAction, first MachineClient, reader MachineClientReader) (any, bool, error) {
	claims, known, err := c.OAuthJWTPayload(req.token)
	if err != nil || !known {
		return nil, known, err
	}
	ctx := c.Request.Context()
	grant, valid := signedGrant(claims)
	store, supported := reader.(SignedAccessIntrospectionStore)
	inactive := map[string]bool{"active": false}
	if !valid || !supported {
		return inactive, true, tokenEndpointError(c.ResponseHeader, req.challenge, req.checkCurrent(ctx, reader, first))
	}
	current, owner, err := store.InspectSignedAccessGrant(ctx, req.client.id, c.Auth.PublicURL()+"/oauth2/userinfo", grant)
	if err == nil {
		err = req.client.recheckClient(first, current)
	}
	if err != nil {
		return nil, true, tokenEndpointError(c.ResponseHeader, req.challenge, err)
	}
	if owner == nil {
		return inactive, true, nil
	}
	claims["active"], claims["client_id"], claims["token_type"] = true, grant.ClientID, "Bearer"
	sub, _ := claims["sub"].(string)
	cnf, _ := claims["cnf"].(map[string]any)
	result, err := opts.addTokenIdentity(claims, grant.ClientID, sub, owner.SubjectType, owner.RedirectURIs, cnf)
	return result, true, err
}

func signedGrant(claims map[string]any) (SignedAccessGrant, bool) {
	var g SignedAccessGrant
	g.ClientID, _ = claims["azp"].(string)
	if g.ClientID == "" {
		return g, false
	}
	if sid := claims["sid"]; sid != nil {
		var ok bool
		if g.SessionID, ok = sid.(string); !ok {
			return g, false
		}
	}
	if sub := claims["sub"]; sub != nil {
		if _, ok := sub.(string); !ok {
			return g, false
		}
	}
	if raw, exists := claims["aud"]; exists {
		switch aud := raw.(type) {
		case string:
			g.Audiences = []string{aud}
		case []any:
			if len(aud) > 64 {
				return g, false
			}
			for _, item := range aud {
				value, ok := item.(string)
				if !ok {
					return g, false
				}
				g.Audiences = append(g.Audiences, value)
			}
		default:
			return g, false
		}
	}
	return g, true
}
