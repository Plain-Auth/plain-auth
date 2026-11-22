package oauthprovider

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"
)

// OpaqueAccessIntrospectionStore authenticates the current registration and
// reads the grant, issuing client, session, and resource policy in one snapshot.
// A non-owner may see a grant only through a link to a registered audience.
// A known but inactive or unauthorized access token still takes precedence over
// a refresh token with the same digest.
type OpaqueAccessIntrospectionStore interface {
	MachineClientReader
	InspectOpaqueAccessToken(ctx context.Context, callerID, digest, userInfoURL string) (MachineClient, *OpaqueAccessTokenRecord, bool, error)
}

// OpaqueAccessTokenRecord carries the issuing application’s identity and the
// current resource claims. UserID is the account ID before pairwise presentation.
type OpaqueAccessTokenRecord struct {
	MachineTokenRecord
	ClientID, UserID, SessionID string
	SessionExpiresAt            time.Time
	SubjectType                 string
	RedirectURIs, Resources     []string
	Confirmation                map[string]any
	ResourceClaims              map[string]json.RawMessage
}

func (opts Options) opaqueIntrospectionClaims(token *OpaqueAccessTokenRecord, digest, issuer, userInfoURL string) (any, error) {
	now := time.Now()
	if token == nil || digest == "" || token.StoredToken != digest || token.ClientID == "" || !token.ExpiresAt.After(now) ||
		token.SessionID != "" && !token.SessionExpiresAt.After(now) {
		return map[string]bool{"active": false}, nil
	}
	claims := map[string]any{"active": true, "iss": issuer, "client_id": token.ClientID, "azp": token.ClientID,
		"token_type": "Bearer", "iat": token.IssuedAt.Unix(), "exp": token.ExpiresAt.Unix(), "scope": strings.Join(token.Scopes, " ")}
	for name, raw := range token.ResourceClaims {
		// Resource policies may add application claims. Protocol fields, including
		// optional fields absent from this grant, are controlled by the issuer.
		switch name {
		case "active", "iss", "sub", "aud", "exp", "iat", "jti", "client_id", "azp", "scope", "auth_time", "acr", "amr", "cnf", "sid", "token_type":
			continue
		}
		claims[name] = raw
	}
	aud := token.Resources
	if len(aud) > 0 && slices.Contains(token.Scopes, "openid") && !slices.Contains(aud, userInfoURL) {
		aud = append(slices.Clone(aud), userInfoURL)
	}
	if len(aud) == 1 {
		claims["aud"] = aud[0]
	} else if len(aud) > 1 {
		claims["aud"] = aud
	}
	if token.SessionID != "" {
		claims["sid"] = token.SessionID
	}
	return opts.addTokenIdentity(claims, token.ClientID, token.UserID, token.SubjectType, token.RedirectURIs, token.Confirmation)
}

func (opts Options) addTokenIdentity(claims map[string]any, clientID, userID, subjectType string, redirects []string, confirmation map[string]any) (map[string]any, error) {
	if userID != "" {
		if subjectType == "pairwise" && userID != clientID {
			subject, err := pairwiseSubject(opts.PairwiseSecret, userID, redirects)
			if err != nil {
				return nil, err
			}
			userID = subject
		}
		claims["sub"] = userID
	}
	if confirmation != nil {
		claims["cnf"] = confirmation
		if jkt, _ := confirmation["jkt"].(string); jkt != "" {
			claims["token_type"] = "DPoP"
		}
	}
	return claims, nil
}
