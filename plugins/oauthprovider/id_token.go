package oauthprovider

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

// IDTokenGrant holds the client-specific identity authorized for an ID token.
// A zero authentication time is omitted, as are an absent nonce or logout session.
type IDTokenGrant struct {
	Subject, Nonce, SessionID string
	AuthTime                  time.Time
}

// DelegatedTokenIssue is the validated grant supplied outside database locks.
// SessionID identifies the original session for refresh-token encoding. The
// ID token's SessionID is set only for a live session of a logout-enabled client.
type DelegatedTokenIssue struct {
	SessionID string
	Refresh   bool
	IDToken   IDTokenGrant
}

// OpenIDGrantStore performs signing outside the grant transaction, then
// rechecks the code or refresh token, session and client policy before commit.
// An issuance failure leaves the original credential available for retry.
type OpenIDGrantStore interface {
	OfflineAuthorizationCodeStore
	RefreshGrantStore
	RedeemOpenIDCode(ctx context.Context, clientID, identifier string, check func(MachineClient) error, prepare func(AuthorizationCodeClient, json.RawMessage) (DelegatedAccessRecord, error), issue func(DelegatedTokenIssue) (string, error)) error
	ExchangeOpenIDRefresh(ctx context.Context, clientID, digest string, check func(MachineClient) error, prepare func(AuthorizationCodeClient, RefreshGrant) (DelegatedAccessRecord, error), issue func(DelegatedTokenIssue) (RefreshGrantDigests, error)) error
}

func canIssueIDToken(c auth.EndpointContext) bool {
	_, ok := c.Store().(OpenIDGrantStore)
	return ok && c.Auth.PublicJWKSURL() != ""
}

func (opts Options) idTokenGrant(client AuthorizationCodeClient, user, liveSession, nonce string, at time.Time) (IDTokenGrant, error) {
	subject := user
	if client.SubjectType == "pairwise" {
		var err error
		subject, err = pairwiseSubject(opts.PairwiseSecret, user, client.RedirectURIs)
		if err != nil {
			return IDTokenGrant{}, err
		}
	}
	if subject == "" {
		return IDTokenGrant{}, errors.New("oauthprovider: missing ID token subject")
	}
	if !client.EmitSessionID {
		liveSession = ""
	}
	return IDTokenGrant{Subject: subject, Nonce: nonce, SessionID: liveSession, AuthTime: at.UTC()}, nil
}

func (opts TokenOptions) signIDToken(c auth.EndpointContext, clientID, access string, grant IDTokenGrant, now time.Time) (string, error) {
	alg := c.Auth.JWTSigningAlgorithm()
	var hash []byte
	switch alg {
	case "RS256", "ES256", "PS256":
		sum := sha256.Sum256([]byte(access))
		hash = sum[:len(sum)/2]
	case "EdDSA", "ES512":
		sum := sha512.Sum512([]byte(access))
		hash = sum[:len(sum)/2]
	default:
		return "", errors.New("oauthprovider: ID token signing algorithm unavailable")
	}
	claims := map[string]any{"acr": "0", "at_hash": base64.RawURLEncoding.EncodeToString(hash)}
	if !grant.AuthTime.IsZero() {
		claims["auth_time"] = grant.AuthTime.Unix()
	}
	if grant.Nonce != "" {
		claims["nonce"] = grant.Nonce
	}
	if grant.SessionID != "" {
		claims["sid"] = grant.SessionID
	}
	return c.Auth.SignJWT(c.Request.Context(), grant.Subject, auth.JWTSignOptions{
		Algorithm: alg, Issuer: c.Auth.OAuthIssuer(), Audience: []string{clientID}, Claims: claims,
		IssuedAt: now, ExpiresAt: now.Add(opts.IDTokenLifetime),
	})
}
