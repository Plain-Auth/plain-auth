package oauthprovider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// IDTokenGrant holds the client-specific identity authorized for an ID token.
// A zero authentication time is omitted, as are an absent nonce or logout session.
type IDTokenGrant struct {
	Subject, Nonce, SessionID string
	AuthTime                  time.Time
	// ClaimsInput is an immutable JSON encoding of IDTokenClaimsInput when the
	// store was asked for IDTokenUserFields. Compare it again before commit.
	ClaimsInput string `json:"-"`
}

// IDTokenClaimsInput describes the current account and approved scopes. User
// has its internal ID even for pairwise clients. UserFields contains configured
// attributes, including hidden ones, keyed by logical name. Metadata is only
// the registered client's metadata object. Each invocation owns its input.
type IDTokenClaimsInput struct {
	User       auth.User
	UserFields map[string]json.RawMessage
	Scopes     []string
	Metadata   map[string]json.RawMessage
}

// IDTokenClaimsFunc contributes application claims to one signed ID token.
type IDTokenClaimsFunc func(context.Context, IDTokenClaimsInput) (map[string]any, error)

// DelegatedTokenIssue is the validated grant supplied outside database locks.
// SessionID identifies the original session for refresh-token encoding. The
// ID token's SessionID is set only for a live session of a logout-enabled client.
type DelegatedTokenIssue struct {
	SessionID string
	Refresh   bool
	IDToken   IDTokenGrant
	// Deferred asks for the issue phase even without a refresh or ID token,
	// for host response fields.
	Deferred bool
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

// idTokenSecret is the HS256 key for an ID token: the client secret the
// request authenticated with, when DisableJWTPlugin is set.
func (opts Options) idTokenSecret(in tokenRequest) string {
	if opts.DisableJWTPlugin {
		return in.secret
	}
	return ""
}

func (opts Options) canIssueIDToken(c auth.EndpointContext) bool {
	_, ok := c.Store().(OpenIDGrantStore)
	return ok && (opts.DisableJWTPlugin || c.Auth.PublicJWKSURL() != "")
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

// signIDToken signs with the jwt plugin, or with HS256 keyed by secret, the
// client secret the client holds, when secret is set. That key includes a
// configured SecretPrefix, as OIDC asks; another runtime keys it with the
// unprefixed stored value, so the two differ only with a prefix.
// idTokenContributors carries the extensions' ID-token claims and the grant
// type they see.
type idTokenContributors struct {
	grantType  string
	extensions []Extension
	// claims are an extension grant's per-issuance claims, which win over
	// the extensions' within the add-only layer, as in another runtime.
	claims map[string]any
}

func (opts Options) extendsIDTokens() bool {
	return slices.ContainsFunc(opts.Extensions, func(e Extension) bool { return e.IDTokenClaims != nil })
}

func (opts Options) idTokenContributors(grantType string) idTokenContributors {
	return idTokenContributors{grantType: grantType, extensions: opts.Extensions}
}

// standardIDClaim reports a claim an ID-token extension cannot set: a
// reserved protocol claim or a standard profile or email claim.
func standardIDClaim(name string) bool {
	switch name {
	case "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "auth_time", "nonce", "acr", "amr", "azp", "sid", "at_hash", "c_hash", "s_hash",
		"name", "picture", "given_name", "family_name", "email", "email_verified":
		return true
	}
	return false
}

// add adds the extensions' ID-token claims where the token
// has no such claim, as another runtime's additive layer does.
func (x idTokenContributors) add(c auth.EndpointContext, claims map[string]any, clientID string, grant IDTokenGrant) error {
	for name, value := range x.claims {
		if _, present := claims[name]; !present && !standardIDClaim(name) {
			claims[name] = value
		}
	}
	if !slices.ContainsFunc(x.extensions, func(e Extension) bool { return e.IDTokenClaims != nil }) {
		return nil
	}
	var snapshot IDTokenClaimsInput
	if err := json.Unmarshal([]byte(grant.ClaimsInput), &snapshot); err != nil || snapshot.User.ID == "" {
		return errors.New("oauthprovider: missing ID token claims input")
	}
	in := TokenClaimsInput{User: &snapshot.User, ClientID: clientID, Scopes: snapshot.Scopes, GrantType: x.grantType, Metadata: snapshot.Metadata, UserFields: snapshot.UserFields}
	added := map[string]bool{}
	for _, extension := range x.extensions {
		if extension.IDTokenClaims == nil {
			continue
		}
		extra, err := extension.IDTokenClaims(c.Request.Context(), in)
		if err != nil {
			return err
		}
		for name, value := range extra {
			if added[name] {
				c.Auth.Logger().WarnContext(c.Request.Context(), "OAuth provider extensions supplied the same ID token claim", "claim", name)
				continue
			}
			if _, present := claims[name]; present || standardIDClaim(name) {
				continue
			}
			claims[name], added[name] = value, true
		}
	}
	return nil
}

func (opts TokenOptions) signIDToken(c auth.EndpointContext, clientID, access string, grant IDTokenGrant, now time.Time, secret string, contributors idTokenContributors) (string, error) {
	alg := c.Auth.JWTSigningAlgorithm()
	if secret != "" {
		alg = "HS256"
	}
	var hash []byte
	switch alg {
	case "RS256", "ES256", "PS256", "HS256":
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
	if opts.CustomIDTokenClaims != nil {
		var input IDTokenClaimsInput
		if err := json.Unmarshal([]byte(grant.ClaimsInput), &input); err != nil || input.User.ID == "" || !slices.Contains(input.Scopes, "openid") {
			return "", errors.New("oauthprovider: missing ID token claims input")
		}
		extra, err := opts.CustomIDTokenClaims(c.Request.Context(), input)
		if err != nil {
			return "", err
		}
		var reserved []string
		for name, value := range extra {
			switch name {
			case "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "auth_time", "nonce", "acr", "amr", "azp", "sid", "at_hash", "c_hash", "s_hash":
				reserved = append(reserved, name)
			default:
				claims[name] = value
			}
		}
		if len(reserved) != 0 {
			slices.Sort(reserved)
			c.Auth.Logger().WarnContext(c.Request.Context(), "OAuth ID token ignored reserved claim names", "claims", reserved)
		}
	}
	if err := contributors.add(c, claims, clientID, grant); err != nil {
		return "", err
	}
	if secret != "" {
		claims["iss"], claims["sub"], claims["aud"] = c.Auth.OAuthIssuer(), grant.Subject, clientID
		claims["iat"], claims["exp"] = now.Unix(), now.Add(opts.IDTokenLifetime).Unix()
		payload, err := json.Marshal(claims)
		if err != nil {
			return "", err
		}
		signing := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(signing))
		return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
	}
	return c.Auth.SignJWT(c.Request.Context(), grant.Subject, auth.JWTSignOptions{
		Algorithm: alg, Issuer: c.Auth.OAuthIssuer(), Audience: []string{clientID}, Claims: claims,
		IssuedAt: now, ExpiresAt: now.Add(opts.IDTokenLifetime),
	})
}
