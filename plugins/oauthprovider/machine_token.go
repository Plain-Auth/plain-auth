package oauthprovider

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// TokenOptions controls access and refresh tokens. Lifetimes use whole seconds.
type TokenOptions struct {
	// OpaqueResourceTokens selects stored tokens even when the JWT plugin is installed.
	OpaqueResourceTokens bool
	// AllowUnlinkedResources lets registered clients target enabled resources without a per-client link.
	AllowUnlinkedResources bool
	MachineLifetime        time.Duration
	// AccessLifetime applies to access tokens issued on behalf of a user.
	AccessLifetime time.Duration
	// IDTokenLifetime defaults to ten hours for an OpenID Connect ID token.
	IDTokenLifetime time.Duration
	// CustomIDTokenClaims runs outside store locks once per OpenID issuance.
	CustomIDTokenClaims IDTokenClaimsFunc
	// HashAuthorizationCode derives the verification identifier from a presented code.
	// The default is unpadded base64url of its SHA-256 digest.
	HashAuthorizationCode func(context.Context, string) (string, error)
	ScopeLifetimes        map[string]time.Duration
	// ScopeExpiresAt caps a token carrying the scope at that instant. A
	// request for a scope whose instant has passed answers invalid_scope.
	ScopeExpiresAt      map[string]time.Time
	OpaquePrefix        string
	GenerateOpaqueToken func(context.Context) (string, error)
	HashOpaqueToken     func(context.Context, string) (string, error)
	// RateLimit applies to the token endpoint and defaults to 20 per minute.
	// An empty rule uses the host's global limit.
	RateLimit *auth.RateLimitRule
	// IntrospectionRateLimit defaults to 100 per minute. An empty rule
	// selects the host's global rate limit for this endpoint.
	IntrospectionRateLimit *auth.RateLimitRule
	// RevocationRateLimit defaults to 30 per minute. An empty rule uses the host's global limit.
	RevocationRateLimit *auth.RateLimitRule
	RefreshPrefix       string
	// RefreshLifetime defaults to 30 days and is independent of the access token lifetime.
	RefreshLifetime      time.Duration
	GenerateRefreshToken func(context.Context) (string, error)
	// EncodeRefreshToken formats an issued refresh credential for its session.
	// The configured prefix is added after encoding. Supply a corresponding decoder.
	EncodeRefreshToken func(ctx context.Context, raw, sessionID string) (string, error)
	// DecodeRefreshToken unwraps an unprefixed refresh token before lookup.
	// Return ErrInvalidRefreshToken for an unrecognized encoding.
	DecodeRefreshToken func(context.Context, string) (string, error)
	HashRefreshToken   func(context.Context, string) (string, error)
}

func (opts *TokenOptions) defaults() error {
	if opts.IDTokenLifetime == 0 {
		opts.IDTokenLifetime = 10 * time.Hour
	}
	if opts.IDTokenLifetime < time.Second || opts.IDTokenLifetime%time.Second != 0 {
		return errors.New("oauthprovider: ID token lifetime must be a positive whole number of seconds")
	}
	if opts.RefreshLifetime == 0 {
		opts.RefreshLifetime = 30 * 24 * time.Hour
	}
	if opts.RefreshLifetime < time.Second || opts.RefreshLifetime%time.Second != 0 {
		return errors.New("oauthprovider: refresh token lifetime must be a positive whole number of seconds")
	}
	if opts.EncodeRefreshToken != nil && opts.DecodeRefreshToken == nil {
		return errors.New("oauthprovider: a refresh token encoder requires a matching decoder")
	}
	if opts.MachineLifetime == 0 {
		opts.MachineLifetime = time.Hour
	}
	if opts.MachineLifetime < time.Second || opts.MachineLifetime%time.Second != 0 {
		return errors.New("oauthprovider: machine token lifetime must be a positive whole number of seconds")
	}
	if opts.AccessLifetime == 0 {
		opts.AccessLifetime = time.Hour
	}
	if opts.AccessLifetime < time.Second || opts.AccessLifetime%time.Second != 0 {
		return errors.New("oauthprovider: access token lifetime must be a positive whole number of seconds")
	}
	opts.ScopeLifetimes = maps.Clone(opts.ScopeLifetimes)
	opts.ScopeExpiresAt = maps.Clone(opts.ScopeExpiresAt)
	for _, ttl := range opts.ScopeLifetimes {
		if ttl < time.Second || ttl%time.Second != 0 {
			return errors.New("oauthprovider: scope lifetime must be a positive whole number of seconds")
		}
	}
	opts.RateLimit = tokenRouteLimit(opts.RateLimit, 20)
	opts.IntrospectionRateLimit = tokenRouteLimit(opts.IntrospectionRateLimit, 100)
	opts.RevocationRateLimit = tokenRouteLimit(opts.RevocationRateLimit, 30)
	return nil
}

func tokenRouteLimit(rule *auth.RateLimitRule, max int) *auth.RateLimitRule {
	if rule == nil {
		return &auth.RateLimitRule{Window: time.Minute, Max: max}
	}
	if *rule == (auth.RateLimitRule{}) {
		return nil
	}
	copy := *rule
	return &copy
}

// MachineClient contains the server-only registration fields required for authentication.
// RowID identifies a particular registration even if a client ID is later reused.
type MachineClient struct {
	RowID, ClientID, StoredSecret, AuthMethod string
	// JWKS and JWKSURI identify the key material registered for private_key_jwt.
	JWKS, JWKSURI             string
	Metadata                  map[string]json.RawMessage
	GrantTypes, MachineScopes []string
	Disabled, RequireDPoP     bool
}

type MachineTokenRecord struct {
	StoredToken         string
	Scopes              []string
	IssuedAt, ExpiresAt time.Time
}

// MachineTokenStore reads local registrations, then locks and re-reads the current
// registration for issuance. StoreMachineToken calls prepare on that locked row
// and inserts only the returned record in the same transaction. Missing clients
// return ErrClientNotFound. prepare performs no I/O or host callbacks.
type MachineTokenStore interface {
	MachineClientReader
	StoreMachineToken(ctx context.Context, clientID string, prepare func(MachineClient) (MachineTokenRecord, error)) error
}

// DPoPMachineTokenStore persists the verified sender thumbprint in the same
// transaction as the token. Its prepare callback follows MachineTokenStore's
// locked-registration contract. Implementations must retain the binding on
// every subsequent token read.
type DPoPMachineTokenStore interface {
	StoreDPoPMachineToken(ctx context.Context, clientID, thumbprint string, prepare func(MachineClient) (MachineTokenRecord, error)) error
}

// MachineClientReader loads the local client registration for secret verification.
type MachineClientReader interface {
	LookupMachineClient(context.Context, string) (MachineClient, error)
}

// MachineToken is returned to a confidential application after a client credentials exchange.
type MachineToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	ExpiresAt   int64  `json:"expires_at"`
	Scope       string `json:"scope"`
}

func tokenDigest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func invalidClient(description string) error {
	return registrationProblem(400, "invalid_client", description)
}

func (r RegistrationOptions) checkSecret(ctx context.Context, issued, stored string) (bool, error) {
	raw, ok := strings.CutPrefix(issued, r.SecretPrefix)
	if !ok || raw == "" || stored == "" {
		return false, nil
	}
	if r.VerifySecret != nil {
		return r.VerifySecret(ctx, raw, stored)
	}
	var encoded string
	if r.StoreSecret != nil {
		var err error
		encoded, err = r.StoreSecret(ctx, raw)
		if err != nil {
			return false, err
		}
	} else {
		encoded = tokenDigest(raw)
	}
	return subtle.ConstantTimeCompare([]byte(encoded), []byte(stored)) == 1, nil
}

func (in tokenRequest) checkMethod(client MachineClient) error {
	if client.ClientID != in.id {
		return invalidClient("client not found")
	}
	if client.Disabled {
		return invalidClient("client is disabled")
	}
	method := client.AuthMethod
	if method == "" {
		method = "client_secret_basic"
	}
	if method != in.method {
		return invalidClient("client registered for " + method + " cannot use " + in.method)
	}
	return nil
}

func (in tokenRequest) authorizedScopes(client MachineClient) ([]string, error) {
	if !slices.Contains(client.GrantTypes, "client_credentials") {
		return nil, registrationProblem(400, "unauthorized_client", "client is not authorized to use grant type client_credentials")
	}
	if in.method == "none" {
		return nil, registrationProblem(400, "unauthorized_client", "public clients cannot use the client_credentials grant")
	}
	if len(client.MachineScopes) == 0 {
		return nil, registrationProblem(400, "unauthorized_client", "client has no authorized client_credentials scopes")
	}
	scopes := in.scopes
	if scopes == nil {
		scopes = client.MachineScopes
	}
	var invalid []string
	for _, name := range scopes {
		if name == "" || userDelegatedScope(name) || !slices.Contains(client.MachineScopes, name) {
			invalid = append(invalid, name)
		}
	}
	if len(invalid) != 0 {
		return nil, registrationProblem(400, "invalid_scope", "The following scopes are invalid: "+strings.Join(invalid, ", "))
	}
	return scopes, nil
}

func userDelegatedScope(scope string) bool {
	return scope == "openid" || scope == "profile" || scope == "email" || scope == "offline_access"
}

func (opts Options) authenticateClient(c auth.EndpointContext, store MachineClientReader, in tokenRequest, endpoint string) (MachineClient, error) {
	ctx := c.Request.Context()
	first, err := store.LookupMachineClient(ctx, in.id)
	if err != nil {
		return MachineClient{}, err
	}
	if err := in.checkMethod(first); err != nil {
		return MachineClient{}, err
	}
	if in.assertion != nil {
		err := opts.verifyClientAssertion(c, store, in, first, endpoint)
		return first, err
	}
	if in.method != "none" {
		ok, err := opts.Registration.checkSecret(ctx, in.secret, first.StoredSecret)
		if err != nil {
			return MachineClient{}, err
		}
		if !ok {
			return MachineClient{}, invalidClient("invalid client_secret")
		}
	}
	return first, nil
}

func (in tokenRequest) recheckClient(first, current MachineClient) error {
	if err := in.checkMethod(current); err != nil {
		return err
	}
	if first.RowID != current.RowID || subtle.ConstantTimeCompare([]byte(first.StoredSecret), []byte(current.StoredSecret)) != 1 {
		return invalidClient("invalid client_secret")
	}
	if in.assertion != nil && (first.JWKS != current.JWKS || first.JWKSURI != current.JWKSURI) {
		return invalidClient("registered client assertion keys have changed")
	}
	return nil
}

func (opts TokenOptions) storedOpaque(ctx context.Context, raw string) (string, error) {
	if opts.HashOpaqueToken == nil {
		return tokenDigest(raw), nil
	}
	stored, err := opts.HashOpaqueToken(ctx, raw)
	if err == nil && stored == "" {
		return "", errors.New("oauthprovider: empty stored access token")
	}
	return stored, err
}

func (opts Options) machineThumbprint(c auth.EndpointContext, in tokenRequest, required bool) (string, error) {
	if in.proof == "" {
		if required {
			return "", proofError("DPoP proof header is required")
		}
		return "", nil
	}
	verifier := opts.proofsFor(c.Store())
	proof, err := verifier.Verify(c.Request.Context(), in.proof, DPoPProofRequest{Method: c.Request.Method, URL: c.Auth.PublicURL() + "/oauth2/token"})
	if err != nil {
		return "", err
	}
	return proof.Thumbprint, nil
}

func (opts TokenOptions) newOpaqueToken(ctx context.Context) (issued, stored string, err error) {
	var raw string
	if gen := opts.GenerateOpaqueToken; gen != nil {
		raw, err = gen(ctx)
	} else {
		raw, err = randomClientCredential()
	}
	if err != nil {
		return "", "", err
	}
	if raw == "" {
		return "", "", errors.New("oauthprovider: empty generated access token")
	}
	stored, err = opts.storedOpaque(ctx, raw)
	return opts.OpaquePrefix + raw, stored, err
}

func (opts TokenOptions) machineLifetime(scopes []string, now time.Time) (time.Duration, error) {
	return opts.scopeLifetime(opts.MachineLifetime, scopes, now)
}

// scopeLifetime is the shortest of the base lifetime, each scope's relative
// lifetime and the whole seconds left until each scope's instant. A scope
// whose instant has passed refuses issuance, where another runtime mints a
// token that has already expired.
func (opts TokenOptions) scopeLifetime(lifetime time.Duration, scopes []string, now time.Time) (time.Duration, error) {
	for _, scope := range scopes {
		if limit, ok := opts.ScopeLifetimes[scope]; ok && limit < lifetime {
			lifetime = limit
		}
		if at, ok := opts.ScopeExpiresAt[scope]; ok {
			left := time.Duration(at.Unix()-now.Unix()) * time.Second
			if left <= 0 {
				return 0, registrationProblem(400, "invalid_scope", "scope "+scope+" has expired")
			}
			lifetime = min(lifetime, left)
		}
	}
	return lifetime, nil
}

func machineResponse(issued, thumbprint string, scopes []string, now time.Time, lifetime time.Duration) MachineToken {
	tokenType := "Bearer"
	if thumbprint != "" {
		tokenType = "DPoP"
	}
	return MachineToken{AccessToken: issued, TokenType: tokenType, Scope: strings.Join(scopes, " "), ExpiresIn: int64(lifetime / time.Second), ExpiresAt: now.Add(lifetime).Unix()}
}

func (opts Options) issueMachineToken(c auth.EndpointContext, store MachineTokenStore, in tokenRequest, first MachineClient) (MachineToken, error) {
	if _, err := in.authorizedScopes(first); err != nil {
		return MachineToken{}, err
	}
	if len(in.resources) != 0 {
		return opts.issueResourceMachineToken(c, store, in, first)
	}
	boundStore, canBind := store.(DPoPMachineTokenStore)
	if in.proof != "" && !canBind {
		return MachineToken{}, &auth.APIError{Status: 501, Code: "OAUTH_DPOP_STORE_UNAVAILABLE", Message: "The configured store cannot persist sender-bound tokens"}
	}
	thumbprint, err := opts.machineThumbprint(c, in, first.RequireDPoP)
	if err != nil {
		return MachineToken{}, err
	}
	ctx := c.Request.Context()
	issued, stored, err := opts.Tokens.newOpaqueToken(ctx)
	if err != nil {
		return MachineToken{}, err
	}
	var result MachineToken
	prepare := func(current MachineClient) (MachineTokenRecord, error) {
		if err := in.recheckClient(first, current); err != nil {
			return MachineTokenRecord{}, err
		}
		scopes, err := in.authorizedScopes(current)
		if err != nil {
			return MachineTokenRecord{}, err
		}
		if current.RequireDPoP && thumbprint == "" {
			return MachineTokenRecord{}, proofError("DPoP proof header is required")
		}
		now := time.Now().UTC().Truncate(time.Second)
		lifetime, err := opts.Tokens.machineLifetime(scopes, now)
		if err != nil {
			return MachineTokenRecord{}, err
		}
		result = machineResponse(issued, thumbprint, scopes, now, lifetime)
		return MachineTokenRecord{StoredToken: stored, Scopes: scopes, IssuedAt: now, ExpiresAt: now.Add(lifetime)}, nil
	}
	if thumbprint != "" {
		err = boundStore.StoreDPoPMachineToken(ctx, in.id, thumbprint, prepare)
	} else {
		err = store.StoreMachineToken(ctx, in.id, prepare)
	}
	if err != nil {
		return MachineToken{}, err
	}
	return result, nil
}
