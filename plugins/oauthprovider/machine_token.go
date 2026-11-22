package oauthprovider

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

// TokenOptions controls opaque access token issuance. Lifetimes use whole seconds.
type TokenOptions struct {
	MachineLifetime     time.Duration
	ScopeLifetimes      map[string]time.Duration
	OpaquePrefix        string
	GenerateOpaqueToken func(context.Context) (string, error)
	HashOpaqueToken     func(context.Context, string) (string, error)
	RateLimit           *auth.RateLimitRule
	// IntrospectionRateLimit defaults to 100 per minute. An empty rule
	// selects the host's global rate limit for this endpoint.
	IntrospectionRateLimit *auth.RateLimitRule
	// RevocationRateLimit defaults to 30 per minute. An empty rule uses the host's global limit.
	RevocationRateLimit *auth.RateLimitRule
	RefreshPrefix       string
	// DecodeRefreshToken unwraps an unprefixed refresh token before lookup.
	// Return ErrInvalidRefreshToken for an unrecognized encoding.
	DecodeRefreshToken func(context.Context, string) (string, error)
	HashRefreshToken   func(context.Context, string) (string, error)
}

func (opts *TokenOptions) defaults() error {
	if opts.MachineLifetime == 0 {
		opts.MachineLifetime = time.Hour
	}
	if opts.MachineLifetime < time.Second || opts.MachineLifetime%time.Second != 0 {
		return errors.New("oauthprovider: machine token lifetime must be a positive whole number of seconds")
	}
	opts.ScopeLifetimes = maps.Clone(opts.ScopeLifetimes)
	for _, ttl := range opts.ScopeLifetimes {
		if ttl < time.Second || ttl%time.Second != 0 {
			return errors.New("oauthprovider: scope lifetime must be a positive whole number of seconds")
		}
	}
	rule := auth.RateLimitRule{Window: time.Minute, Max: 20}
	if opts.RateLimit != nil {
		rule = *opts.RateLimit
	}
	opts.RateLimit = &rule
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
	GrantTypes, MachineScopes                 []string
	Disabled, RequireDPoP                     bool
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
	if len(in.resources) != 0 {
		return nil, registrationProblem(400, "invalid_target", "requested resource is not available for token issuance")
	}
	if client.RequireDPoP || in.dpop {
		msg := "DPoP proof header is required"
		if in.dpop {
			msg = "DPoP proof could not be verified"
		}
		return nil, registrationProblem(400, "invalid_dpop_proof", msg)
	}
	return scopes, nil
}

func userDelegatedScope(scope string) bool {
	return scope == "openid" || scope == "profile" || scope == "email" || scope == "offline_access"
}

func (r RegistrationOptions) authenticateClient(ctx context.Context, store MachineClientReader, in tokenRequest) (MachineClient, error) {
	first, err := store.LookupMachineClient(ctx, in.id)
	if err != nil {
		return MachineClient{}, err
	}
	if err := in.checkMethod(first); err != nil {
		return MachineClient{}, err
	}
	if in.method != "none" {
		ok, err := r.checkSecret(ctx, in.secret, first.StoredSecret)
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

func (opts Options) issueMachineToken(ctx context.Context, store MachineTokenStore, in tokenRequest) (MachineToken, error) {
	first, err := opts.Registration.authenticateClient(ctx, store, in)
	if err != nil {
		return MachineToken{}, err
	}
	if _, err := in.authorizedScopes(first); err != nil {
		return MachineToken{}, err
	}
	var raw string
	if gen := opts.Tokens.GenerateOpaqueToken; gen != nil {
		raw, err = gen(ctx)
	} else {
		raw, err = randomClientCredential()
	}
	if err != nil {
		return MachineToken{}, err
	}
	if raw == "" {
		return MachineToken{}, errors.New("oauthprovider: empty generated access token")
	}
	stored, err := opts.Tokens.storedOpaque(ctx, raw)
	if err != nil {
		return MachineToken{}, err
	}
	var result MachineToken
	err = store.StoreMachineToken(ctx, in.id, func(current MachineClient) (MachineTokenRecord, error) {
		if err := in.recheckClient(first, current); err != nil {
			return MachineTokenRecord{}, err
		}
		scopes, err := in.authorizedScopes(current)
		if err != nil {
			return MachineTokenRecord{}, err
		}
		lifetime := opts.Tokens.MachineLifetime
		for _, scope := range scopes {
			if limit, ok := opts.Tokens.ScopeLifetimes[scope]; ok && limit < lifetime {
				lifetime = limit
			}
		}
		now := time.Now().UTC().Truncate(time.Second)
		expires := now.Add(lifetime)
		result = MachineToken{AccessToken: opts.Tokens.OpaquePrefix + raw, TokenType: "Bearer", Scope: strings.Join(scopes, " "), ExpiresIn: int64(lifetime / time.Second), ExpiresAt: expires.Unix()}
		return MachineTokenRecord{StoredToken: stored, Scopes: scopes, IssuedAt: now, ExpiresAt: expires}, nil
	})
	if err != nil {
		return MachineToken{}, err
	}
	return result, nil
}
