package frostauth

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// JWTSignOptions applies to a single trusted server-side issuance. Reserved claims
// come from the typed fields. Algorithm and KeyID may select a provisioned key.
type JWTSignOptions struct {
	Claims                         map[string]any
	Algorithm, KeyID               string
	Type, ContentType              string
	Issuer                         string
	Audience                       []string
	IssuedAt, ExpiresAt, NotBefore time.Time
}

// JWTVerifyOptions allows a service to require its own issuer, audience and subject.
type JWTVerifyOptions struct {
	Issuer, Audience, Subject string
}

var ErrInvalidJWT = errors.New("jwt: invalid service token")

type JWTKeyLookup interface {
	JWTKeyByID(context.Context, string) (StoredJWTKey, error)
}

func (a *Auth) jwtExpectations(settings JWTVerifyOptions) JWTVerifyOptions {
	if settings.Issuer == "" {
		settings.Issuer = a.serviceJWT.Issuer
		if settings.Issuer == "" {
			settings.Issuer = a.opts.BaseURL
		}
	}
	if settings.Audience == "" {
		settings.Audience = a.serviceJWT.Audience
		if settings.Audience == "" {
			settings.Audience = a.opts.BaseURL
		}
	}
	return settings
}

func (o *JWTOptions) enablesAlgorithm(alg string) bool {
	return alg == o.Algorithm || slices.Contains(o.AdditionalAlgorithms, alg)
}

// SignJWT signs an assertion for a server-chosen subject. Only trusted host
// code should decide who can obtain an assertion and which claims to include.
func (a *Auth) SignJWT(ctx context.Context, subject string, settings JWTSignOptions) (string, error) {
	opts := a.serviceJWT
	if opts == nil {
		return "", &APIError{404, "NOT_FOUND", "JWT plugin is not enabled"}
	}
	if subject == "" {
		return "", errors.New("jwt: subject is required")
	}
	if settings.Algorithm != "" && !opts.enablesAlgorithm(settings.Algorithm) {
		return "", errors.New("jwt: algorithm is not configured")
	}
	now := a.now().UTC()
	iat := settings.IssuedAt
	if iat.IsZero() {
		iat = now
	}
	exp := settings.ExpiresAt
	if exp.IsZero() {
		exp = iat.Add(opts.Expiration)
	}
	if !exp.After(iat) || (!settings.NotBefore.IsZero() && !exp.After(settings.NotBefore)) {
		return "", errors.New("jwt: expiration must follow issuance and activation")
	}
	claims := maps.Clone(settings.Claims)
	if claims == nil {
		claims = make(map[string]any)
	}
	defaults := a.jwtExpectations(JWTVerifyOptions{Issuer: settings.Issuer})
	claims["sub"], claims["iss"], claims["aud"] = subject, defaults.Issuer, defaults.Audience
	if len(settings.Audience) == 1 {
		claims["aud"] = settings.Audience[0]
	} else if len(settings.Audience) > 1 {
		claims["aud"] = settings.Audience
	}
	claims["iat"], claims["exp"] = iat.Unix(), exp.Unix()
	delete(claims, "nbf")
	if !settings.NotBefore.IsZero() {
		claims["nbf"] = settings.NotBefore.Unix()
	}
	var row StoredJWTKey
	var err error
	if settings.KeyID != "" {
		lookup, ok := a.opts.Store.(JWTKeyLookup)
		if !ok {
			return "", errors.New("jwt: store does not support signing by key ID")
		}
		row, err = lookup.JWTKeyByID(ctx, settings.KeyID)
		if err == nil && (row.ID != settings.KeyID || !opts.enablesAlgorithm(row.Algorithm) ||
			(settings.Algorithm != "" && row.Algorithm != settings.Algorithm) ||
			(row.ExpiresAt != nil && !now.Before(*row.ExpiresAt))) {
			return "", errors.New("jwt: requested key is ineligible for signing")
		}
	} else {
		alg := settings.Algorithm
		if alg == "" {
			alg = opts.Algorithm
		}
		row, err = a.activeSigningKey(ctx, now.Truncate(time.Millisecond), alg)
	}
	if err != nil {
		return "", err
	}
	return a.signStoredJWTKey(row, claims, settings)
}

// VerifyJWT verifies a compact assertion using the configured algorithms and
// published keys. The caller receives claims only after signature, identity,
// audience, expiry and activation checks have succeeded.
func (a *Auth) VerifyJWT(ctx context.Context, token string, settings JWTVerifyOptions) (map[string]any, error) {
	opts := a.serviceJWT
	if opts == nil {
		return nil, &APIError{404, "NOT_FOUND", "JWT plugin is not enabled"}
	}
	algorithms := []jose.SignatureAlgorithm{jose.SignatureAlgorithm(opts.Algorithm)}
	for _, alg := range opts.AdditionalAlgorithms {
		algorithms = append(algorithms, jose.SignatureAlgorithm(alg))
	}
	signed, err := jwt.ParseSigned(token, algorithms)
	if err != nil || len(signed.Headers) != 1 || signed.Headers[0].KeyID == "" {
		return nil, ErrInvalidJWT
	}
	now := a.now().UTC()
	rows, err := a.opts.Store.(JWTStore).PublicJWTKeys(ctx, now.Add(-*opts.GracePeriod))
	if err != nil {
		return nil, err
	}
	header := signed.Headers[0]
	settings = a.jwtExpectations(settings)
	for _, row := range rows {
		if row.ID != header.KeyID || row.Algorithm != header.Algorithm {
			continue
		}
		var key jose.JSONWebKey
		if err := key.UnmarshalJSON([]byte(row.PublicKey)); err != nil || !key.Valid() || !key.IsPublic() {
			return nil, errors.New("jwt: invalid stored public key")
		}
		var claims jwt.Claims
		var payload map[string]any
		if err := signed.Claims(key.Key, &claims, &payload); err != nil || claims.Subject == "" || claims.Expiry == nil || !now.Before(claims.Expiry.Time()) {
			return nil, ErrInvalidJWT
		}
		expected := jwt.Expected{Issuer: settings.Issuer, AnyAudience: jwt.Audience{settings.Audience}, Subject: settings.Subject, Time: now}
		if err := claims.ValidateWithLeeway(expected, 0); err != nil {
			return nil, ErrInvalidJWT
		}
		return payload, nil
	}
	return nil, ErrInvalidJWT
}
