package plainauth

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"reflect"
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

// JWTSigningRequest is what JWTOptions.Sign receives for each token.
type JWTSigningRequest struct {
	// Claims is the complete claim set; the server has set sub, iss, aud,
	// iat and exp, and nbf when requested.
	Claims map[string]any
	// Type and ContentType are the typ and cty header values the caller
	// requires, such as at+jwt for OAuth access tokens; merge them into the
	// signed header.
	Type, ContentType string
	// Algorithm and KeyID are the algorithm or key the caller pinned, such
	// as an OAuth resource's key; both are empty for ordinary tokens, which
	// use JWTOptions.Algorithm.
	Algorithm, KeyID string
}

// signWithCallback hands a token to JWTOptions.Sign and checks the result. A
// result must be a compact JWS with the requested algorithm, key and media
// types and exactly the claims it was given, so a misconfigured signer
// fails here rather than at a resource server; another runtime returns
// whatever the signer produces.
func (a *Auth) signWithCallback(ctx context.Context, claims map[string]any, settings JWTSignOptions) (string, error) {
	opts := a.serviceJWT
	token, err := opts.Sign(ctx, JWTSigningRequest{Claims: claims, Type: settings.Type, ContentType: settings.ContentType, Algorithm: settings.Algorithm, KeyID: settings.KeyID})
	if err != nil {
		return "", err
	}
	invalid := errors.New("jwt: custom signer returned an invalid token")
	jws, err := jose.ParseSignedCompact(token, opts.verificationAlgorithms())
	if err != nil || len(jws.Signatures) != 1 {
		return "", invalid
	}
	header := jws.Signatures[0].Protected
	want := settings.Algorithm
	if want == "" && settings.KeyID == "" {
		want = opts.Algorithm
	}
	if want != "" && header.Algorithm != want || settings.KeyID != "" && header.KeyID != settings.KeyID ||
		settings.Type != "" && header.ExtraHeaders[jose.HeaderType] != settings.Type ||
		settings.ContentType != "" && header.ExtraHeaders[jose.HeaderContentType] != settings.ContentType {
		return "", invalid
	}
	var got, sent map[string]any
	body, err := json.Marshal(claims)
	if err != nil || json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &got) != nil || json.Unmarshal(body, &sent) != nil || !reflect.DeepEqual(got, sent) {
		return "", invalid
	}
	return token, nil
}

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
	if opts.Sign != nil {
		return a.signWithCallback(ctx, claims, settings)
	}
	var row StoredJWTKey
	var err error
	if settings.KeyID != "" {
		lookup, ok := a.jwtKeys().(JWTKeyLookup)
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
	now := a.now().UTC()
	var claims jwt.Claims
	var payload map[string]any
	if err := a.readSignedJWT(ctx, token, now, true, &claims, &payload); err != nil {
		return nil, err
	}
	if claims.Subject == "" || claims.Expiry == nil || !now.Before(claims.Expiry.Time()) {
		return nil, ErrInvalidJWT
	}
	settings = a.jwtExpectations(settings)
	expected := jwt.Expected{Issuer: settings.Issuer, AnyAudience: jwt.Audience{settings.Audience}, Subject: settings.Subject, Time: now}
	if err := claims.ValidateWithLeeway(expected, 0); err != nil {
		return nil, ErrInvalidJWT
	}
	return payload, nil
}

func (a *Auth) readSignedJWT(ctx context.Context, token string, now time.Time, requireKeyID bool, claims ...any) error {
	opts := a.serviceJWT
	if opts == nil {
		return &APIError{404, "NOT_FOUND", "JWT plugin is not enabled"}
	}
	signed, err := jwt.ParseSigned(token, opts.verificationAlgorithms())
	if err != nil || len(signed.Headers) != 1 || requireKeyID && signed.Headers[0].KeyID == "" {
		return ErrInvalidJWT
	}
	key, err := a.jwtVerificationKey(ctx, now, signed.Headers[0])
	if err != nil {
		return err
	}
	if err := signed.Claims(key, claims...); err != nil {
		return ErrInvalidJWT
	}
	return nil
}

func (opts *JWTOptions) verificationAlgorithms() []jose.SignatureAlgorithm {
	algorithms := []jose.SignatureAlgorithm{jose.SignatureAlgorithm(opts.Algorithm)}
	for _, alg := range opts.AdditionalAlgorithms {
		algorithms = append(algorithms, jose.SignatureAlgorithm(alg))
	}
	return algorithms
}

func (a *Auth) jwtVerificationKey(ctx context.Context, now time.Time, header jose.Header) (any, error) {
	rows, err := a.jwtKeys().PublicJWTKeys(ctx, now.Add(-*a.serviceJWT.GracePeriod))
	if err != nil {
		return nil, err
	}
	if header.KeyID == "" {
		// An OAuth JWS can omit kid. JOSE may choose a verification key
		// only when the header unambiguously identifies one local key.
		for _, row := range rows {
			if row.Algorithm == header.Algorithm {
				if header.KeyID != "" {
					return nil, errors.New("jwt: multiple verification keys match the token algorithm")
				}
				header.KeyID = row.ID
			}
		}
	}
	for _, row := range rows {
		if row.ID != header.KeyID || row.Algorithm != header.Algorithm {
			continue
		}
		var key jose.JSONWebKey
		if err := key.UnmarshalJSON([]byte(row.PublicKey)); err != nil || !key.Valid() || !key.IsPublic() {
			return nil, errors.New("jwt: invalid stored public key")
		}
		return key.Key, nil
	}
	return nil, ErrInvalidJWT
}

// CheckOAuthJWTRevocation recognizes self-contained tokens during revocation.
// A recognized inactive token needs no further action. A live access token
// returns unsupported_token_type. Unknown signatures and issuers fall through
// to stored-token lookup. This check never authorizes access to a resource.
func (c EndpointContext) CheckOAuthJWTRevocation(token string, resourceKnown func(context.Context, string) (bool, error)) (bool, error) {
	a, ctx := c.Auth, c.Request.Context()
	if a.serviceJWT == nil {
		return false, nil
	}
	now := a.now().UTC()
	var claims struct {
		jwt.Claims
		Client string `json:"azp"`
	}
	if err := a.readSignedJWT(ctx, token, now, false, &claims); err != nil {
		if errors.Is(err, ErrInvalidJWT) {
			return false, nil
		}
		return false, err
	}
	if claims.Expiry != nil && !now.Before(claims.Expiry.Time()) {
		return true, nil
	}
	if claims.Issuer != a.OAuthIssuer() || claims.NotBefore != nil && now.Before(claims.NotBefore.Time()) {
		return false, nil
	}
	if claims.Client == "" || len(claims.Audience) > 64 {
		return true, nil
	}
	seen := map[string]bool{a.PublicURL() + "/oauth2/userinfo": true}
	for _, audience := range claims.Audience {
		if seen[audience] {
			continue
		}
		if resourceKnown == nil {
			return true, errors.New("jwt: OAuth resource lookup unavailable")
		}
		known, err := resourceKnown(ctx, audience)
		if err != nil || !known {
			return true, err
		}
		seen[audience] = true
	}
	return true, &OAuthError{Status: 400, Code: "unsupported_token_type", Description: "JWT access tokens are self-contained and cannot be revoked server-side"}
}
