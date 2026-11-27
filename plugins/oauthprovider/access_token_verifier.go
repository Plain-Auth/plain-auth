package oauthprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// AccessTokenVerifierOptions configures a resource server's check of the
// access tokens an issuer signs.
type AccessTokenVerifierOptions struct {
	// Issuer is the iss the tokens carry.
	Issuer string
	// Audience lists the aud values accepted; a token must name one.
	Audience []string
	// JWKSURL serves the issuer's signing keys, over HTTPS or on loopback.
	JWKSURL string
	// Type is the typ header tokens must carry, at+jwt by default.
	Type string
	// RequiredClaims must be present in every token.
	RequiredClaims []string
	// ScopeSatisfied reports whether the granted scopes satisfy one
	// required scope. It defaults to exact membership.
	ScopeSatisfied func(required string, granted map[string]bool) bool
	// Transport fetches the keys; http.DefaultTransport by default.
	Transport http.RoundTripper
}

// AccessTokenVerifier checks access tokens for a resource server, as
// another runtime's verifyBearerToken does. One verifier caches the
// issuer's keys for every route.
type AccessTokenVerifier struct {
	opts AccessTokenVerifierOptions
	keys *resourceKeys
	now  func() time.Time
}

// NewAccessTokenVerifier checks the options once. Type defaults to at+jwt
// and exp is required, where another runtime checks typ only when given
// and accepts a token without exp, since otherwise a session JWT with the
// same issuer and audience would pass (safety).
func NewAccessTokenVerifier(opts AccessTokenVerifierOptions) (*AccessTokenVerifier, error) {
	if opts.Issuer == "" {
		return nil, errors.New("oauthprovider: access token verifier needs an issuer")
	}
	opts.Audience = slices.DeleteFunc(slices.Clone(opts.Audience), func(aud string) bool { return aud == "" })
	if len(opts.Audience) == 0 {
		return nil, errors.New("oauthprovider: access token verifier needs an audience")
	}
	u, err := url.Parse(opts.JWKSURL)
	if err != nil || !u.IsAbs() || u.User != nil || u.Fragment != "" || u.Host == "" || !(u.Scheme == "https" || u.Scheme == "http" && loopback(u.Hostname())) {
		return nil, errors.New("oauthprovider: access token verifier needs an HTTPS JWKS URL, or HTTP on loopback")
	}
	if opts.Type == "" {
		opts.Type = "at+jwt"
	}
	if slices.Contains(opts.RequiredClaims, "") {
		return nil, errors.New("oauthprovider: required claim names must not be empty")
	}
	opts.RequiredClaims = slices.Clone(opts.RequiredClaims)
	return &AccessTokenVerifier{opts: opts, keys: newResourceKeys(opts.JWKSURL, nil, opts.Transport), now: time.Now}, nil
}

// Error returns the failure's description, or else its message.
func (f *ResourceFailure) Error() string {
	if f.Description != "" {
		return f.Description
	}
	return f.Message
}

// invalidToken is a presented token that failed validation.
func invalidToken(message string) *ResourceFailure {
	return &ResourceFailure{Status: 401, Code: "invalid_token", Message: message, Description: message}
}

// VerifyBearer checks a bearer access token and returns its claims, with
// azp copied to client_id. A token that fails is a *ResourceFailure: 401
// invalid_token, or 403 insufficient_scope naming every missing scope. A
// DPoP-bound token is refused, since only a request can prove its key. Any
// other error, such as unreadable keys, is a server error.
func (v *AccessTokenVerifier) VerifyBearer(ctx context.Context, token string, requiredScopes ...string) (map[string]any, error) {
	claims, err := v.verify(ctx, token, requiredScopes)
	if err != nil {
		return nil, err
	}
	if cnf, ok := claims["cnf"].(map[string]any); ok {
		if jkt, _ := cnf["jkt"].(string); jkt != "" {
			return nil, invalidToken("DPoP-bound access token requires request verification")
		}
	}
	return claims, nil
}

// verify checks the token and its scopes.
func (v *AccessTokenVerifier) verify(ctx context.Context, token string, requiredScopes []string) (map[string]any, error) {
	for _, scope := range requiredScopes {
		if !validScope(scope) {
			return nil, fmt.Errorf("oauthprovider: invalid required scope %q", scope)
		}
	}
	if token == "" {
		return nil, &ResourceFailure{Status: 401, Message: "missing authorization header"}
	}
	claims, err := v.verifyLocal(ctx, token)
	if err != nil {
		return nil, err
	}
	granted, err := grantedScopes(claims["scope"])
	if err != nil {
		return nil, err
	}
	satisfied := v.opts.ScopeSatisfied
	if satisfied == nil {
		satisfied = func(required string, granted map[string]bool) bool { return granted[required] }
	}
	var missing []string
	for _, scope := range requiredScopes {
		if !satisfied(scope, granted) {
			missing = append(missing, scope)
		}
	}
	if len(missing) > 0 {
		description := "access token is missing required scope: " + strings.Join(missing, " ")
		return nil, &ResourceFailure{Status: 403, Code: "insufficient_scope", Message: description, Description: description, MissingScopes: distinct(missing)}
	}
	return claims, nil
}

// grantedScopes reads a scope claim: absent is none, and anything but
// space-separated scope tokens is invalid.
func grantedScopes(claim any) (map[string]bool, error) {
	granted := map[string]bool{}
	if claim == nil {
		return granted, nil
	}
	scope, ok := claim.(string)
	if !ok {
		return nil, invalidToken("access token scope claim is invalid")
	}
	// An empty claim splits into one empty token, which is invalid.
	for _, token := range strings.Split(scope, " ") {
		if !validScope(token) {
			return nil, invalidToken("access token scope claim is invalid")
		}
		granted[token] = true
	}
	return granted, nil
}

// verifyLocal checks a JWS access token against the issuer's keys, as
// another runtime's jwtVerify does, in its order. A value that is not a
// compact JWS is an opaque token, which this verifier cannot read.
func (v *AccessTokenVerifier) verifyLocal(ctx context.Context, token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	var header map[string]any
	if len(parts) != 3 || !decodeSegment(parts[0], &header) || !decodeSegment(parts[1], new(any)) {
		return nil, invalidToken("no token payload")
	}
	invalid := invalidToken("invalid access token")
	signed, err := jose.ParseSigned(token, assertionAlgorithms)
	if err != nil {
		return nil, invalid
	}
	payload, err := v.keys.verify(ctx, signed)
	if errors.Is(err, errInvalidKey) {
		return nil, invalid
	}
	if err != nil {
		return nil, fmt.Errorf("oauthprovider: verify access token: %w", err)
	}
	if typ, _ := header["typ"].(string); normalizeType(typ) != normalizeType(v.opts.Type) {
		return nil, invalid
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil || claims == nil {
		return nil, invalid
	}
	for _, name := range append([]string{"iss", "aud"}, v.opts.RequiredClaims...) {
		if _, ok := claims[name]; !ok {
			return nil, invalid
		}
	}
	if claims["iss"] != v.opts.Issuer || !audienceMatches(claims["aud"], v.opts.Audience) {
		return nil, invalid
	}
	now := float64(v.now().Unix())
	if _, ok := claims["iat"]; ok && !isNumber(claims["iat"]) {
		return nil, invalid
	}
	if nbf, ok := claims["nbf"]; ok && (!isNumber(nbf) || nbf.(float64) > now) {
		return nil, invalid
	}
	// exp is required and numeric.
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, invalid
	}
	if exp <= now {
		return nil, invalidToken("token expired")
	}
	if azp, ok := claims["azp"].(string); ok && azp != "" {
		claims["client_id"] = azp
	}
	return claims, nil
}

func isNumber(v any) bool {
	_, ok := v.(float64)
	return ok
}

// decodeSegment reads a base64url JSON segment into v.
func decodeSegment(segment string, v any) bool {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	return err == nil && json.NewDecoder(bytes.NewReader(raw)).Decode(v) == nil
}

// normalizeType compares typ values as media types: lowercase, with
// application/ added when no subtype separator is present.
func normalizeType(typ string) string {
	typ = strings.ToLower(typ)
	if typ != "" && !strings.Contains(typ, "/") {
		typ = "application/" + typ
	}
	return typ
}

// audienceMatches reports whether aud, a string or array of strings,
// names an accepted audience.
func audienceMatches(aud any, accepted []string) bool {
	switch v := aud.(type) {
	case string:
		return slices.Contains(accepted, v)
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && slices.Contains(accepted, s) {
				return true
			}
		}
	}
	return false
}
