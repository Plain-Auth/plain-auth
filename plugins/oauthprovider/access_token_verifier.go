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
	"regexp"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/jsjson"
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
	// It may be empty when Remote is set.
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
	// Remote introspects every token at the issuer after the local check.
	Remote *RemoteVerification
	// Origin is the API's public origin, which Handler joins with each
	// request URI for DPoP proofs. It defaults to the origin of the first
	// HTTP or HTTPS Audience, never the request's Host.
	Origin string
	// MetadataMappings give Handler's challenges a resource_metadata URL
	// for an audience that is not a URL.
	MetadataMappings map[string]string
	// Auth, an auth instance in the same process, supplies defaults: the
	// issuer it signs with, its keys read in process, or its RemoteJWKSURL,
	// and its introspection endpoint for Remote. Audience is never
	// defaulted.
	Auth *auth.Auth
	// DPoP checks the proofs of DPoP-bound tokens at VerifyRequest. Its
	// replay store defaults to memory for this verifier; share a SQL or
	// Redis store across the API's instances.
	DPoP DPoPOptions
}

// AccessTokenVerifier checks access tokens for a resource server, as
// another runtime's verifyBearerToken does. One verifier caches the
// issuer's keys for every route.
type AccessTokenVerifier struct {
	opts   AccessTokenVerifierOptions
	keys   *resourceKeys
	proofs *DPoPVerifier
	http   *http.Client
	now    func() time.Time
}

// NewAccessTokenVerifier checks the options once. Type defaults to at+jwt
// and exp is required, where another runtime checks typ only when given
// and accepts a token without exp, since otherwise a session JWT with the
// same issuer and audience would pass (safety).
func NewAccessTokenVerifier(opts AccessTokenVerifierOptions) (*AccessTokenVerifier, error) {
	if r := opts.Remote; r != nil {
		copied := *r
		opts.Remote = &copied
	}
	// local reads the instance's own keys in process.
	local := opts.Auth != nil && opts.JWKSURL == "" && opts.Auth.LocalJWKS()
	if a := opts.Auth; a != nil {
		if opts.Issuer == "" {
			opts.Issuer = a.OAuthIssuer()
		}
		if opts.JWKSURL == "" && !local && a.JWTSigningAlgorithm() != "" {
			opts.JWKSURL = a.PublicJWKSURL()
		}
		if opts.Remote != nil && opts.Remote.IntrospectionURL == "" {
			opts.Remote.IntrospectionURL = a.PublicURL() + "/oauth2/introspect"
		}
	}
	if opts.Issuer == "" {
		return nil, errors.New("oauthprovider: access token verifier needs an issuer")
	}
	opts.Audience = slices.DeleteFunc(slices.Clone(opts.Audience), func(aud string) bool { return aud == "" })
	if len(opts.Audience) == 0 {
		return nil, errors.New("oauthprovider: access token verifier needs an audience")
	}
	if opts.JWKSURL == "" && !local && opts.Remote == nil {
		return nil, errors.New("oauthprovider: access token verifier needs a JWKS URL, an auth instance with local keys, or remote verification")
	}
	if opts.JWKSURL != "" && !secureURL(opts.JWKSURL) {
		return nil, errors.New("oauthprovider: access token verifier needs an HTTPS JWKS URL, or HTTP on loopback")
	}
	if r := opts.Remote; r != nil && (!secureURL(r.IntrospectionURL) || r.ClientID == "" || r.ClientSecret == "") {
		return nil, errors.New("oauthprovider: remote verification needs an HTTPS introspection URL, or HTTP on loopback, and the API's client credentials")
	}
	if opts.Type == "" {
		opts.Type = "at+jwt"
	}
	if opts.Origin != "" {
		u, err := url.Parse(opts.Origin)
		if err != nil || !secureURL(opts.Origin) || u.Path != "" && u.Path != "/" || u.RawQuery != "" {
			return nil, errors.New("oauthprovider: Origin must be an HTTPS origin, or HTTP on loopback")
		}
	}
	if slices.Contains(opts.RequiredClaims, "") {
		return nil, errors.New("oauthprovider: required claim names must not be empty")
	}
	opts.RequiredClaims = slices.Clone(opts.RequiredClaims)
	proofs, err := NewDPoPVerifier(opts.DPoP)
	if err != nil {
		return nil, err
	}
	v := &AccessTokenVerifier{opts: opts, proofs: proofs, now: time.Now, http: newIntrospectionClient(opts.Transport)}
	switch {
	case local:
		v.keys = newResourceKeys("", opts.Auth.PublicJWKS, nil)
	case opts.JWKSURL != "":
		v.keys = newResourceKeys(opts.JWKSURL, nil, opts.Transport)
	}
	return v, nil
}

// secureURL reports an absolute HTTPS URL, or HTTP on loopback, without
// credentials or a fragment.
func secureURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.IsAbs() && u.User == nil && u.Fragment == "" && u.Host != "" && (u.Scheme == "https" || u.Scheme == "http" && loopback(u.Hostname()))
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

// ResourceRequest is what a resource server reads from a request to check
// its access token.
type ResourceRequest struct {
	Authorization, DPoP, Method string
	// URL is the request's public absolute URL.
	URL string
}

// ResourceRequestFrom reads a request's first Authorization and DPoP
// headers and its method, with origin, the API's public origin, before the
// request URI.
func ResourceRequestFrom(r *http.Request, origin string) ResourceRequest {
	return ResourceRequest{Authorization: r.Header.Get("Authorization"), DPoP: r.Header.Get("DPoP"), Method: r.Method, URL: strings.TrimRight(origin, "/") + r.URL.RequestURI()}
}

// authorizationScheme matches an Authorization header's scheme and value.
var authorizationScheme = regexp.MustCompile("^([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*)\\s+(.+)$")

// parseAuthorization reads a Bearer or DPoP access token, as another
// runtime does; any other scheme is "Unknown" with the whole value.
func parseAuthorization(header string) (scheme, token string) {
	value := jsjson.TrimSpace(header)
	if value == "" {
		return "", ""
	}
	match := authorizationScheme.FindStringSubmatch(value)
	if match == nil {
		return "Unknown", value
	}
	// The value is trimmed and the separator greedy, so the token is too.
	switch strings.ToLower(match[1]) {
	case "bearer":
		return "Bearer", match[2]
	case "dpop":
		return "DPoP", match[2]
	}
	return "Unknown", value
}

// VerifyRequest checks a request's access token as VerifyBearer does,
// scopes included, then its sender binding, as another runtime's
// verifyAccessTokenRequest does: a DPoP-bound token needs the DPoP scheme
// and a proof by its key for this method and URL, which is spent once, and
// a bearer token must not use the DPoP scheme. Failures are 401
// invalid_token or invalid_dpop_proof; a replay store error is a server
// error.
func (v *AccessTokenVerifier) VerifyRequest(ctx context.Context, req ResourceRequest, requiredScopes ...string) (map[string]any, error) {
	if err := checkRequiredScopes(requiredScopes); err != nil {
		return nil, err
	}
	// An empty header is refused by verify as a missing one.
	scheme, token := parseAuthorization(req.Authorization)
	if scheme == "Unknown" {
		return nil, invalidToken("authorization scheme must be Bearer or DPoP")
	}
	claims, err := v.verify(ctx, token, requiredScopes)
	if err != nil {
		return nil, err
	}
	var jkt string
	if cnf, ok := claims["cnf"].(map[string]any); ok {
		jkt, _ = cnf["jkt"].(string)
	}
	err = v.proofs.CheckBinding(ctx, scheme, req.DPoP, DPoPProofRequest{Method: req.Method, URL: req.URL, AccessToken: token, ExpectedThumbprint: jkt})
	var problem *auth.OAuthError
	if errors.As(err, &problem) {
		return nil, &ResourceFailure{Status: 401, Code: problem.Code, Message: problem.Description, Description: problem.Description}
	}
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func checkRequiredScopes(scopes []string) error {
	for _, scope := range scopes {
		if !validScope(scope) {
			return fmt.Errorf("oauthprovider: invalid required scope %q", scope)
		}
	}
	return nil
}

// verify checks the token and its scopes.
func (v *AccessTokenVerifier) verify(ctx context.Context, token string, requiredScopes []string) (map[string]any, error) {
	if err := checkRequiredScopes(requiredScopes); err != nil {
		return nil, err
	}
	if token == "" {
		return nil, &ResourceFailure{Status: 401, Message: "missing authorization header"}
	}
	// The local check runs with a key source unless Remote forces
	// introspection alone; an opaque value goes on to introspection.
	var claims map[string]any
	remote := v.opts.Remote
	if v.keys != nil && (remote == nil || !remote.Force) {
		var err error
		claims, err = v.verifyLocal(ctx, token)
		if err != nil && !errors.Is(err, errOpaqueToken) {
			return nil, err
		}
	}
	if remote != nil {
		var err error
		if claims, err = v.introspect(ctx, token); err != nil {
			return nil, err
		}
	}
	if claims == nil {
		return nil, invalidToken("no token payload")
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

// errOpaqueToken marks a value that is not a compact JWS.
var errOpaqueToken = errors.New("oauthprovider: not a JWS access token")

// verifyLocal checks a JWS access token against the issuer's keys, as
// another runtime's jwtVerify does, in its order. A value that is not a
// compact JWS is an opaque token, which this verifier cannot read.
func (v *AccessTokenVerifier) verifyLocal(ctx context.Context, token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	var header map[string]any
	if len(parts) != 3 || !decodeSegment(parts[0], &header) || !decodeSegment(parts[1], new(any)) {
		return nil, errOpaqueToken
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
	if err := v.checkClaims(claims, true, true); err != nil {
		return nil, err
	}
	if azp, ok := claims["azp"].(string); ok && azp != "" {
		claims["client_id"] = azp
	}
	return claims, nil
}

// checkClaims applies the claim rules another runtime's jose checks, in
// its order: required claims present, iss, aud when checked, then iat,
// nbf and exp as numbers, exp required when asked.
func (v *AccessTokenVerifier) checkClaims(claims map[string]any, audience, requireExp bool) error {
	invalid := invalidToken("invalid access token")
	required := append([]string{"iss"}, v.opts.RequiredClaims...)
	if audience {
		required = append(required, "aud")
	}
	for _, name := range required {
		if _, ok := claims[name]; !ok {
			return invalid
		}
	}
	if claims["iss"] != v.opts.Issuer || audience && !audienceMatches(claims["aud"], v.opts.Audience) {
		return invalid
	}
	now := float64(v.now().Unix())
	if _, ok := claims["iat"]; ok && !isNumber(claims["iat"]) {
		return invalid
	}
	if nbf, ok := claims["nbf"]; ok && (!isNumber(nbf) || nbf.(float64) > now) {
		return invalid
	}
	raw, present := claims["exp"]
	if !present && !requireExp {
		return nil
	}
	exp, ok := raw.(float64)
	if !ok {
		return invalid
	}
	if exp <= now {
		return invalidToken("token expired")
	}
	return nil
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
