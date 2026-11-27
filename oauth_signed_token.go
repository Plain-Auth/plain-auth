package plainauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	jose "github.com/go-jose/go-jose/v4"
)

// OAuthJWTPayload checks a compact token against this server's configured signing
// keys, OAuth issuer and time claims. A recognized token with nil claims is
// inactive. An unrecognized value can still identify a stored opaque token.
// Callers must check the authorized party, audiences and session before using
// any claims to authorize a request.
func (c EndpointContext) OAuthJWTPayload(token string) (claims map[string]any, recognized bool, err error) {
	a := c.Auth
	if a.serviceJWT == nil {
		return nil, false, nil
	}
	signed, unencoded, err := parseOAuthJWS(token, a.serviceJWT.verificationAlgorithms())
	if err != nil {
		return nil, false, nil
	}
	now := a.now()
	key, err := a.jwtVerificationKey(c.Request.Context(), now, signed.Signatures[0].Header)
	if errors.Is(err, ErrInvalidJWT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	payload, err := signed.Verify(key)
	if err != nil {
		return nil, false, nil
	}
	if unencoded || !utf8.Valid(payload) || !json.Valid(payload) {
		return nil, true, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&claims); err != nil || claims == nil {
		return nil, true, nil
	}
	issuer, _ := claims["iss"].(string)
	if !a.oauthIssuerAccepted(issuer) {
		return nil, false, nil
	}
	for _, name := range []string{"iat", "nbf", "exp"} {
		v, ok := claims[name]
		if !ok {
			continue
		}
		numeric, ok := v.(json.Number)
		if !ok {
			return nil, false, nil
		}
		value, err := numeric.Float64()
		if err != nil {
			return nil, false, nil
		}
		if name == "nbf" && value > float64(now.Unix()) {
			return nil, false, nil
		}
		if name == "exp" && value <= float64(now.Unix()) {
			return nil, true, nil
		}
	}
	return claims, true, nil
}

// OAuthIDTokenHint verifies an ID token this server signed for its OAuth
// issuer and returns its claims without checking exp or nbf, because
// RP-Initiated Logout accepts an expired ID token as a hint. Any other token
// returns nil claims, including one typed as an access or logout token,
// which another runtime would accept; an error reports a key store failure.
func (c EndpointContext) OAuthIDTokenHint(token string) (map[string]any, error) {
	a := c.Auth
	if a.serviceJWT == nil {
		return nil, nil
	}
	signed, unencoded, err := parseOAuthJWS(token, a.serviceJWT.verificationAlgorithms())
	if err != nil || unencoded {
		return nil, nil
	}
	header := signed.Signatures[0].Header
	if typ, _ := header.ExtraHeaders[jose.HeaderType].(string); typedNonIDToken(typ) {
		return nil, nil
	}
	key, err := a.jwtVerificationKey(c.Request.Context(), a.now(), header)
	if errors.Is(err, ErrInvalidJWT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	payload, err := signed.Verify(key)
	if err != nil || !utf8.Valid(payload) {
		return nil, nil
	}
	var claims map[string]any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if decoder.Decode(&claims) != nil || claims == nil {
		return nil, nil
	}
	if issuer, _ := claims["iss"].(string); !a.oauthIssuerAccepted(issuer) {
		return nil, nil
	}
	return claims, nil
}

// typedNonIDToken reports a JWS type that marks an access or logout token,
// so neither can stand in for an ID token.
func typedNonIDToken(typ string) bool {
	switch strings.TrimPrefix(strings.ToLower(typ), "application/") {
	case "at+jwt", "logout+jwt":
		return true
	}
	return false
}

func parseOAuthJWS(token string, algorithms []jose.SignatureAlgorithm) (*jose.JSONWebSignature, bool, error) {
	signed, err := jose.ParseSignedCompact(token, algorithms)
	if err == nil && signed.Signatures[0].Header.ExtraHeaders["b64"] != false {
		return signed, false, nil
	}
	// RFC 7797 permits raw JWS payloads, but JWT does not. Verify the
	// signature over the original bytes before treating one as an inactive JWT.
	header, rest, ok := strings.Cut(token, ".")
	body, sig, last := strings.Cut(rest, ".")
	if !ok || !last || strings.Contains(sig, ".") {
		return nil, false, ErrInvalidJWT
	}
	raw, err := jose.ParseDetached(header+".."+sig, []byte(body), algorithms)
	if err != nil || raw.Signatures[0].Header.ExtraHeaders["b64"] != false {
		return nil, false, ErrInvalidJWT
	}
	crit, _ := raw.Signatures[0].Header.ExtraHeaders["crit"].([]any)
	for _, name := range crit {
		if name == "b64" {
			return raw, true, nil
		}
	}
	return nil, false, ErrInvalidJWT
}
