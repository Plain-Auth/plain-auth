package oauthprovider

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// VerifyBearer accepts an at+jwt signed by the issuer's ES256 or RS256 keys
// for an accepted audience, and refuses a wrong typ, issuer or audience, a
// missing required claim or exp, an expired or not yet valid token, a
// symmetric or unsigned token, an opaque value, a malformed scope claim, a
// DPoP-bound token, and missing scopes, all of them together.
func TestAccessTokenVerifier(t *testing.T) {
	ctx := t.Context()
	issuer := newIssuerKeys(t)
	ec := issuer.publish("ec")["ec"]
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer.mu.Lock()
	issuer.keys = append(issuer.keys, jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "rsa", Algorithm: "RS256", Use: "sig"})
	issuer.mu.Unlock()
	const iss = "https://issuer.example.test/api/auth"
	v, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: iss, Audience: []string{"https://api.example.test"}, JWKSURL: issuer.server.URL,
		RequiredClaims: []string{"azp"}, Transport: issuer.server.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	base := func(overrides map[string]any) map[string]any {
		claims := map[string]any{"iss": iss, "aud": "https://api.example.test", "sub": "user", "azp": "app", "exp": now + 60, "iat": now, "scope": "read write"}
		for k, value := range overrides {
			if value == nil {
				delete(claims, k)
			} else {
				claims[k] = value
			}
		}
		return claims
	}
	sign := func(claims map[string]any, typ string, alg jose.SignatureAlgorithm, key any, kid string) string {
		t.Helper()
		options := new(jose.SignerOptions).WithHeader("kid", kid)
		if typ != "" {
			options = options.WithType(jose.ContentType(typ))
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, options)
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(claims)
		object, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		compact, err := object.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	token := func(overrides map[string]any) string { return sign(base(overrides), "at+jwt", jose.ES256, ec, "ec") }
	failure := func(err error) *ResourceFailure {
		t.Helper()
		var f *ResourceFailure
		if !errors.As(err, &f) {
			t.Fatalf("wanted a resource failure, got %v", err)
		}
		return f
	}
	refused := func(err error, status int, code, description string) {
		t.Helper()
		f := failure(err)
		if f.Status != status || f.Code != code || f.Description != description {
			t.Fatalf("wanted %d %s %q, got %+v", status, code, description, f)
		}
	}
	// Valid tokens.
	for name, value := range map[string]string{
		"es256":      token(nil),
		"rs256":      sign(base(nil), "at+jwt", jose.RS256, rsaKey, "rsa"),
		"media type": sign(base(nil), "application/at+jwt", jose.ES256, ec, "ec"),
		"upper case": sign(base(nil), "AT+JWT", jose.ES256, ec, "ec"),
		"array aud":  token(map[string]any{"aud": []any{"https://other.example.test", "https://api.example.test"}}),
		"future iat": token(map[string]any{"iat": now + 30}),
	} {
		claims, err := v.VerifyBearer(ctx, value, "read")
		if err != nil || claims["client_id"] != "app" || claims["sub"] != "user" {
			t.Error("a valid token was refused", name, claims, err)
		}
	}
	// Refused tokens.
	invalid := "invalid access token"
	hs, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(strings.Repeat("k", 32))}, new(jose.SignerOptions).WithType("at+jwt"))
	hsObject, _ := hs.Sign([]byte(`{"iss":"` + iss + `"}`))
	symmetric, _ := hsObject.CompactSerialize()
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+iss+`"}`)) + "."
	for name, c := range map[string]struct {
		token, description string
	}{
		"typ JWT":        {sign(base(nil), "JWT", jose.ES256, ec, "ec"), invalid},
		"no typ":         {sign(base(nil), "", jose.ES256, ec, "ec"), invalid},
		"wrong issuer":   {token(map[string]any{"iss": "https://evil.example.test"}), invalid},
		"wrong audience": {token(map[string]any{"aud": "https://other.example.test"}), invalid},
		"wrong array":    {token(map[string]any{"aud": []any{"https://other.example.test"}}), invalid},
		"no azp":         {token(map[string]any{"azp": nil}), invalid},
		"no exp":         {token(map[string]any{"exp": nil}), invalid},
		"expired":        {token(map[string]any{"exp": now - 1}), "token expired"},
		"not yet valid":  {token(map[string]any{"nbf": now + 60}), invalid},
		"text exp":       {token(map[string]any{"exp": "later"}), invalid},
		"text iat":       {token(map[string]any{"iat": "now"}), invalid},
		"HS256":          {symmetric, invalid},
		"none":           {none, invalid},
		"opaque":         {"access_opaque", "no token payload"},
		"empty scope":    {token(map[string]any{"scope": ""}), "access token scope claim is invalid"},
		"double space":   {token(map[string]any{"scope": "read  write"}), "access token scope claim is invalid"},
		"bound":          {token(map[string]any{"cnf": map[string]any{"jkt": "thumb"}}), "DPoP-bound access token requires request verification"},
		"unknown key":    {sign(base(nil), "at+jwt", jose.ES256, ec, "missing"), invalid},
	} {
		_, err := v.VerifyBearer(ctx, c.token)
		refused(err, 401, "invalid_token", c.description)
		_ = name
	}
	if _, err := v.VerifyBearer(ctx, ""); failure(err).Status != 401 || failure(err).Code != "" || failure(err).Message != "missing authorization header" {
		t.Fatal("a missing token was not refused", err)
	}
	// Missing scopes are reported together.
	_, err = v.VerifyBearer(ctx, token(nil), "read", "admin", "billing")
	refused(err, 403, "insufficient_scope", "access token is missing required scope: admin billing")
	if !slices.Equal(failure(err).MissingScopes, []string{"admin", "billing"}) {
		t.Fatal("the missing scopes were not named", failure(err).MissingScopes)
	}
	// An absent scope claim grants none.
	_, err = v.VerifyBearer(ctx, token(map[string]any{"scope": nil}), "read")
	refused(err, 403, "insufficient_scope", "access token is missing required scope: read")
	// An invalid required scope is a configuration error, before the token.
	if _, err := v.VerifyBearer(ctx, "", "bad scope"); err == nil || errors.As(err, new(*ResourceFailure)) {
		t.Fatal("an invalid required scope was not a configuration error", err)
	}
	// A hierarchical matcher sees de-duplicated granted scopes.
	var seen map[string]bool
	hierarchical, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: iss, Audience: []string{"https://api.example.test"}, JWKSURL: issuer.server.URL, Transport: issuer.server.Client().Transport,
		ScopeSatisfied: func(required string, granted map[string]bool) bool {
			seen = granted
			return granted[required] || granted[strings.SplitN(required, ":", 2)[0]]
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hierarchical.VerifyBearer(ctx, token(map[string]any{"scope": "files files"}), "files:read"); err != nil || len(seen) != 1 {
		t.Fatal("a hierarchical matcher was not applied", err, seen)
	}
	// A key outage is a server error.
	issuer.set(503, "")
	outage, _ := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: iss, Audience: []string{"https://api.example.test"}, JWKSURL: issuer.server.URL, Transport: issuer.server.Client().Transport})
	if _, err := outage.VerifyBearer(ctx, token(nil)); err == nil || errors.As(err, new(*ResourceFailure)) {
		t.Fatal("a key outage was not a server error", err)
	}
	// Construction checks.
	for name, opts := range map[string]AccessTokenVerifierOptions{
		"no issuer":    {Audience: []string{"a"}, JWKSURL: "https://keys.example.test"},
		"no audience":  {Issuer: iss, Audience: []string{""}, JWKSURL: "https://keys.example.test"},
		"plain http":   {Issuer: iss, Audience: []string{"a"}, JWKSURL: "http://keys.example.test/jwks"},
		"credentials":  {Issuer: iss, Audience: []string{"a"}, JWKSURL: "https://user:pass@keys.example.test/jwks"},
		"fragment":     {Issuer: iss, Audience: []string{"a"}, JWKSURL: "https://keys.example.test/jwks#x"},
		"empty claim":  {Issuer: iss, Audience: []string{"a"}, JWKSURL: "https://keys.example.test/jwks", RequiredClaims: []string{""}},
		"relative URL": {Issuer: iss, Audience: []string{"a"}, JWKSURL: "/jwks"},
	} {
		if _, err := NewAccessTokenVerifier(opts); err == nil {
			t.Error("verifier options were accepted", name)
		}
	}
	if _, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: iss, Audience: []string{"a"}, JWKSURL: "http://127.0.0.1:8080/jwks"}); err != nil {
		t.Fatal("a loopback HTTP JWKS URL was refused", err)
	}
}
