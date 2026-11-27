package oauthprovider

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
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

// VerifyRequest reads Bearer and DPoP schemes case-insensitively and
// refuses others; checks a DPoP-bound token's proof for the request's
// method, URL and token, once; refuses a bound token sent as Bearer and an
// unbound one sent as DPoP; answers a missing scope before a bad proof; and
// returns a replay store failure as a server error.
func TestAccessTokenVerifierRequests(t *testing.T) {
	ctx := t.Context()
	issuer := newIssuerKeys(t)
	signer := issuer.publish("ec")["ec"]
	const iss, aud = "https://issuer.example.test/api/auth", "https://api.example.test"
	v, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: iss, Audience: []string{aud}, JWKSURL: issuer.server.URL, Transport: issuer.server.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	_, proofKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := (&jose.JSONWebKey{Key: proofKey}).Public()
	thumb, _ := public.Thumbprint(crypto.SHA256)
	jkt := base64.RawURLEncoding.EncodeToString(thumb)
	now := time.Now().Unix()
	token := func(extra map[string]any) string {
		claims := map[string]any{"iss": iss, "aud": aud, "sub": "user", "exp": now + 60, "scope": "read"}
		for k, value := range extra {
			claims[k] = value
		}
		signerOpts := new(jose.SignerOptions).WithHeader("kid", "ec").WithType("at+jwt")
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: signer}, signerOpts)
		payload, _ := json.Marshal(claims)
		object, _ := s.Sign(payload)
		compact, _ := object.CompactSerialize()
		return compact
	}
	bearer, bound := token(nil), token(map[string]any{"cnf": map[string]any{"jkt": jkt}})
	const target = aud + "/posts"
	proof := func(access, method, url string, key any, jwk any) string {
		return signDPoP(t, jose.EdDSA, key, "dpop+jwt", jwk, map[string]any{"htm": method, "htu": url, "iat": time.Now().Unix(), "jti": rand.Text(), "ath": tokenDigest(access)})
	}
	request := func(authorization, dpop string) ResourceRequest {
		return ResourceRequest{Authorization: authorization, DPoP: dpop, Method: "GET", URL: target}
	}
	// Accepted requests.
	for name, req := range map[string]ResourceRequest{
		"bearer":       request("Bearer "+bearer, ""),
		"lower bearer": request("  bearer   "+bearer+" ", ""),
		"dpop":         request("DPoP "+bound, proof(bound, "GET", target, proofKey, public)),
		"mixed dpop":   request("dPoP "+bound, proof(bound, "GET", target, proofKey, public)),
	} {
		if claims, err := v.VerifyRequest(ctx, req, "read"); err != nil || claims["sub"] != "user" {
			t.Error("a valid request was refused", name, err)
		}
	}
	// Refused requests.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherPublic := (&jose.JSONWebKey{Key: other}).Public()
	_, err = v.VerifyRequest(ctx, request("", ""))
	if f := (*ResourceFailure)(nil); !errors.As(err, &f) || f.Status != 401 || f.Code != "" || f.Message != "missing authorization header" {
		t.Fatal("a missing header was not refused", err)
	}
	for name, c := range map[string]struct {
		req               ResourceRequest
		code, description string
	}{
		"basic":        {request("Basic "+base64.StdEncoding.EncodeToString([]byte("a:b")), ""), "invalid_token", "authorization scheme must be Bearer or DPoP"},
		"no scheme":    {request(bearer, ""), "invalid_token", "authorization scheme must be Bearer or DPoP"},
		"unbound dpop": {request("DPoP "+bearer, ""), "invalid_token", "DPoP authorization requires a DPoP-bound access token"},
		"bound bearer": {request("Bearer "+bound, proof(bound, "GET", target, proofKey, public)), "invalid_token", "DPoP-bound access token requires the DPoP authorization scheme"},
		"no proof":     {request("DPoP "+bound, ""), "invalid_dpop_proof", "DPoP proof header is required"},
		"wrong token":  {request("DPoP "+bound, proof(bearer, "GET", target, proofKey, public)), "invalid_dpop_proof", ""},
		"wrong method": {request("DPoP "+bound, proof(bound, "POST", target, proofKey, public)), "invalid_dpop_proof", ""},
		"wrong URL":    {request("DPoP "+bound, proof(bound, "GET", aud+"/other", proofKey, public)), "invalid_dpop_proof", ""},
		"wrong key":    {request("DPoP "+bound, proof(bound, "GET", target, other, otherPublic)), "invalid_dpop_proof", ""},
	} {
		_, err := v.VerifyRequest(ctx, c.req)
		var f *ResourceFailure
		if !errors.As(err, &f) || f.Status != 401 || f.Code != c.code || c.description != "" && f.Description != c.description {
			t.Error("a request was not refused", name, err)
		}
	}
	// A proof is spent once.
	once := proof(bound, "GET", target, proofKey, public)
	if _, err := v.VerifyRequest(ctx, request("DPoP "+bound, once)); err != nil {
		t.Fatal(err)
	}
	_, err = v.VerifyRequest(ctx, request("DPoP "+bound, once))
	var replay *ResourceFailure
	if !errors.As(err, &replay) || replay.Code != "invalid_dpop_proof" {
		t.Fatal("a replayed proof was accepted", err)
	}
	// A missing scope is answered before a bad proof.
	if _, err := v.VerifyRequest(ctx, request("DPoP "+bound, ""), "admin"); !errors.As(err, new(*ResourceFailure)) || err.(*ResourceFailure).Status != 403 {
		t.Fatal("a missing scope was not answered first", err)
	}
	// A replay store failure is a server error.
	broken, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: iss, Audience: []string{aud}, JWKSURL: issuer.server.URL, Transport: issuer.server.Client().Transport,
		DPoP: DPoPOptions{ReplayStore: unavailableProofStore{errors.New("store down")}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broken.VerifyRequest(ctx, request("DPoP "+bound, proof(bound, "GET", target, proofKey, public))); err == nil || errors.As(err, new(*ResourceFailure)) {
		t.Fatal("a replay store failure was not a server error", err)
	}
}

// ResourceRequestFrom reads the request with the API's public origin.
func TestResourceRequestFrom(t *testing.T) {
	r := httptest.NewRequest("POST", "http://internal:8080/v1/posts?id=7", nil)
	r.Header.Set("Authorization", "DPoP token")
	r.Header.Set("DPoP", "proof")
	got := ResourceRequestFrom(r, "https://api.example.test/")
	if got != (ResourceRequest{Authorization: "DPoP token", DPoP: "proof", Method: "POST", URL: "https://api.example.test/v1/posts?id=7"}) {
		t.Fatal("the resource request was read wrong", got)
	}
}

// Remote verification posts the token to the issuer's introspection
// endpoint with the API's credentials and checks the response: inactive,
// audience-less, foreign, expired and wrongly issued answers are refused,
// AllowMissingAudience accepts only a missing aud, an opaque token reported
// active passes, Force skips the local check and its typ, active must be
// JSON true, and failed calls are server errors.
func TestAccessTokenVerifierRemote(t *testing.T) {
	ctx := t.Context()
	issuer := newIssuerKeys(t)
	signer := issuer.publish("ec")["ec"]
	const iss, aud = "https://issuer.example.test/api/auth", "https://api.example.test"
	now := time.Now().Unix()
	var mu sync.Mutex
	var forms []url.Values
	var headers []http.Header
	response := `{}`
	status := 200
	stub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		mu.Lock()
		forms, headers = append(forms, r.PostForm), append(headers, r.Header.Clone())
		body, code := response, status
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		w.Write([]byte(body))
	}))
	t.Cleanup(stub.Close)
	answer := func(code int, body map[string]any) {
		raw, _ := json.Marshal(body)
		mu.Lock()
		status, response = code, string(raw)
		mu.Unlock()
	}
	remote := func(r RemoteVerification, jwks bool) *AccessTokenVerifier {
		t.Helper()
		r.IntrospectionURL, r.ClientID, r.ClientSecret = stub.URL+"/introspect", "api", "api-secret"
		opts := AccessTokenVerifierOptions{Issuer: iss, Audience: []string{aud}, Remote: &r, Transport: stub.Client().Transport}
		if jwks {
			opts.JWKSURL = issuer.server.URL
		}
		v, err := NewAccessTokenVerifier(opts)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	active := func(extra map[string]any) map[string]any {
		body := map[string]any{"active": true, "iss": iss, "aud": aud, "sub": "user", "client_id": "app", "exp": now + 60, "scope": "read"}
		for k, value := range extra {
			if value == nil {
				delete(body, k)
			} else {
				body[k] = value
			}
		}
		return body
	}
	refused := func(err error, description string) {
		t.Helper()
		var f *ResourceFailure
		if !errors.As(err, &f) || f.Status != 401 || f.Code != "invalid_token" || f.Description != description {
			t.Fatalf("wanted invalid_token %q, got %v", description, err)
		}
	}
	v := remote(RemoteVerification{}, false)
	// The request carries exactly the API's credentials and the token.
	answer(200, active(nil))
	claims, err := v.VerifyBearer(ctx, "access_opaque", "read")
	if err != nil || claims["sub"] != "user" {
		t.Fatal("an opaque token reported active was refused", err)
	}
	mu.Lock()
	form, header := forms[len(forms)-1], headers[len(headers)-1]
	mu.Unlock()
	if len(form) != 4 || form.Get("client_id") != "api" || form.Get("client_secret") != "api-secret" || form.Get("token") != "access_opaque" || form.Get("token_type_hint") != "access_token" ||
		header.Get("Accept") != "application/json" || header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatal("the introspection request was wrong", form, header)
	}
	for name, c := range map[string]struct {
		body        map[string]any
		description string
	}{
		"inactive":       {map[string]any{"active": false}, "token inactive"},
		"string active":  {active(map[string]any{"active": "true"}), "token inactive"},
		"no audience":    {active(map[string]any{"aud": nil}), "invalid access token"},
		"other audience": {active(map[string]any{"aud": "https://other.example.test"}), "invalid access token"},
		"expired":        {active(map[string]any{"exp": now - 1}), "token expired"},
		"other issuer":   {active(map[string]any{"iss": "https://evil.example.test"}), "invalid access token"},
	} {
		answer(200, c.body)
		_, err := v.VerifyBearer(ctx, "access_opaque")
		refused(err, c.description)
		_ = name
	}
	// exp is optional in an introspection response.
	answer(200, active(map[string]any{"exp": nil}))
	if _, err := v.VerifyBearer(ctx, "access_opaque"); err != nil {
		t.Fatal("an introspection response without exp was refused", err)
	}
	// AllowMissingAudience accepts only a missing aud.
	lenient := remote(RemoteVerification{AllowMissingAudience: true}, false)
	answer(200, active(map[string]any{"aud": nil}))
	if _, err := lenient.VerifyBearer(ctx, "access_opaque"); err != nil {
		t.Fatal("AllowMissingAudience refused a missing aud", err)
	}
	answer(200, active(map[string]any{"aud": "https://other.example.test"}))
	_, err = lenient.VerifyBearer(ctx, "access_opaque")
	refused(err, "invalid access token")
	// A JWT passes both checks; without Force a wrong typ is refused
	// locally, with Force it is not.
	jwt := func(typ string) string {
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: signer}, new(jose.SignerOptions).WithHeader("kid", "ec").WithType(jose.ContentType(typ)))
		payload, _ := json.Marshal(map[string]any{"iss": iss, "aud": aud, "sub": "user", "exp": now + 60})
		object, _ := s.Sign(payload)
		compact, _ := object.CompactSerialize()
		return compact
	}
	both := remote(RemoteVerification{}, true)
	answer(200, active(nil))
	if _, err := both.VerifyBearer(ctx, jwt("at+jwt")); err != nil {
		t.Fatal("a JWT did not pass both checks", err)
	}
	_, err = both.VerifyBearer(ctx, jwt("JWT"))
	refused(err, "invalid access token")
	if _, err := remote(RemoteVerification{Force: true}, true).VerifyBearer(ctx, jwt("JWT")); err != nil {
		t.Fatal("Force did not skip the local check", err)
	}
	// Failed calls are server errors.
	for _, code := range []int{401, 500, 302} {
		answer(code, map[string]any{"error": "x"})
		if _, err := v.VerifyBearer(ctx, "access_opaque"); err == nil || errors.As(err, new(*ResourceFailure)) || strings.Contains(err.Error(), "api-secret") {
			t.Fatal("a failed introspection was not a server error", code, err)
		}
	}
	// Construction checks.
	for name, r := range map[string]*RemoteVerification{
		"plain http": {IntrospectionURL: "http://issuer.example.test/introspect", ClientID: "a", ClientSecret: "b"},
		"no client":  {IntrospectionURL: stub.URL, ClientSecret: "b"},
		"no secret":  {IntrospectionURL: stub.URL, ClientID: "a"},
	} {
		if _, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: iss, Audience: []string{aud}, Remote: r}); err == nil {
			t.Error("remote options were accepted", name)
		}
	}
	if _, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: iss, Audience: []string{aud}}); err == nil {
		t.Fatal("a verifier without a key source or introspection was accepted")
	}
}
