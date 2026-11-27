package mcp_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth/plugins/mcp"
	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	jose "github.com/go-jose/go-jose/v4"
)

const (
	issuer   = "https://app.example.com"
	resource = "https://app.example.com/mcp"
)

type fixture struct {
	t      *testing.T
	signer *ecdsa.PrivateKey
	jwks   *httptest.Server
	down   atomic.Bool
}

func newFixture(t *testing.T) *fixture {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, signer: key}
	f.jwks = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.down.Load() {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "ES256", Use: "sig"}}})
	}))
	t.Cleanup(f.jwks.Close)
	return f
}

func (f *fixture) token(extra map[string]any) string {
	claims := map[string]any{"iss": issuer, "aud": resource, "sub": "user-5", "azp": "client-1", "exp": time.Now().Unix() + 60, "scope": "mcp:read"}
	for k, v := range extra {
		claims[k] = v
	}
	s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: f.signer}, new(jose.SignerOptions).WithHeader("kid", "k").WithType("at+jwt"))
	payload, _ := json.Marshal(claims)
	object, _ := s.Sign(payload)
	compact, _ := object.CompactSerialize()
	return compact
}

func (f *fixture) handler(opts mcp.ProtectedHandlerOptions, next http.Handler) http.Handler {
	f.t.Helper()
	opts.Issuer, opts.Audience, opts.JWKSURL, opts.Transport = issuer, []string{resource}, f.jwks.URL, f.jwks.Client().Transport
	h, err := mcp.NewProtectedHandler(opts, next)
	if err != nil {
		f.t.Fatal(err)
	}
	return h
}

func serve(h http.Handler, authorization, proof string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", resource, nil)
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	if proof != "" {
		r.Header.Set("DPoP", proof)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

var unreachable = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("unreachable") })

// A protected MCP handler answers failures with the challenges another
// runtime's handler sends, exact headers included, and a JSON-RPC body.
func TestProtectedHandlerChallenges(t *testing.T) {
	f := newFixture(t)
	// A scope failure is a 403 insufficient_scope challenge.
	w := serve(f.handler(mcp.ProtectedHandlerOptions{RequiredScopes: []string{"mcp:write"}}, unreachable), "Bearer "+f.token(nil), "")
	if w.Code != 403 || w.Header().Get("WWW-Authenticate") != `Bearer error="insufficient_scope", scope="mcp:write", resource_metadata="https://app.example.com/.well-known/oauth-protected-resource/mcp", error_description="access token is missing required scope: mcp:write"` {
		t.Fatal("the scope failure was wrong", w.Code, w.Header())
	}
	if w.Body.String() != `{"jsonrpc":"2.0","error":{"code":-32000,"message":"access token is missing required scope: mcp:write"},"id":null}`+"\n" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatal("the JSON-RPC body was wrong", w.Body.String())
	}
	// The challenge scope hint and the expose header.
	w = serve(f.handler(mcp.ProtectedHandlerOptions{ChallengeScopes: []string{"mcp:read"}}, unreachable), "", "")
	if w.Code != 401 || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Bearer ") || !strings.Contains(w.Header().Get("WWW-Authenticate"), `scope="mcp:read"`) ||
		w.Header().Get("Access-Control-Expose-Headers") != "WWW-Authenticate" {
		t.Fatal("the unauthenticated challenge was wrong", w.Code, w.Header())
	}
	// The hint defaults to the required scopes.
	w = serve(f.handler(mcp.ProtectedHandlerOptions{RequiredScopes: []string{"mcp:write"}}, unreachable), "", "")
	if !strings.Contains(w.Header().Get("WWW-Authenticate"), `scope="mcp:write"`) {
		t.Fatal("the challenge hint did not default to the required scopes", w.Header())
	}
	// A failed DPoP request gets a DPoP challenge.
	dpopOpts := mcp.ProtectedHandlerOptions{}
	dpopOpts.DPoP.SigningAlgorithms = []string{"ES256"}
	w = serve(f.handler(dpopOpts, unreachable), "DPoP "+f.token(map[string]any{"exp": time.Now().Unix() - 1}), "")
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") != `DPoP error="invalid_token", error_description="token expired", algs="ES256"` {
		t.Fatal("the DPoP challenge was wrong", w.Code, w.Header())
	}
	// A wrong typ or algorithm is refused.
	if w := serve(f.handler(mcp.ProtectedHandlerOptions{}, unreachable), "Bearer access-token", ""); w.Code != 401 {
		t.Fatal("an opaque token passed without introspection", w.Code)
	}
}

// A verified request reaches next with its claims; next can ask for more
// scopes with WriteInsufficientScope in the request's scheme, and a 403 it
// writes itself passes through unchanged. An outage reaches OnError.
func TestProtectedHandlerRequests(t *testing.T) {
	f := newFixture(t)
	var seen map[string]any
	stepUp := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = mcp.AccessTokenClaims(r.Context())
		switch {
		case stepUp:
			if err := mcp.WriteInsufficientScope(w, r, "mcp:admin"); err != nil {
				t.Error(err)
			}
		case r.Header.Get("X-Deny") != "":
			w.WriteHeader(403)
			w.Write([]byte("denied"))
		default:
			w.WriteHeader(204)
		}
	})
	opts := mcp.ProtectedHandlerOptions{}
	opts.DPoP.SigningAlgorithms = []string{"ES256", "EdDSA"}
	h := f.handler(opts, next)
	if w := serve(h, "Bearer "+f.token(nil), ""); w.Code != 204 || seen["sub"] != "user-5" || seen["client_id"] != "client-1" {
		t.Fatal("a verified request did not reach next with its claims", w.Code, seen)
	}
	stepUp = true
	if w := serve(h, "Bearer "+f.token(nil), ""); w.Code != 403 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `scope="mcp:admin"`) || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Bearer ") {
		t.Fatal("a bearer step-up was wrong", w.Code, w.Header())
	}
	// A DPoP-bound request steps up with a DPoP challenge.
	_, proofKey, _ := ed25519.GenerateKey(rand.Reader)
	public := (&jose.JSONWebKey{Key: proofKey}).Public()
	thumb, _ := public.Thumbprint(crypto.SHA256)
	bound := f.token(map[string]any{"cnf": map[string]any{"jkt": base64.RawURLEncoding.EncodeToString(thumb)}})
	proof := func() string {
		sum := sha256.Sum256([]byte(bound))
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: proofKey}, new(jose.SignerOptions).WithType("dpop+jwt").WithHeader("jwk", public))
		payload, _ := json.Marshal(map[string]any{"htm": "POST", "htu": resource, "iat": time.Now().Unix(), "jti": rand.Text(), "ath": base64.RawURLEncoding.EncodeToString(sum[:])})
		object, _ := s.Sign(payload)
		compact, _ := object.CompactSerialize()
		return compact
	}
	if w := serve(h, "DPoP "+bound, proof()); w.Code != 403 || w.Header().Get("WWW-Authenticate") != `DPoP error="insufficient_scope", scope="mcp:admin", error_description="access token is missing required scope: mcp:admin", algs="ES256 EdDSA"` {
		t.Fatal("a DPoP step-up was wrong", w.Code, w.Header())
	}
	// A spent proof is refused.
	stepUp = false
	once := proof()
	if w := serve(h, "DPoP "+bound, once); w.Code != 204 {
		t.Fatal("a bound request was refused", w.Code, w.Body.String())
	}
	if w := serve(h, "DPoP "+bound, once); w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "invalid_dpop_proof") {
		t.Fatal("a replayed proof was accepted", w.Code, w.Header())
	}
	// next's own 403 passes through.
	r := httptest.NewRequest("POST", resource, nil)
	r.Header.Set("Authorization", "Bearer "+f.token(nil))
	r.Header.Set("X-Deny", "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || w.Body.String() != "denied" || w.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("next's denial was changed", w.Code, w.Body.String(), w.Header())
	}
	// WriteInsufficientScope needs a protected request.
	if err := mcp.WriteInsufficientScope(httptest.NewRecorder(), httptest.NewRequest("GET", resource, nil), "mcp:admin"); err == nil {
		t.Fatal("an unprotected request stepped up")
	}
	// An outage reaches OnError.
	var reported error
	failing := f.handler(mcp.ProtectedHandlerOptions{OnError: func(w http.ResponseWriter, r *http.Request, err error) {
		reported = err
		w.WriteHeader(502)
	}}, unreachable)
	f.down.Store(true)
	if w := serve(failing, "Bearer "+f.token(nil), ""); w.Code != 502 || reported == nil || errors.As(reported, new(*oauthprovider.ResourceFailure)) {
		t.Fatal("an outage did not reach OnError", w.Code, reported)
	}
}

// The MCP resource must be an HTTPS URL, or HTTP on a loopback host,
// without credentials, fragment or query.
func TestProtectedHandlerResource(t *testing.T) {
	build := func(resource string) error {
		_, err := mcp.NewProtectedHandler(mcp.ProtectedHandlerOptions{AccessTokenVerifierOptions: oauthprovider.AccessTokenVerifierOptions{
			Issuer: issuer, Audience: []string{resource}, JWKSURL: "https://app.example.com/jwks"}}, unreachable)
		return err
	}
	for bad, message := range map[string]string{
		"urn:example:mcp":                       "must be an absolute URL",
		"http://app.example.com/mcp":            "must use HTTPS",
		"http://mcp.internal/mcp":               "must use HTTPS",
		"http://127.example.com/mcp":            "must use HTTPS",
		"https://user:pass@app.example.com/mcp": "must not contain credentials",
		"https://app.example.com/mcp#x":         "must not contain a fragment",
		"https://app.example.com/mcp?x=1":       "must not contain a query",
		"https://app.example.com/m cp":          "must not contain spaces",
	} {
		if err := build(bad); err == nil || !strings.Contains(err.Error(), message) {
			t.Error("a bad MCP resource was not refused for its reason", bad, err)
		}
	}
	for _, good := range []string{"https://app.example.com/mcp", "http://localhost:3000/mcp", "http://my-branch.api.localhost/mcp", "http://127.0.0.1:3000/mcp", "http://127.42.0.1/mcp", "http://[::1]:3000/mcp"} {
		if err := build(good); err != nil {
			t.Error("a good MCP resource was refused", good, err)
		}
	}
	if _, err := mcp.NewProtectedHandler(mcp.ProtectedHandlerOptions{AccessTokenVerifierOptions: oauthprovider.AccessTokenVerifierOptions{
		Issuer: issuer, Audience: []string{resource, "https://other.example.com"}, JWKSURL: "https://app.example.com/jwks"}}, unreachable); err == nil {
		t.Fatal("two audiences were accepted")
	}
}
