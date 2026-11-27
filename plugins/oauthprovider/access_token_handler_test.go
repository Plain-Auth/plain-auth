package oauthprovider

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Handler answers a request without credentials with a Bearer challenge
// naming the resource metadata, a failed token with invalid_token, a DPoP
// failure with a DPoP challenge, a missing scope with 403 insufficient_scope
// in the presented scheme, and an outage with a logged 500; a verified
// request reaches next with its claims. It refuses a non-URL audience
// without metadata and a missing origin when built.
func TestAccessTokenHandler(t *testing.T) {
	issuer := newIssuerKeys(t)
	signer := issuer.publish("ec")["ec"]
	const iss, aud = "https://issuer.example.test/api/auth", "https://api.example.test/files"
	v, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: iss, Audience: []string{aud}, JWKSURL: issuer.server.URL, Transport: issuer.server.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	var reached map[string]any
	h, err := v.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached, _ = AccessTokenClaims(r.Context())
		w.WriteHeader(204)
	}), "read")
	if err != nil {
		t.Fatal(err)
	}
	_, proofKey, _ := ed25519.GenerateKey(rand.Reader)
	public := (&jose.JSONWebKey{Key: proofKey}).Public()
	thumb, _ := public.Thumbprint(crypto.SHA256)
	jkt := base64.RawURLEncoding.EncodeToString(thumb)
	token := func(extra map[string]any) string {
		claims := map[string]any{"iss": iss, "aud": aud, "sub": "user", "exp": time.Now().Unix() + 60, "scope": "read"}
		for k, value := range extra {
			claims[k] = value
		}
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: signer}, new(jose.SignerOptions).WithHeader("kid", "ec").WithType("at+jwt"))
		payload, _ := json.Marshal(claims)
		object, _ := s.Sign(payload)
		compact, _ := object.CompactSerialize()
		return compact
	}
	serve := func(authorization, proof string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://internal/files/report", nil)
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
	const metadata = `resource_metadata="https://api.example.test/.well-known/oauth-protected-resource/files"`
	check := func(name string, w *httptest.ResponseRecorder, status int, scheme string, contains ...string) {
		t.Helper()
		challenge := w.Header().Get("WWW-Authenticate")
		if w.Code != status || !strings.HasPrefix(challenge, scheme+" ") || !strings.Contains(w.Header().Get("Access-Control-Expose-Headers"), "WWW-Authenticate") {
			t.Fatalf("%s: wanted %d %s, got %d %q", name, status, scheme, w.Code, challenge)
		}
		for _, part := range contains {
			if !strings.Contains(challenge, part) {
				t.Fatalf("%s: the challenge lacked %q: %q", name, part, challenge)
			}
		}
	}
	w := serve("", "")
	check("no credentials", w, 401, "Bearer", metadata)
	if strings.Contains(w.Header().Get("WWW-Authenticate"), "error=") {
		t.Fatal("a request without credentials got an error code", w.Header())
	}
	var body map[string]string
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || body["message"] != "missing authorization header" {
		t.Fatal("the body was wrong", w.Body.String())
	}
	check("expired", serve("Bearer "+token(map[string]any{"exp": time.Now().Unix() - 1}), ""), 401, "Bearer", `error="invalid_token"`, `error_description="token expired"`, metadata)
	check("unbound DPoP", serve("DPoP "+token(nil), ""), 401, "DPoP", `error="invalid_token"`, "algs=")
	bound := token(map[string]any{"cnf": map[string]any{"jkt": jkt}})
	check("bound as bearer", serve("Bearer "+bound, ""), 401, "DPoP", `error="invalid_token"`, "algs=")
	check("bearer scope", serve("Bearer "+token(map[string]any{"scope": "other"}), ""), 403, "Bearer", `error="insufficient_scope"`, `scope="read"`)
	proof := signDPoP(t, jose.EdDSA, proofKey, "dpop+jwt", public, map[string]any{"htm": "GET", "htu": "https://api.example.test/files/report", "iat": time.Now().Unix(), "jti": rand.Text(), "ath": tokenDigest(bound)})
	check("DPoP scope", serve("DPoP "+token(map[string]any{"scope": "other", "cnf": map[string]any{"jkt": jkt}}), ""), 403, "DPoP", `error="insufficient_scope"`, `scope="read"`)
	// A verified request reaches next, with the proof checked against the
	// configured origin rather than the request's host.
	if w := serve("DPoP "+bound, proof); w.Code != 204 || reached["sub"] != "user" {
		t.Fatal("a verified request did not reach next", w.Code, w.Body.String(), reached)
	}
	// An outage is a logged 500.
	var logs bytes.Buffer
	saved := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(saved) })
	issuer.set(503, "")
	broken, _ := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: iss, Audience: []string{aud}, JWKSURL: issuer.server.URL, Transport: issuer.server.Client().Transport})
	brokenHandler, err := broken.Handler(http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://internal/files", nil)
	r.Header.Set("Authorization", "Bearer "+token(nil))
	out := httptest.NewRecorder()
	brokenHandler.ServeHTTP(out, r)
	if out.Code != 500 || !strings.Contains(out.Body.String(), "access token verification failed") || !strings.Contains(logs.String(), "OAuth access token verification failed") {
		t.Fatal("an outage was not a logged 500", out.Code, out.Body.String(), logs.String())
	}
	// Construction checks.
	urn, _ := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: iss, Audience: []string{"urn:api"}, JWKSURL: issuer.server.URL, Origin: "https://api.example.test"})
	if _, err := urn.Handler(http.NotFoundHandler()); err == nil {
		t.Fatal("a non-URL audience without metadata was accepted")
	}
	mapped, _ := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: iss, Audience: []string{"urn:api"}, JWKSURL: issuer.server.URL, Origin: "https://api.example.test",
		MetadataMappings: map[string]string{"urn:api": "https://api.example.test/.well-known/oauth-protected-resource"}})
	if _, err := mapped.Handler(http.NotFoundHandler()); err != nil {
		t.Fatal("a mapped non-URL audience was refused", err)
	}
	originless, _ := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: iss, Audience: []string{"urn:api"}, JWKSURL: issuer.server.URL,
		MetadataMappings: map[string]string{"urn:api": "https://api.example.test/.well-known/oauth-protected-resource"}})
	if _, err := originless.Handler(http.NotFoundHandler()); err == nil {
		t.Fatal("a handler without an origin was accepted")
	}
	if _, err := v.Handler(http.NotFoundHandler(), "bad scope"); err == nil {
		t.Fatal("an invalid scope was accepted")
	}
	if _, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: iss, Audience: []string{aud}, JWKSURL: issuer.server.URL, Origin: "https://api.example.test/path"}); err == nil {
		t.Fatal("an origin with a path was accepted")
	}
}
