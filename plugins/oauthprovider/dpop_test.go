package oauthprovider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	jose "github.com/go-jose/go-jose/v4"
)

func signDPoP(t *testing.T, alg jose.SignatureAlgorithm, key any, typ string, public any, claims map[string]any) string {
	t.Helper()
	opts := new(jose.SignerOptions).WithType(jose.ContentType(typ))
	if public != nil {
		opts.WithHeader("jwk", public)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func expectProofError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var problem *auth.OAuthError
	if !errors.As(err, &problem) || problem.Code != code || problem.Status != status {
		t.Fatalf("got %v, want %d %s", err, status, code)
	}
}

func TestDPoPProofValidation(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := (&jose.JSONWebKey{Key: key}).Public()
	thumb, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	jkt := base64.RawURLEncoding.EncodeToString(thumb)
	const epoch = 1800000000
	const endpoint = "https://api.example.test/v1/a%2Fb"
	req := DPoPProofRequest{Method: "PUT", URL: endpoint + "?version=1", AccessToken: "issued-token", ExpectedThumbprint: jkt}
	base := map[string]any{"htm": "put", "htu": "https://API.example.test:443/x/%2e%2E/v1/a%2Fb?another=2", "jti": "single-use", "iat": epoch, "ath": tokenDigest(req.AccessToken)}
	v, err := NewDPoPVerifier(DPoPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(epoch, 999999999)
	v.now = func() time.Time { return now }
	sign := func(c map[string]any) string { return signDPoP(t, jose.EdDSA, key, "dpop+jwt", pub, c) }
	for _, tc := range []struct {
		name  string
		field string
		value any
	}{
		{"method", "htm", "POST"}, {"path", "htu", "https://api.example.test/v1/a/b"}, {"host", "htu", "https://other.example.test/v1/a%2Fb"},
		{"fragment", "htu", endpoint + "#f"}, {"relative", "htu", "/v1/a%2Fb"}, {"future", "iat", epoch + 6}, {"old", "iat", epoch - 301},
		{"missing iat", "iat", nil}, {"string iat", "iat", "now"}, {"missing ID", "jti", ""}, {"long ID", "jti", strings.Repeat("🧊", 257)},
		{"expired", "exp", epoch}, {"future nbf", "nbf", epoch + 1}, {"bad exp", "exp", "tomorrow"}, {"bad nbf", "nbf", nil},
		{"wrong token", "ath", tokenDigest("other")}, {"missing hash", "ath", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := maps.Clone(base)
			c[tc.field] = tc.value
			_, err := v.Verify(t.Context(), sign(c), req)
			expectProofError(t, err, 400, "invalid_dpop_proof")
		})
	}
	altered := req
	altered.ExpectedThumbprint = "wrong"
	proof := sign(base)
	_, err = v.Verify(t.Context(), proof, altered)
	expectProofError(t, err, 400, "invalid_dpop_proof")
	altered = req
	altered.RequireAccessTokenHash = true
	altered.AccessToken = ""
	missing := maps.Clone(base)
	delete(missing, "ath")
	_, err = v.Verify(t.Context(), sign(missing), altered)
	expectProofError(t, err, 400, "invalid_dpop_proof")
	result, err := v.Verify(t.Context(), proof, req)
	if err != nil || result.Thumbprint != jkt || result.URL != endpoint || result.Method != "put" || result.ID != "single-use" || result.ReplayKey != tokenDigest(jkt+"\nPUT\n"+endpoint+"\nsingle-use") || !result.ExpiresAt.Equal(time.Unix(epoch+301, 0)) {
		t.Fatalf("validated proof %+v, err %v", result, err)
	}
	changed := maps.Clone(base)
	changed["htm"] = "PUT"
	changed["htu"] = endpoint
	_, err = v.Verify(t.Context(), sign(changed), req)
	expectProofError(t, err, 400, "invalid_dpop_proof")
	now = now.Add(300 * time.Second)
	_, err = v.Verify(t.Context(), proof, req)
	expectProofError(t, err, 400, "invalid_dpop_proof")
	now = now.Add(time.Second)
	changed["iat"] = now.Unix() + 5
	_, err = v.Verify(t.Context(), sign(changed), req)
	if err != nil {
		t.Fatal("new proof after expiry", err)
	}
	changed["iat"] = float64(now.Unix()) - 299.5
	changed["jti"] = strings.Repeat("🧊", 256)
	result, err = v.Verify(t.Context(), sign(changed), req)
	if err != nil || result.IssuedAt.Nanosecond() != 500000000 {
		t.Fatal("valid fractional time and 512-unit ID", err)
	}
}

type unavailableProofStore struct{ err error }

func (s unavailableProofStore) ReserveDPoPProof(context.Context, string, time.Time, time.Time) (bool, error) {
	return false, s.err
}

func TestDPoPBindingAndReplay(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := (&jose.JSONWebKey{Key: key}).Public()
	thumb, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	req := DPoPProofRequest{Method: "GET", URL: "https://api.example.test/doc", AccessToken: "token", ExpectedThumbprint: base64.RawURLEncoding.EncodeToString(thumb)}
	claims := map[string]any{"htm": req.Method, "htu": req.URL, "iat": time.Now().Unix(), "jti": "once", "ath": tokenDigest(req.AccessToken)}
	proof := signDPoP(t, jose.EdDSA, key, "dpop+jwt", pub, claims)
	v, err := NewDPoPVerifier(DPoPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	absent := req
	absent.AccessToken = ""
	expectProofError(t, v.CheckBinding(t.Context(), "DPoP", proof, absent), 401, "invalid_token")
	unbound := req
	unbound.ExpectedThumbprint = ""
	if err = v.CheckBinding(t.Context(), "Bearer", "", unbound); err != nil {
		t.Fatal(err)
	}
	expectProofError(t, v.CheckBinding(t.Context(), "DPoP", proof, unbound), 401, "invalid_token")
	expectProofError(t, v.CheckBinding(t.Context(), "Basic", proof, unbound), 401, "invalid_token")
	expectProofError(t, v.CheckBinding(t.Context(), "Bearer", proof, req), 401, "invalid_token")
	expectProofError(t, v.CheckBinding(t.Context(), "DPoP", "", req), 401, "invalid_dpop_proof")
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			err := v.CheckBinding(t.Context(), "dpop", proof, req)
			if err == nil {
				wins.Add(1)
				return
			}
			expectProofError(t, err, 401, "invalid_dpop_proof")
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("proof accepted %d times", wins.Load())
	}
	down := errors.New("storage unavailable")
	failed, err := NewDPoPVerifier(DPoPOptions{ReplayStore: unavailableProofStore{down}})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(failed.CheckBinding(t.Context(), "DPoP", proof, req), down) {
		t.Fatal("lost backend failure")
	}
}

func TestDPoPProofSigningAlgorithms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req := DPoPProofRequest{Method: "POST", URL: "https://issuer.example.test/token"}
	c := map[string]any{"htm": req.Method, "htu": req.URL, "iat": time.Now().Unix(), "jti": "algorithms"}
	for _, alg := range assertionAlgorithms {
		t.Run(string(alg), func(t *testing.T) {
			var key any = rsaKey
			switch alg {
			case jose.EdDSA:
				key = edKey
			case jose.ES256, jose.ES384, jose.ES512:
				curve := map[jose.SignatureAlgorithm]elliptic.Curve{jose.ES256: elliptic.P256(), jose.ES384: elliptic.P384(), jose.ES512: elliptic.P521()}[alg]
				key, err = ecdsa.GenerateKey(curve, rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
			}
			pub := (&jose.JSONWebKey{Key: key}).Public()
			proof := signDPoP(t, alg, key, "dpop+jwt", pub, c)
			v, err := NewDPoPVerifier(DPoPOptions{SigningAlgorithms: []string{string(alg)}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = v.Verify(t.Context(), proof, req); err != nil {
				t.Fatal(err)
			}
			disabled, err := NewDPoPVerifier(DPoPOptions{SigningAlgorithms: []string{}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = disabled.Verify(t.Context(), proof, req)
			expectProofError(t, err, 400, "invalid_dpop_proof")
		})
	}
	for _, alg := range []string{"HS256", "none"} {
		if _, err := NewDPoPVerifier(DPoPOptions{SigningAlgorithms: []string{alg}}); err == nil {
			t.Fatal("accepted", alg)
		}
	}
	if _, err := NewDPoPVerifier(DPoPOptions{ProofMaxAge: -1}); err == nil {
		t.Fatal("negative age accepted")
	}
	v, _ := NewDPoPVerifier(DPoPOptions{})
	pub := (&jose.JSONWebKey{Key: edKey}).Public()
	raw, err := json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"k", "d", "p", "q", "dp", "dq", "qi", "oth", "key_ops", "use", "alg"} {
		header := maps.Clone(fields)
		header[field] = nil
		switch field {
		case "key_ops":
			header[field] = []string{"sign"}
		case "use":
			header[field] = "enc"
		case "alg":
			header[field] = "ES256"
		}
		_, err = v.Verify(t.Context(), signDPoP(t, jose.EdDSA, edKey, "dpop+jwt", header, c), req)
		expectProofError(t, err, 400, "invalid_dpop_proof")
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, proof := range []string{"malformed", signDPoP(t, jose.EdDSA, edKey, "JWT", pub, c), signDPoP(t, jose.EdDSA, edKey, "dpop+jwt", nil, c), signDPoP(t, jose.EdDSA, other, "dpop+jwt", pub, c)} {
		_, err = v.Verify(t.Context(), proof, req)
		expectProofError(t, err, 400, "invalid_dpop_proof")
	}
}
