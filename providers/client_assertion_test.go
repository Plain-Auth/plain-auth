package providers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/go-jose/go-jose/v4"
)

func pkcs8PEM(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func privateJWK(t *testing.T, key crypto.Signer, kid, alg string) []byte {
	t.Helper()
	raw, err := (jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: alg}).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// PrivateKeyJWT signs a fresh assertion for each token request, with the
// client ID as issuer and subject, the token endpoint as audience, the
// configured lifetime and a new jti, from an RSA, EC or Ed25519 key in PEM
// or JWK form.
func TestPrivateKeyJWT(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	request := auth.TokenRequest{ClientID: "client", TokenURL: "https://idp.example/token", GrantType: "authorization_code"}
	for _, tc := range []struct {
		name     string
		options  PrivateKeyJWTOptions
		public   crypto.PublicKey
		alg, kid string
		lifetime int64
	}{
		{"RSA PEM", PrivateKeyJWTOptions{PrivateKeyPEM: pkcs8PEM(t, rsaKey), KeyID: "rsa-1"}, &rsaKey.PublicKey, "RS256", "rsa-1", 120},
		{"EC JWK", PrivateKeyJWTOptions{PrivateKeyJWK: privateJWK(t, ecKey, "ec-1", "ES256"), ValidFor: time.Minute}, &ecKey.PublicKey, "ES256", "ec-1", 60},
		{"explicit kid over the JWK's", PrivateKeyJWTOptions{PrivateKeyJWK: privateJWK(t, ecKey, "ec-1", "ES256"), KeyID: "override"}, &ecKey.PublicKey, "ES256", "override", 120},
		{"Ed25519 PEM", PrivateKeyJWTOptions{PrivateKeyPEM: pkcs8PEM(t, edKey), Algorithm: "EdDSA"}, edKey.Public(), "EdDSA", "", 120},
	} {
		sign, err := PrivateKeyJWT(tc.options)
		if err != nil {
			t.Fatal(tc.name, err)
		}
		var jtis []string
		for range 2 {
			raw, err := sign(context.Background(), request)
			if err != nil {
				t.Fatal(tc.name, err)
			}
			parsed, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(tc.alg)})
			if err != nil {
				t.Fatal(tc.name, err)
			}
			payload, err := parsed.Verify(tc.public)
			if err != nil {
				t.Fatal(tc.name, "the signature did not verify:", err)
			}
			header := parsed.Signatures[0].Header
			if header.KeyID != tc.kid || header.ExtraHeaders["typ"] != "JWT" {
				t.Fatalf("%s: header %+v", tc.name, header)
			}
			var claims struct {
				Iss, Sub, Aud, Jti string
				Iat, Exp           int64
			}
			if err := json.Unmarshal(payload, &claims); err != nil || claims.Iss != "client" || claims.Sub != "client" || claims.Aud != request.TokenURL || claims.Exp-claims.Iat != tc.lifetime || claims.Jti == "" {
				t.Fatalf("%s: claims %+v %v", tc.name, claims, err)
			}
			jtis = append(jtis, claims.Jti)
		}
		if jtis[0] == jtis[1] {
			t.Fatal(tc.name, "reused a jti")
		}
	}
}

// PrivateKeyJWT refuses symmetric and unknown algorithms, a JWK whose alg
// conflicts, a public JWK, a key that does not fit its algorithm, two or no
// key sources, a short RSA key, and lifetimes outside whole seconds up to five
// minutes.
func TestPrivateKeyJWTRefusals(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	public, _ := (jose.JSONWebKey{Key: &p256.PublicKey}).MarshalJSON()
	pem := pkcs8PEM(t, rsaKey)
	for name, o := range map[string]PrivateKeyJWTOptions{
		"HS256":              {PrivateKeyPEM: pem, Algorithm: "HS256"},
		"none":               {PrivateKeyPEM: pem, Algorithm: "none"},
		"conflicting alg":    {PrivateKeyJWK: privateJWK(t, p256, "k", "ES256"), Algorithm: "ES384"},
		"public JWK":         {PrivateKeyJWK: public},
		"P-384 with ES256":   {PrivateKeyPEM: pkcs8PEM(t, p384), Algorithm: "ES256"},
		"EC with RS256":      {PrivateKeyPEM: pkcs8PEM(t, p256)},
		"both sources":       {PrivateKeyPEM: pem, PrivateKeyJWK: privateJWK(t, rsaKey, "k", "RS256")},
		"no source":          {},
		"RSA-1024":           {PrivateKeyPEM: pkcs8PEM(t, small)},
		"fractional seconds": {PrivateKeyPEM: pem, ValidFor: 1500 * time.Millisecond},
		"six minutes":        {PrivateKeyPEM: pem, ValidFor: 6 * time.Minute},
	} {
		if _, err := PrivateKeyJWT(o); err == nil {
			t.Fatal("PrivateKeyJWT accepted", name)
		}
	}
}
