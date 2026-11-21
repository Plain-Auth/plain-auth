package providers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func appleSigningKey(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestAppleClientSecret(t *testing.T) {
	private, data := appleSigningKey(t, elliptic.P256())
	opts := AppleClientSecretOptions{TeamID: "ABCDEF1234", KeyID: "012345ABCD", ClientID: "org.example.MyService", PrivateKeyPEM: data}
	for _, validity := range []time.Duration{0, time.Second, 15_777_000 * time.Second} {
		opts.ValidFor = validity
		before := time.Now().Unix()
		token, err := GenerateAppleClientSecret(opts)
		if err != nil {
			t.Fatal(err)
		}
		jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil || len(jws.Signatures) != 1 || jws.Signatures[0].Protected.KeyID != opts.KeyID {
			t.Fatal("missing ES256 signature or key ID", err)
		}
		body, err := jws.Verify(&private.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		var claims struct {
			Iss, Sub, Aud string
			Iat, Exp      int64
		}
		if err := json.Unmarshal(body, &claims); err != nil {
			t.Fatal(err)
		}
		if validity == 0 {
			validity = 180 * 24 * time.Hour
		}
		if claims.Iss != opts.TeamID || claims.Sub != opts.ClientID || claims.Aud != "https://appleid.apple.com" ||
			claims.Iat < before || claims.Iat > time.Now().Unix() || claims.Exp-claims.Iat != int64(validity/time.Second) {
			t.Fatal("incorrect Apple client-secret claims")
		}
		if p := Apple(opts.ClientID, token); p.Config.ClientID != opts.ClientID || p.Config.ClientSecret != token {
			t.Fatal("provider discarded the generated client secret")
		}
	}
}

func TestAppleClientSecretRejectsInvalidOptions(t *testing.T) {
	_, data := appleSigningKey(t, elliptic.P256())
	_, differentCurve := appleSigningKey(t, elliptic.P384())
	base := AppleClientSecretOptions{TeamID: "ABCDEF1234", KeyID: "012345ABCD", ClientID: "org.example.web", PrivateKeyPEM: data}
	for name, change := range map[string]func(*AppleClientSecretOptions){
		"no client":            func(v *AppleClientSecretOptions) { v.ClientID = "" },
		"no team":              func(v *AppleClientSecretOptions) { v.TeamID = "" },
		"no key ID":            func(v *AppleClientSecretOptions) { v.KeyID = " " },
		"negative validity":    func(v *AppleClientSecretOptions) { v.ValidFor = -time.Hour },
		"fractional validity":  func(v *AppleClientSecretOptions) { v.ValidFor = time.Millisecond },
		"Apple validity limit": func(v *AppleClientSecretOptions) { v.ValidFor = 15_777_001 * time.Second },
		"malformed PEM":        func(v *AppleClientSecretOptions) { v.PrivateKeyPEM = []byte("fixture-private-material") },
		"trailing data":        func(v *AppleClientSecretOptions) { v.PrivateKeyPEM = append(append([]byte(nil), data...), data...) },
		"wrong curve":          func(v *AppleClientSecretOptions) { v.PrivateKeyPEM = differentCurve },
	} {
		t.Run(name, func(t *testing.T) {
			opts := base
			change(&opts)
			if token, err := GenerateAppleClientSecret(opts); err == nil || token != "" || strings.Contains(err.Error(), "fixture-private-material") {
				t.Fatal("invalid options issued a credential or exposed key material")
			}
		})
	}
}
