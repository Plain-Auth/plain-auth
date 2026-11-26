// Package clientassertion signs RFC 7523 private_key_jwt client assertions
// for the social providers and the enterprise SSO plugin.
package clientassertion

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Options configures New; see providers.PrivateKeyJWTOptions.
type Options struct {
	PrivateKeyPEM, PrivateKeyJWK []byte
	KeyID, Algorithm             string
	CertificatePEM               []byte
	ValidFor                     time.Duration
}

// Algorithms are the assertion signing algorithms.
var Algorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

// Signer signs a fresh assertion with iss and sub set to clientID and aud
// set to audience. It may run concurrently.
type Signer func(clientID, audience string) (string, error)

// New checks the key against the algorithm once and returns its Signer.
// Errors never include key material.
func New(o Options) (Signer, error) {
	var key crypto.Signer
	keyID, alg := o.KeyID, o.Algorithm
	switch {
	case len(o.PrivateKeyPEM) > 0 && len(o.PrivateKeyJWK) == 0:
		source := bytes.TrimSpace(o.PrivateKeyPEM)
		block, rest := pem.Decode(source)
		if !bytes.HasPrefix(source, []byte("-----BEGIN PRIVATE KEY-----")) || block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("private key JWT: the PEM must be one PKCS#8 PRIVATE KEY block")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		signer, ok := parsed.(crypto.Signer)
		if err != nil || !ok {
			return nil, errors.New("private key JWT: unreadable private key")
		}
		key = signer
	case len(o.PrivateKeyJWK) > 0 && len(o.PrivateKeyPEM) == 0:
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(o.PrivateKeyJWK); err != nil || jwk.IsPublic() {
			return nil, errors.New("private key JWT: the JWK must be a private key")
		}
		signer, ok := jwk.Key.(crypto.Signer)
		if !ok {
			return nil, errors.New("private key JWT: unsupported JWK key")
		}
		key = signer
		if keyID == "" {
			keyID = jwk.KeyID
		}
		if jwk.Algorithm != "" {
			if alg != "" && alg != jwk.Algorithm {
				return nil, errors.New("private key JWT: the algorithm differs from the JWK's")
			}
			alg = jwk.Algorithm
		}
	default:
		return nil, errors.New("private key JWT: set exactly one of PrivateKeyPEM and PrivateKeyJWK")
	}
	if alg == "" {
		alg = "RS256"
	}
	if !slices.Contains(Algorithms, alg) {
		return nil, errors.New("private key JWT: unsupported algorithm")
	}
	if rsaKey, ok := key.(*rsa.PrivateKey); ok && rsaKey.N.BitLen() < 2048 {
		return nil, errors.New("private key JWT: RSA keys need at least 2048 bits")
	}
	validFor := o.ValidFor
	if validFor == 0 {
		validFor = 2 * time.Minute
	}
	if validFor < time.Second || validFor > 5*time.Minute || validFor%time.Second != 0 {
		return nil, errors.New("private key JWT: ValidFor must be whole seconds from 1s to 5m")
	}
	options := (&jose.SignerOptions{}).WithType("JWT")
	if keyID != "" {
		options = options.WithHeader("kid", keyID)
	}
	if len(o.CertificatePEM) > 0 {
		source := bytes.TrimSpace(o.CertificatePEM)
		block, rest := pem.Decode(source)
		if !bytes.HasPrefix(source, []byte("-----BEGIN CERTIFICATE-----")) || block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("private key JWT: the certificate must be one CERTIFICATE block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		public, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
		if err != nil || !ok || !public.Equal(cert.PublicKey) {
			return nil, errors.New("private key JWT: the certificate does not hold the key's public key")
		}
		sha256Print, sha1Print := sha256.Sum256(cert.Raw), sha1.Sum(cert.Raw)
		options = options.WithHeader("x5t#S256", base64.RawURLEncoding.EncodeToString(sha256Print[:])).WithHeader("x5t", base64.RawURLEncoding.EncodeToString(sha1Print[:]))
	}
	sign := func(claims map[string]any) (string, error) {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(alg), Key: key}, options)
		if err != nil {
			return "", errors.New("private key JWT: the key does not fit the algorithm")
		}
		payload, err := json.Marshal(claims)
		if err != nil {
			return "", err
		}
		signed, err := signer.Sign(payload)
		if err != nil {
			return "", errors.New("private key JWT: signing failed")
		}
		return signed.CompactSerialize()
	}
	// One signature now proves the key and algorithm fit together.
	if _, err := sign(map[string]any{"check": true}); err != nil {
		return nil, err
	}
	return func(clientID, audience string) (string, error) {
		now := time.Now()
		return sign(map[string]any{"iss": clientID, "sub": clientID, "aud": audience, "iat": now.Unix(), "exp": now.Add(validFor).Unix(), "jti": rand.Text()})
	}, nil
}
