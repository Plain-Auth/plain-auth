package providers

import (
	"bytes"
	"context"
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

	auth "github.com/Plain-Org/plain-auth"
	"github.com/go-jose/go-jose/v4"
)

// PrivateKeyJWTOptions configures PrivateKeyJWT.
type PrivateKeyJWTOptions struct {
	// PrivateKeyPEM is one PKCS#8 "PRIVATE KEY" block and PrivateKeyJWK a
	// private JSON Web Key; set exactly one.
	PrivateKeyPEM, PrivateKeyJWK []byte
	// KeyID is sent as the kid header; it defaults to the JWK's kid.
	KeyID string
	// Algorithm is RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384,
	// ES512 or EdDSA. It defaults to the JWK's alg, then RS256; one that
	// differs from the JWK's alg is refused.
	Algorithm string
	// CertificatePEM is the key's X.509 certificate as one CERTIFICATE
	// block. When set, each assertion names it by its x5t#S256 and x5t
	// thumbprints, as Microsoft Entra ID requires for certificate
	// credentials.
	CertificatePEM []byte
	// ValidFor is each assertion's lifetime in whole seconds, from one
	// second to five minutes; it defaults to two minutes.
	ValidFor time.Duration
}

var assertionAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

// PrivateKeyJWT returns a ClientAssertionFunc that signs an RFC 7523 client
// assertion for each token request: iss and sub are the client ID, aud is
// the token endpoint, and each assertion has a fresh jti. Use it with
// plainauth.TokenAuthPrivateKeyJWT. The key is checked against the
// algorithm when it is built, and errors never include key material.
func PrivateKeyJWT(o PrivateKeyJWTOptions) (auth.ClientAssertionFunc, error) {
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
	if !slices.Contains(assertionAlgorithms, alg) {
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
	return func(_ context.Context, r auth.TokenRequest) (string, error) {
		now := time.Now()
		return sign(map[string]any{"iss": r.ClientID, "sub": r.ClientID, "aud": r.TokenURL, "iat": now.Unix(), "exp": now.Add(validFor).Unix(), "jti": rand.Text()})
	}, nil
}
