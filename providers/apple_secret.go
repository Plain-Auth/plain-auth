package providers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AppleClientSecretOptions identifies the app and the signing key issued by Apple.
type AppleClientSecretOptions struct {
	ClientID      string // Services ID for a web app or bundle ID for a native app.
	TeamID        string
	KeyID         string
	PrivateKeyPEM []byte        // Contents of the downloaded PKCS#8 .p8 file.
	ValidFor      time.Duration // Defaults to 180 days.
}

// GenerateAppleClientSecret signs the JWT used for Apple token requests.
// Pass the result to Apple and generate a replacement before it expires.
func GenerateAppleClientSecret(opts AppleClientSecretOptions) (string, error) {
	for _, id := range []string{opts.ClientID, opts.TeamID, opts.KeyID} {
		if id == "" || strings.TrimSpace(id) != id {
			return "", errors.New("apple: client ID, team ID and key ID are required without surrounding whitespace")
		}
	}
	lifetime := opts.ValidFor
	if lifetime == 0 {
		lifetime = 180 * 24 * time.Hour
	}
	const upperLimit = 15_777_000 * time.Second
	if lifetime < time.Second || lifetime > upperLimit || lifetime%time.Second != 0 {
		return "", errors.New("apple: client-secret validity must be 1 to 15777000 whole seconds")
	}
	source := bytes.TrimSpace(opts.PrivateKeyPEM)
	block, rest := pem.Decode(source)
	if !bytes.HasPrefix(source, []byte("-----BEGIN PRIVATE KEY-----")) || block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) > 0 {
		return "", errors.New("apple: expected one PKCS#8 PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", errors.New("apple: invalid PKCS#8 private key")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return "", errors.New("apple: the client-secret key must be ECDSA P-256")
	}
	now := time.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": opts.TeamID, "sub": opts.ClientID, "aud": "https://appleid.apple.com",
		"iat": now, "exp": now + int64(lifetime/time.Second),
	})
	token.Header["kid"] = opts.KeyID
	return token.SignedString(key)
}
