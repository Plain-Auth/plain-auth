package providers

import (
	"context"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/clientassertion"
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

// PrivateKeyJWT returns a ClientAssertionFunc that signs an RFC 7523 client
// assertion for each token request: iss and sub are the client ID, aud is
// the token endpoint, and each assertion has a fresh jti. Use it with
// plainauth.TokenAuthPrivateKeyJWT. The key is checked against the
// algorithm when it is built, and errors never include key material.
func PrivateKeyJWT(o PrivateKeyJWTOptions) (auth.ClientAssertionFunc, error) {
	sign, err := clientassertion.New(clientassertion.Options{PrivateKeyPEM: o.PrivateKeyPEM, PrivateKeyJWK: o.PrivateKeyJWK, KeyID: o.KeyID, Algorithm: o.Algorithm, CertificatePEM: o.CertificatePEM, ValidFor: o.ValidFor})
	if err != nil {
		return nil, err
	}
	return func(_ context.Context, r auth.TokenRequest) (string, error) { return sign(r.ClientID, r.TokenURL) }, nil
}
