package sso

import (
	"context"
	"slices"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/providers"
)

// PrivateKeyRequest names the provider whose token request needs a
// private_key_jwt client assertion. KeyID and Issuer come from the stored
// configuration, which the registrant chooses. Bind keys to RecordID, which
// changes when a provider ID is deleted and registered again, or to
// OrganizationID.
type PrivateKeyRequest struct {
	// Another runtime passes only the provider ID, key ID and issuer; the
	// record and tenant let a host bind keys to one registration.
	RecordID, ProviderID, OrganizationID, UserID string
	KeyID, Issuer                                string
}

// PrivateKey is the signing key ResolvePrivateKey returns. Set exactly one
// of PEM, one PKCS#8 PRIVATE KEY block, and JWK, a private JSON Web Key.
// KeyID and Algorithm apply when the provider's privateKeyId and
// privateKeyAlgorithm are unset.
type PrivateKey struct {
	PEM, JWK         []byte
	KeyID, Algorithm string
}

const privateKeyJWT = "private_key_jwt"

// signingAlgorithms are the ID token and client assertion algorithms.
var signingAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

// checkClientAuth applies the registration rules for the token endpoint
// authentication method after discovery.
func (o Options) checkClientAuth(cfg *Config) error {
	switch cfg.TokenEndpointAuthentication {
	case privateKeyJWT:
		if o.ResolvePrivateKey == nil {
			return apiError(400, "private_key_jwt authentication requires the ResolvePrivateKey option")
		}
		// Refuse unsupported algorithms at registration; another runtime
		// silently falls back to RS256 at sign-in.
		if cfg.PrivateKeyAlgorithm != "" && !slices.Contains(signingAlgorithms, cfg.PrivateKeyAlgorithm) {
			return apiError(400, "Unsupported private key algorithm")
		}
	case "", "client_secret_basic", "client_secret_post":
		if cfg.ClientSecret == "" {
			return apiError(400, "clientSecret is required when using client_secret_basic or client_secret_post authentication")
		}
	default:
		return apiError(400, "Unsupported OpenID Connect client authentication method")
	}
	return nil
}

// clientAssertion resolves the provider's key and signs an RFC 7523 client
// assertion for one code exchange. The resolver runs before the token
// request, outside any store transaction.
func (o Options) clientAssertion(ctx context.Context, p BrowserProvider) (string, bool) {
	cfg := p.OIDC
	org := ""
	if p.OrganizationID != nil {
		org = *p.OrganizationID
	}
	key, err := o.ResolvePrivateKey(ctx, PrivateKeyRequest{RecordID: p.ID, ProviderID: p.ProviderID, OrganizationID: org, UserID: p.UserID, KeyID: cfg.PrivateKeyID, Issuer: p.Issuer})
	if err != nil || (len(key.PEM) == 0 && len(key.JWK) == 0) {
		return "", false
	}
	kid, alg := cfg.PrivateKeyID, cfg.PrivateKeyAlgorithm
	if kid == "" {
		kid = key.KeyID
	}
	if alg == "" {
		alg = key.Algorithm
	}
	sign, err := providers.PrivateKeyJWT(providers.PrivateKeyJWTOptions{PrivateKeyPEM: key.PEM, PrivateKeyJWK: key.JWK, KeyID: kid, Algorithm: alg})
	if err != nil {
		return "", false
	}
	assertion, err := sign(ctx, auth.TokenRequest{ClientID: cfg.ClientID, TokenURL: cfg.TokenEndpoint, GrantType: "authorization_code"})
	return assertion, err == nil
}
