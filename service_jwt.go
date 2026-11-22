package plainauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

type JWTOptions struct {
	Algorithm                    string
	AdditionalAlgorithms         []string
	RSAModulusBits               int
	Issuer, Audience, JWKSPath   string
	Expiration, RotationInterval time.Duration
	GracePeriod                  *time.Duration
	DisableHeader                bool
	DefinePayload                func(context.Context, SessionResult) (map[string]any, error)
}

type PublicJWTKey struct {
	ID, Algorithm, Curve, PublicKey string
	CreatedAt                       time.Time
	ExpiresAt                       *time.Time
}
type StoredJWTKey struct {
	PublicJWTKey
	EncryptedPrivateKey string
}

type JWTStore interface {
	ActiveJWTKey(ctx context.Context, algorithm string, now time.Time, generate func() (StoredJWTKey, error)) (StoredJWTKey, error)
	PublicJWTKeys(ctx context.Context, cutoff time.Time) ([]PublicJWTKey, error)
}

func NewJWT(opts JWTOptions) (Plugin, error) {
	if opts.Algorithm == "" {
		opts.Algorithm = string(jose.EdDSA)
	}
	opts.AdditionalAlgorithms = slices.Clone(opts.AdditionalAlgorithms)
	for _, alg := range append([]string{opts.Algorithm}, opts.AdditionalAlgorithms...) {
		switch jose.SignatureAlgorithm(alg) {
		case jose.EdDSA, jose.ES256, jose.ES512, jose.RS256, jose.PS256:
		default:
			return Plugin{}, errors.New("jwt: unsupported signing algorithm " + alg)
		}
	}
	if opts.RSAModulusBits == 0 {
		opts.RSAModulusBits = 2048
	}
	if opts.RSAModulusBits < 2048 || opts.RSAModulusBits%8 != 0 {
		return Plugin{}, errors.New("jwt: RSA modulus length must be at least 2048 bits and a multiple of eight")
	}
	if opts.Expiration == 0 {
		opts.Expiration = 15 * time.Minute
	}
	if opts.Expiration < time.Second || opts.RotationInterval < 0 {
		return Plugin{}, errors.New("jwt: invalid token lifetime or rotation interval")
	}
	grace := 30 * 24 * time.Hour
	if opts.GracePeriod != nil {
		grace = *opts.GracePeriod
	}
	if grace < 0 {
		return Plugin{}, errors.New("jwt: negative public key grace period")
	}
	opts.GracePeriod = &grace
	if opts.JWKSPath == "" {
		opts.JWKSPath = "/jwks"
	}
	if !strings.HasPrefix(opts.JWKSPath, "/") || strings.Contains(opts.JWKSPath, "..") {
		return Plugin{}, errors.New("jwt: invalid JWKS path")
	}
	return Plugin{
		ID: "jwt", serviceJWT: &opts,
		ValidateStore: func(store Store) error {
			if _, ok := store.(JWTStore); !ok {
				return errors.New("jwt: a JWTStore is required")
			}
			if check, ok := store.(interface{ CheckJWKS() error }); ok {
				return check.CheckJWKS()
			}
			return nil
		},
		Endpoints: []Endpoint{
			{Method: http.MethodGet, Path: opts.JWKSPath, Handler: func(c EndpointContext) (any, error) { return c.Auth.PublicJWKS(c.Request.Context()) }},
			{Method: http.MethodGet, Path: "/token", Handler: func(c EndpointContext) (any, error) {
				token, err := c.Auth.IssueJWT(c.Request.Context(), c.Request.Header)
				if err != nil {
					return nil, err
				}
				return map[string]string{"token": token}, nil
			}},
		},
	}, nil
}

// PublicJWKSURL returns the configured key-set endpoint when it is served.
func (a *Auth) PublicJWKSURL() string {
	if a.serviceJWT == nil {
		return ""
	}
	if _, disabled := a.disabledPaths[a.serviceJWT.JWKSPath]; disabled {
		return ""
	}
	return a.PublicURL() + a.serviceJWT.JWKSPath
}

// PublicJWKS returns public verification material. Private key data is excluded
// from the store query used to publish the set.
func (a *Auth) PublicJWKS(ctx context.Context) (jose.JSONWebKeySet, error) {
	opts := a.serviceJWT
	if opts == nil {
		return jose.JSONWebKeySet{}, &APIError{404, "NOT_FOUND", "JWT plugin is not enabled"}
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	store := a.opts.Store.(JWTStore)
	cutoff := now.Add(-*opts.GracePeriod)
	rows, err := store.PublicJWTKeys(ctx, cutoff)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	if len(rows) == 0 {
		if _, err = a.activeSigningKey(ctx, now, opts.Algorithm); err != nil {
			return jose.JSONWebKeySet{}, err
		}
		rows, err = store.PublicJWTKeys(ctx, cutoff)
		if err != nil {
			return jose.JSONWebKeySet{}, err
		}
	}
	set := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(rows))}
	for _, row := range rows {
		var key jose.JSONWebKey
		if err := json.Unmarshal([]byte(row.PublicKey), &key); err != nil || !key.IsPublic() || !key.Valid() {
			return jose.JSONWebKeySet{}, errors.New("jwt: invalid public key")
		}
		key.KeyID = row.ID
		key.Algorithm = row.Algorithm
		if key.Algorithm == "" {
			return jose.JSONWebKeySet{}, errors.New("jwt: stored public key has no algorithm")
		}
		set.Keys = append(set.Keys, key)
	}
	return set, nil
}

func (a *Auth) activeSigningKey(ctx context.Context, now time.Time, algorithm string) (StoredJWTKey, error) {
	opts := a.serviceJWT
	return a.opts.Store.(JWTStore).ActiveJWTKey(ctx, algorithm, now, func() (StoredJWTKey, error) {
		var private crypto.Signer
		var err error
		var curve string
		switch jose.SignatureAlgorithm(algorithm) {
		case jose.EdDSA:
			curve = "Ed25519"
			_, private, err = ed25519.GenerateKey(rand.Reader)
		case jose.ES256:
			curve = "P-256"
			private, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case jose.ES512:
			curve = "P-521"
			private, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		case jose.RS256, jose.PS256:
			private, err = rsa.GenerateKey(rand.Reader, opts.RSAModulusBits)
		default:
			return StoredJWTKey{}, errors.New("jwt: unsupported signing algorithm")
		}
		if err != nil {
			return StoredJWTKey{}, err
		}
		public, err := json.Marshal(jose.JSONWebKey{Key: private.Public()})
		if err != nil {
			return StoredJWTKey{}, err
		}
		secret, err := json.Marshal(jose.JSONWebKey{Key: private})
		if err != nil {
			return StoredJWTKey{}, err
		}
		encrypted, err := a.sealRecord("jwk", secret)
		if err != nil {
			return StoredJWTKey{}, err
		}
		envelope, err := json.Marshal(encrypted)
		if err != nil {
			return StoredJWTKey{}, err
		}
		row := StoredJWTKey{PublicJWTKey: PublicJWTKey{ID: randomID(), Algorithm: algorithm, Curve: curve, PublicKey: string(public), CreatedAt: now}, EncryptedPrivateKey: string(envelope)}
		if opts.RotationInterval > 0 {
			ends := now.Add(opts.RotationInterval)
			row.ExpiresAt = &ends
		}
		return row, nil
	})
}

// IssueJWT creates an audience-bound assertion from an active authenticated session.
func (a *Auth) IssueJWT(ctx context.Context, h http.Header) (string, error) {
	if a.serviceJWT == nil {
		return "", &APIError{404, "NOT_FOUND", "JWT plugin is not enabled"}
	}
	s, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return "", err
	}
	return a.signSessionJWT(ctx, *s)
}
func (a *Auth) signSessionJWT(ctx context.Context, s SessionResult) (string, error) {
	opts := a.serviceJWT
	claims := map[string]any{}
	if opts.DefinePayload != nil {
		payload, err := opts.DefinePayload(ctx, s)
		if err != nil {
			return "", err
		}
		for k, v := range payload {
			claims[k] = v
		}
	} else {
		raw, err := json.Marshal(s.User)
		if err != nil {
			return "", err
		}
		if err = json.Unmarshal(raw, &claims); err != nil {
			return "", err
		}
	}
	return a.SignJWT(ctx, s.User.ID, JWTSignOptions{Claims: claims})
}

func (a *Auth) signStoredJWTKey(row StoredJWTKey, claims map[string]any, settings JWTSignOptions) (string, error) {
	var envelope string
	if err := json.Unmarshal([]byte(row.EncryptedPrivateKey), &envelope); err != nil {
		return "", errors.New("jwt: invalid encrypted private key")
	}
	plain, err := a.openRecord("jwk", envelope)
	if err != nil {
		return "", errors.New("jwt: cannot decrypt the signing key")
	}
	var secret, pub jose.JSONWebKey
	if json.Unmarshal(plain, &secret) != nil || !secret.Valid() || secret.IsPublic() || json.Unmarshal([]byte(row.PublicKey), &pub) != nil || !pub.IsPublic() {
		return "", errors.New("jwt: invalid signing key")
	}
	check, err := secret.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	expected, err := pub.Thumbprint(crypto.SHA256)
	if err != nil || !bytes.Equal(check, expected) {
		return "", errors.New("jwt: inconsistent signing key pair")
	}
	headers := (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), row.ID)
	if settings.Type != "" {
		headers.WithType(jose.ContentType(settings.Type))
	}
	if settings.ContentType != "" {
		headers.WithContentType(jose.ContentType(settings.ContentType))
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(row.Algorithm), Key: secret.Key}, headers)
	if err != nil {
		return "", err
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return sig.CompactSerialize()
}
