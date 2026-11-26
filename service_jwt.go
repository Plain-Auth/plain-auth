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
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

type JWTOptions struct {
	Algorithm            string
	AdditionalAlgorithms []string
	// RSAModulusBits sets the size of RS256 and PS256 keys. It defaults to
	// 2048 and must be an even number of at least 2048 bits.
	RSAModulusBits               int
	Issuer, Audience, JWKSPath   string
	Expiration, RotationInterval time.Duration
	GracePeriod                  *time.Duration
	DisableHeader                bool
	DefinePayload                func(context.Context, SessionResult) (map[string]any, error)
	// KeyStore keeps signing keys outside the main Store, for example in
	// memory, in a secret manager or in a per-tenant keyring chosen from the
	// context. It may also implement JWTKeyLookup to support
	// JWTSignOptions.KeyID. When nil, the main Store must implement JWTStore.
	// The store, not the plugin, picks the active key and serializes its
	// generation, so concurrent requests share one new key.
	KeyStore JWTStore
	// DisablePrivateKeyEncryption stores new private keys as plain JWK JSON
	// and reads stored keys that way. Encryption is on by default. Turn it
	// off only when another system must read the keys and protects the
	// table itself. An instance cannot sign with a key stored the other way.
	DisablePrivateKeyEncryption bool
	// RemoteJWKSURL publishes the key set at another address, such as a CDN.
	// The JWKSPath route is not served, and discovery advertises this URL.
	// Algorithm must be set. Keep every active and recently retired public
	// key there, for example by copying Auth.PublicJWKS. Verification here
	// still reads the key store and never fetches the URL.
	RemoteJWKSURL string
}

type PublicJWTKey struct {
	ID, Algorithm, Curve, PublicKey string
	CreatedAt                       time.Time
	ExpiresAt                       *time.Time
}
type StoredJWTKey struct {
	PublicJWTKey
	// EncryptedPrivateKey holds the sealed private JWK, or the plain private
	// JWK JSON when DisablePrivateKeyEncryption is set.
	EncryptedPrivateKey string
}

// JWTStore keeps the plugin's signing keys. Both methods receive the request
// context, or the context a host passes to SignJWT and VerifyJWT, so an
// implementation can choose a tenant's keyring from values a host middleware
// adds.
type JWTStore interface {
	// ActiveJWTKey returns the newest key for algorithm that has not expired
	// at now. With none, it calls generate, saves the new key and returns
	// it. Serialize generation so concurrent callers share one key.
	ActiveJWTKey(ctx context.Context, algorithm string, now time.Time, generate func() (StoredJWTKey, error)) (StoredJWTKey, error)
	// PublicJWTKeys returns the keys with no expiry or an expiry after
	// cutoff, oldest first.
	PublicJWTKeys(ctx context.Context, cutoff time.Time) ([]PublicJWTKey, error)
}

// jwtKeys is the configured key store, or the main Store.
func (a *Auth) jwtKeys() JWTStore {
	if a.serviceJWT.KeyStore != nil {
		return a.serviceJWT.KeyStore
	}
	return a.opts.Store.(JWTStore)
}

func NewJWT(opts JWTOptions) (Plugin, error) {
	if opts.RemoteJWKSURL != "" {
		// Discovery advertises the signing algorithm, which a remote key set
		// cannot reveal.
		if opts.Algorithm == "" {
			return Plugin{}, errors.New("jwt: RemoteJWKSURL requires an explicit Algorithm")
		}
		// Only a usable absolute address is accepted, so discovery never
		// advertises a relative or malformed key URL; another runtime
		// accepts any string.
		u, err := url.Parse(opts.RemoteJWKSURL)
		if err != nil || u.Hostname() == "" || u.User != nil || strings.ContainsAny(opts.RemoteJWKSURL, "#\\ \t\r\n") || !(u.Scheme == "https" || u.Scheme == "http" && loopbackHost(u.Host)) {
			return Plugin{}, errors.New("jwt: RemoteJWKSURL must be an absolute HTTPS URL, or HTTP on a loopback host")
		}
	}
	if opts.Algorithm == "" {
		opts.Algorithm = string(jose.EdDSA)
	}
	opts.AdditionalAlgorithms = slices.Clone(opts.AdditionalAlgorithms)
	// Only signature algorithms are accepted. ECDH-ES and its key-wrapping
	// variants agree encryption keys and cannot sign a JWS on any curve.
	// EdDSA keys always use Ed25519, because Ed448 cannot sign here.
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
	// Go's FIPS 140-only mode refuses odd RSA sizes, so New refuses them at
	// startup instead of at the first key generation.
	if opts.RSAModulusBits < 2048 || opts.RSAModulusBits%2 != 0 {
		return Plugin{}, errors.New("jwt: RSA modulus length must be an even number of at least 2048 bits")
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
			var keys any = opts.KeyStore
			if opts.KeyStore == nil {
				if _, ok := store.(JWTStore); !ok {
					return errors.New("jwt: a JWTStore is required")
				}
				keys = store
			}
			if check, ok := keys.(interface{ CheckJWKS() error }); ok {
				return check.CheckJWKS()
			}
			return nil
		},
		Endpoints: jwtEndpoints(opts),
	}, nil
}

func jwtEndpoints(opts JWTOptions) []Endpoint {
	endpoints := []Endpoint{{Method: http.MethodGet, Path: "/token", Handler: func(c EndpointContext) (any, error) {
		token, err := c.Auth.IssueJWT(c.Request.Context(), c.Request.Header)
		if err != nil {
			return nil, err
		}
		return map[string]string{"token": token}, nil
	}}}
	// A remote key set replaces the local route, which then answers 404.
	if opts.RemoteJWKSURL == "" {
		endpoints = append([]Endpoint{{Method: http.MethodGet, Path: opts.JWKSPath, Handler: func(c EndpointContext) (any, error) { return c.Auth.PublicJWKS(c.Request.Context()) }}}, endpoints...)
	}
	return endpoints
}

// JWTSigningAlgorithm returns the configured primary algorithm, or an empty string
// when the JWT plugin is disabled.
func (a *Auth) JWTSigningAlgorithm() string {
	if a.serviceJWT == nil {
		return ""
	}
	return a.serviceJWT.Algorithm
}

// PublicJWKSURL returns RemoteJWKSURL when set, otherwise the served key-set
// endpoint, or an empty string when that path is disabled.
func (a *Auth) PublicJWKSURL() string {
	if a.serviceJWT == nil {
		return ""
	}
	if a.serviceJWT.RemoteJWKSURL != "" {
		return a.serviceJWT.RemoteJWKSURL
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
	store := a.jwtKeys()
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
	return a.jwtKeys().ActiveJWTKey(ctx, algorithm, now, func() (StoredJWTKey, error) {
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
		stored := string(secret)
		if !opts.DisablePrivateKeyEncryption {
			encrypted, err := a.sealRecord("jwk", secret)
			if err != nil {
				return StoredJWTKey{}, err
			}
			envelope, err := json.Marshal(encrypted)
			if err != nil {
				return StoredJWTKey{}, err
			}
			stored = string(envelope)
		}
		row := StoredJWTKey{PublicJWTKey: PublicJWTKey{ID: randomID(), Algorithm: algorithm, Curve: curve, PublicKey: string(public), CreatedAt: now}, EncryptedPrivateKey: stored}
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
	plain := []byte(row.EncryptedPrivateKey)
	if !a.serviceJWT.DisablePrivateKeyEncryption {
		var envelope string
		if err := json.Unmarshal(plain, &envelope); err != nil {
			return "", errors.New("jwt: invalid encrypted private key")
		}
		var err error
		if plain, err = a.openRecord("jwk", envelope); err != nil {
			return "", errors.New("jwt: cannot decrypt the signing key")
		}
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
