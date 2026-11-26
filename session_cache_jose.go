package plainauth

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

type sessionCacheKey struct {
	material []byte
	id       string
}

func (a *Auth) prepareSessionCacheKeys() error {
	cache := a.opts.SessionCookieCache
	if cache == nil || cache.Strategy == SessionCacheCompact {
		return nil
	}
	secrets := a.opts.Secrets
	if len(secrets) == 0 {
		secrets = []VersionedSecret{{Value: a.opts.Secret}}
	}
	for _, secret := range secrets {
		key := sessionCacheKey{material: []byte(secret.Value)}
		if cache.Strategy == SessionCacheJWE {
			// These HKDF inputs define the encrypted cache cookie format. Changing
			// them makes every outstanding encrypted snapshot unreadable.
			derived, err := hkdf.Key(sha256.New, key.material, []byte("plainauth-session-cache"), "Plain Auth session cache encryption key", 64)
			if err != nil {
				return err
			}
			key.material = derived
			// RFC 7638 requires exactly the octet key's k and kty members in
			// lexical order. The k value uses the unpadded base64url alphabet.
			canonical := `{"k":"` + base64.RawURLEncoding.EncodeToString(derived) + `","kty":"oct"}`
			digest := sha256.Sum256([]byte(canonical))
			key.id = base64.RawURLEncoding.EncodeToString(digest[:])
		}
		a.sessionCacheKeys = append(a.sessionCacheKeys, key)
	}
	return nil
}

type sessionJOSEClaims struct {
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	JWTID     string `json:"jti,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	Audience  string `json:"aud,omitempty"`
	Subject   string `json:"sub,omitempty"`
	SessionID string `json:"sid,omitempty"`
}

// Key-set snapshots carry their own type and audience, so a service token
// signed with the same key never passes as a session snapshot. The names
// are this library's own.
const (
	sessionSnapshotType     = "plainauth.session-cache+jwt"
	sessionSnapshotAudience = "plainauth:session-cache"
)

// keySetSnapshots reports whether jwt-strategy snapshots are signed with the
// JWT plugin's keys.
func (a *Auth) keySetSnapshots() bool {
	return a.serviceJWT != nil && a.serviceJWT.SessionCookieCache
}

// checkJWTSessionCache refuses a key-set snapshot setting that could not
// work. Without DisableHeader the option would do nothing, because session
// reads that issue the token header always read the store.
func (a *Auth) checkJWTSessionCache() error {
	if !a.keySetSnapshots() {
		return nil
	}
	opts := a.serviceJWT
	cache := a.opts.SessionCookieCache
	switch {
	case cache == nil || cache.Strategy != SessionCacheJWT:
		return errors.New("jwt: SessionCookieCache requires Options.SessionCookieCache with the jwt strategy")
	case opts.Sign != nil:
		return errors.New("jwt: SessionCookieCache requires locally managed keys and does not support Sign")
	case !opts.DisableHeader:
		return errors.New("jwt: SessionCookieCache requires DisableHeader, because session reads that issue a token header always read the store")
	}
	if cache.MaxAge > *opts.GracePeriod {
		a.Logger().Warn("Session cookie cache lifetime exceeds the JWT key grace period; rotated keys may stop verifying cached sessions before the cookie expires", "maxAge", cache.MaxAge, "gracePeriod", *opts.GracePeriod)
	}
	return nil
}

// verifyKeySetSnapshot verifies a snapshot signed with the JWT plugin's key.
// The algorithm comes from the published key, never the token, and a key
// past its grace period no longer verifies snapshots, where another runtime
// accepts any stored key with that ID.
func (a *Auth) verifyKeySetSnapshot(ctx context.Context, encoded string, now time.Time) []byte {
	value, err := jose.ParseSignedCompact(encoded, a.serviceJWT.verificationAlgorithms())
	if err != nil || len(value.Signatures) != 1 {
		return nil
	}
	header := value.Signatures[0].Protected
	if header.KeyID == "" || header.ExtraHeaders[jose.HeaderType] != sessionSnapshotType {
		return nil
	}
	key, err := a.jwtVerificationKey(ctx, now.UTC(), header)
	if err != nil {
		return nil
	}
	raw, err := value.Verify(key)
	if err != nil {
		return nil
	}
	var claims struct {
		Issuer    string `json:"iss"`
		Audience  string `json:"aud"`
		Subject   string `json:"sub"`
		SessionID string `json:"sid"`
		User      struct {
			ID string `json:"id"`
		} `json:"user"`
		Session struct {
			Token string `json:"token"`
		} `json:"session"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.Issuer != a.jwtExpectations(JWTVerifyOptions{}).Issuer || claims.Audience != sessionSnapshotAudience ||
		claims.Subject == "" || claims.Subject != claims.User.ID || claims.SessionID == "" || claims.SessionID != claims.Session.Token {
		return nil
	}
	return raw
}

func (a *Auth) writeJOSESnapshot(ctx context.Context, payload sessionCachePayload, now time.Time, ttl time.Duration) (string, error) {
	claims := sessionJOSEClaims{IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix()}
	encrypt := a.opts.SessionCookieCache.Strategy == SessionCacheJWE
	keySet := !encrypt && a.keySetSnapshots()
	if keySet {
		claims.Issuer, claims.Audience = a.jwtExpectations(JWTVerifyOptions{}).Issuer, sessionSnapshotAudience
		claims.Subject, claims.SessionID = payload.User.ID, payload.Session.Token
	}
	if encrypt {
		id, err := uuid.NewRandom()
		if err != nil {
			return "", err
		}
		claims.JWTID = id.String()
	}
	raw, err := payload.marshal(&claims)
	if err != nil {
		return "", err
	}
	if len(raw) > maxSessionChunks*maxSessionChunkSize {
		return "", errors.New("auth: browser session snapshot exceeds cookie capacity")
	}
	if keySet {
		row, err := a.activeSigningKey(ctx, now.UTC().Truncate(time.Millisecond), a.serviceJWT.Algorithm)
		if err != nil {
			return "", err
		}
		return a.signStoredJWTKey(row, raw, sessionSnapshotType, "")
	}
	key := a.sessionCacheKeys[0]
	if encrypt {
		cipher, err := jose.NewEncrypter(jose.A256CBC_HS512, jose.Recipient{Algorithm: jose.DIRECT, Key: key.material, KeyID: key.id}, nil)
		if err != nil {
			return "", err
		}
		value, err := cipher.Encrypt(raw)
		if err != nil {
			return "", err
		}
		return value.CompactSerialize()
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key.material}, nil)
	if err != nil {
		return "", err
	}
	value, err := signer.Sign(raw)
	if err != nil {
		return "", err
	}
	return value.CompactSerialize()
}

func (a *Auth) readJOSESnapshot(ctx context.Context, encoded string, now time.Time) []byte {
	var raw []byte
	if a.opts.SessionCookieCache.Strategy == SessionCacheJWE {
		raw = a.decryptSessionSnapshot(encoded)
	} else if a.keySetSnapshots() {
		raw = a.verifyKeySetSnapshot(ctx, encoded, now)
	} else {
		value, err := jose.ParseSignedCompact(encoded, []jose.SignatureAlgorithm{jose.HS256})
		if err != nil {
			return nil
		}
		for _, key := range a.sessionCacheKeys {
			if verified, err := value.Verify(key.material); err == nil {
				raw = verified
				break
			}
		}
	}
	var claims struct {
		ExpiresAt int64 `json:"exp"`
		NotBefore int64 `json:"nbf"`
		IssuedAt  int64 `json:"iat"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.ExpiresAt <= now.Unix() || claims.NotBefore > now.Unix() {
		return nil
	}
	return raw
}

func (a *Auth) decryptSessionSnapshot(encoded string) []byte {
	// A missing key ID is legal on older envelopes. An explicit ID must
	// match a retained derived key. Compressed payloads are never issued.
	segment, _, ok := strings.Cut(encoded, ".")
	if !ok {
		return nil
	}
	header, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return nil
	}
	var fields struct {
		KeyID       json.RawMessage `json:"kid"`
		Compression json.RawMessage `json:"zip"`
	}
	if json.Unmarshal(header, &fields) != nil || fields.Compression != nil {
		return nil
	}
	var id string
	if fields.KeyID != nil && (json.Unmarshal(fields.KeyID, &id) != nil || id == "") {
		return nil
	}
	message, err := jose.ParseEncryptedCompact(encoded, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256CBC_HS512})
	if err != nil {
		return nil
	}
	for _, key := range a.sessionCacheKeys {
		if id != "" && key.id != id {
			continue
		}
		raw, err := message.Decrypt(key.material)
		if err == nil {
			return raw
		}
	}
	return nil
}
