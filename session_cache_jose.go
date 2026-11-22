package plainauth

import (
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
			// These HKDF inputs are part of the shared encrypted-cookie wire format.
			derived, err := hkdf.Key(sha256.New, key.material, []byte("better-auth-session"), "BetterAuth.js Generated Encryption Key", 64)
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
}

func (a *Auth) writeJOSESnapshot(payload sessionCachePayload, now time.Time, ttl time.Duration) (string, error) {
	claims := sessionJOSEClaims{IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix()}
	encrypt := a.opts.SessionCookieCache.Strategy == SessionCacheJWE
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

func (a *Auth) readJOSESnapshot(encoded string, now time.Time) []byte {
	var raw []byte
	if a.opts.SessionCookieCache.Strategy == SessionCacheJWE {
		raw = a.decryptSessionSnapshot(encoded)
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
