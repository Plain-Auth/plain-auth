package goapi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/schema"
	jose "github.com/go-jose/go-jose/v4"
	libjwt "github.com/golang-jwt/jwt/v5"
)

// signerKeys lists a host signer's public key and holds no private keys.
type signerKeys struct {
	public authn.PublicJWTKey
	minted int
}

func (k *signerKeys) ActiveJWTKey(context.Context, string, time.Time, func() (authn.StoredJWTKey, error)) (authn.StoredJWTKey, error) {
	k.minted++
	return authn.StoredJWTKey{}, errors.New("signing keys are held by the signer")
}

func (k *signerKeys) PublicJWTKeys(context.Context, time.Time) ([]authn.PublicJWTKey, error) {
	return []authn.PublicJWTKey{k.public}, nil
}

// signerServer builds an auth instance whose JWT plugin signs with sign, and
// returns a function that signs up one account and fetches its token.
func signerServer(t *testing.T, store authn.Store, opts authn.JWTOptions) (*authn.Auth, func() (string, authn.User, int)) {
	t.Helper()
	p, err := authn.NewJWT(opts)
	if err != nil {
		t.Fatal(err)
	}
	off := false
	a, err := authn.New(authn.Options{Store: store, BaseURL: "https://signer.example", Secret: strings.Repeat("g", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []authn.Plugin{p}})
	if err != nil {
		t.Fatal(err)
	}
	return a, func() (string, authn.User, int) {
		t.Helper()
		account, err := a.SignUpEmail(t.Context(), authn.SignUpInput{Name: "Signer", Email: strings.ToLower(rand.Text()) + "@signer.example", Password: "signer-password"}, authn.RequestMeta{})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "https://signer.example/api/auth/token", nil)
		r.AddCookie(a.SessionCookie(account.Token, true))
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		var issued struct{ Token string }
		_ = json.Unmarshal(w.Body.Bytes(), &issued)
		return issued.Token, account.User, w.Code
	}
}

// A host signer receives the finished claims and the requested header and
// key, and its result must be a compact JWS with those values.
func TestJWTCustomSigner(t *testing.T) {
	const base = "https://signer.example"
	t.Run("local key", func(t *testing.T) {
		ctx := t.Context()
		store, err := sqlstore.Open(ctx, "sqlite", ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		hostPublic, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		published, _ := json.Marshal(jose.JSONWebKey{Key: hostPublic})
		keys := &signerKeys{public: authn.PublicJWTKey{ID: "local-1", Algorithm: "EdDSA", Curve: "Ed25519", PublicKey: string(published), CreatedAt: time.Now()}}
		mode := "ok"
		var requests []authn.JWTSigningRequest
		sign := func(_ context.Context, req authn.JWTSigningRequest) (string, error) {
			requests = append(requests, req)
			claims := req.Claims
			switch mode {
			case "garbage":
				return "not-a-token", nil
			case "fail":
				return "", errors.New("key service unavailable")
			case "hs256":
				return libjwt.NewWithClaims(libjwt.SigningMethodHS256, libjwt.MapClaims(claims)).SignedString([]byte(rand.Text()))
			case "alter-claims":
				altered := map[string]any{}
				for k, v := range claims {
					altered[k] = v
				}
				altered["sub"] = "someone-else"
				claims = altered
			case "mutate-claims":
				req.Claims["sub"] = "someone-else"
			}
			kid := "local-1"
			if mode == "wrong-kid" {
				kid = "local-2"
			}
			options := (&jose.SignerOptions{}).WithHeader("kid", kid).WithType("JWT")
			if req.Type != "" && mode != "drop-type" {
				options.WithType(jose.ContentType(req.Type))
			}
			if req.ContentType != "" && mode != "drop-cty" {
				options.WithContentType(jose.ContentType(req.ContentType))
			}
			key := jose.SigningKey{Algorithm: jose.EdDSA, Key: hostPrivate}
			if mode == "wrong-alg" {
				key = jose.SigningKey{Algorithm: jose.ES256, Key: other}
			}
			signer, err := jose.NewSigner(key, options)
			if err != nil {
				return "", err
			}
			body, err := json.Marshal(claims)
			if err != nil {
				return "", err
			}
			signed, err := signer.Sign(body)
			if err != nil {
				return "", err
			}
			return signed.CompactSerialize()
		}
		a, session := signerServer(t, store, authn.JWTOptions{Algorithm: "EdDSA", AdditionalAlgorithms: []string{"ES256"}, RemoteJWKSURL: "https://keys.example.test/jwks.json", KeyStore: keys, Sign: sign})
		token, user, status := session()
		if status != 200 || len(requests) != 1 {
			t.Fatal("session token issuance failed", status)
		}
		got := requests[0]
		if got.Claims["sub"] != user.ID || got.Claims["iss"] != base || got.Claims["aud"] != base || got.Claims["exp"].(int64)-got.Claims["iat"].(int64) != 900 || got.Claims["email"] != user.Email || got.Type != "" || got.Algorithm != "" || got.KeyID != "" {
			t.Fatal("signer did not receive the finished session claims", got)
		}
		verify := func(raw, audience string) (*libjwt.Token, error) {
			return libjwt.Parse(raw, func(tok *libjwt.Token) (any, error) {
				if tok.Header["kid"] != "local-1" {
					return nil, errors.New("unknown key")
				}
				return hostPublic, nil
			}, libjwt.WithValidMethods([]string{"EdDSA"}), libjwt.WithIssuer(base), libjwt.WithAudience(audience))
		}
		if parsed, err := verify(token, base); err != nil || parsed.Header["typ"] != "JWT" {
			t.Fatal("host-signed session token did not verify", err)
		}
		service := authn.JWTSignOptions{Type: "at+jwt", ContentType: "application/json", Algorithm: "EdDSA", KeyID: "local-1", Audience: []string{"https://api.example.test"}, Claims: map[string]any{"scope": "reports"}}
		raw, err := a.SignJWT(ctx, "worker", service)
		if err != nil {
			t.Fatal(err)
		}
		last := requests[len(requests)-1]
		if last.Type != "at+jwt" || last.ContentType != "application/json" || last.Algorithm != "EdDSA" || last.KeyID != "local-1" || last.Claims["sub"] != "worker" || last.Claims["aud"] != "https://api.example.test" || last.Claims["scope"] != "reports" {
			t.Fatal("signer did not receive the requested header and pinned key", last)
		}
		if parsed, err := verify(raw, "https://api.example.test"); err != nil || parsed.Header["typ"] != "at+jwt" || parsed.Header["cty"] != "application/json" {
			t.Fatal("localized signer dropped the requested type", err)
		}
		if _, err := a.VerifyJWT(ctx, raw, authn.JWTVerifyOptions{Audience: "https://api.example.test", Subject: "worker"}); err != nil {
			t.Fatal("host verification ignored the signer's public keys", err)
		}
		if set, err := a.PublicJWKS(ctx); err != nil || keys.minted != 0 || len(set.Keys) != 1 || set.Keys[0].KeyID != "local-1" {
			t.Fatal("custom signer fell back to stored keys", err, keys.minted)
		}
		mode = "garbage"
		if _, err := a.SignJWT(ctx, "worker", authn.JWTSignOptions{}); err == nil {
			t.Fatal("accepted a result that is not a compact JWS")
		}
		mode = "hs256"
		if _, err := a.SignJWT(ctx, "worker", authn.JWTSignOptions{}); err == nil {
			t.Fatal("accepted a token signed with an unconfigured algorithm")
		}
		mode = "drop-type"
		if _, err := a.SignJWT(ctx, "worker", authn.JWTSignOptions{Type: "at+jwt"}); err == nil {
			t.Fatal("accepted a token without the requested type")
		}
		mode = "alter-claims"
		if _, err := a.SignJWT(ctx, "worker", authn.JWTSignOptions{}); err == nil {
			t.Fatal("accepted a token whose claims differ from the request")
		}
		mode = "mutate-claims"
		if _, err := a.SignJWT(ctx, "worker", authn.JWTSignOptions{}); err == nil {
			t.Fatal("accepted a token whose signer edited the request's claims")
		}
		mode = "wrong-alg"
		if _, err := a.SignJWT(ctx, "worker", authn.JWTSignOptions{}); err == nil {
			t.Fatal("accepted a token signed with another configured algorithm than the primary one")
		}
		mode = "wrong-kid"
		if _, err := a.SignJWT(ctx, "worker", authn.JWTSignOptions{KeyID: "local-1"}); err == nil {
			t.Fatal("accepted a token under another key than the pinned one")
		}
		mode = "drop-cty"
		if _, err := a.SignJWT(ctx, "worker", authn.JWTSignOptions{ContentType: "application/json"}); err == nil {
			t.Fatal("accepted a token without the requested content type")
		}
		mode = "fail"
		if _, err := a.SignJWT(ctx, "worker", authn.JWTSignOptions{}); err == nil || !strings.Contains(err.Error(), "key service unavailable") {
			t.Fatal("signer failure did not fail issuance", err)
		}
		if _, _, status := session(); status != 500 {
			t.Fatal("signer failure did not fail issuance", status)
		}
	})
	t.Run("remote digest", func(t *testing.T) {
		ctx := t.Context()
		store, err := sqlstore.OpenWithOptions(ctx, "sqlite", ":memory:", []string{"jwt"}, schema.Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		kms, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		digests := 0
		remoteSign := func(digest []byte) ([]byte, error) {
			digests++
			r, s, err := ecdsa.Sign(rand.Reader, kms, digest)
			if err != nil {
				return nil, err
			}
			return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...), nil
		}
		b64 := base64.RawURLEncoding.EncodeToString
		sign := func(_ context.Context, req authn.JWTSigningRequest) (string, error) {
			header := map[string]string{"alg": "ES256", "kid": "kms-1", "typ": "JWT"}
			if req.Type != "" {
				header["typ"] = req.Type
			}
			if req.ContentType != "" {
				header["cty"] = req.ContentType
			}
			h, _ := json.Marshal(header)
			body, err := json.Marshal(req.Claims)
			if err != nil {
				return "", err
			}
			input := b64(h) + "." + b64(body)
			sum := sha256.Sum256([]byte(input))
			sig, err := remoteSign(sum[:])
			if err != nil {
				return "", err
			}
			return input + "." + b64(sig), nil
		}
		a, session := signerServer(t, store, authn.JWTOptions{Algorithm: "ES256", RemoteJWKSURL: "https://keys.example.test/jwks.json", Sign: sign})
		verify := func(raw string) (*libjwt.Token, error) {
			return libjwt.Parse(raw, func(*libjwt.Token) (any, error) { return &kms.PublicKey, nil }, libjwt.WithValidMethods([]string{"ES256"}), libjwt.WithIssuer(base), libjwt.WithAudience(base), libjwt.WithExpirationRequired())
		}
		token, _, status := session()
		if _, err := verify(token); status != 200 || err != nil || digests != 1 {
			t.Fatal("remotely signed token did not verify", status, err, digests)
		}
		raw, err := a.SignJWT(ctx, "worker", authn.JWTSignOptions{Type: "at+jwt"})
		if parsed, verr := verify(raw); err != nil || verr != nil || parsed.Header["typ"] != "at+jwt" {
			t.Fatal("remote signer dropped the requested type", err, verr)
		}
		if set, err := a.PublicJWKS(ctx); err != nil || len(set.Keys) != 0 {
			t.Fatal("custom signer minted a local key", err)
		}
		if _, err := a.VerifyJWT(ctx, token, authn.JWTVerifyOptions{}); !errors.Is(err, authn.ErrInvalidJWT) {
			t.Fatal("verified a token without the signer's public keys", err)
		}
	})
}
