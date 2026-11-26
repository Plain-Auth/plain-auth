package goapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/plugins/jwt"
	jose "github.com/go-jose/go-jose/v4"
	libjwt "github.com/golang-jwt/jwt/v5"
)

type tenantKey struct{}

// tenantKeyring keeps each tenant's signing keys in memory, choosing the
// tenant from the context.
type tenantKeyring struct {
	mu        sync.Mutex
	keys      map[string][]authn.StoredJWTKey
	generated map[string]int
}

func (r *tenantKeyring) tenant(ctx context.Context) (string, error) {
	tenant, _ := ctx.Value(tenantKey{}).(string)
	if tenant == "" {
		return "", errors.New("no tenant in context")
	}
	return tenant, nil
}

func (r *tenantKeyring) ActiveJWTKey(ctx context.Context, algorithm string, now time.Time, generate func() (authn.StoredJWTKey, error)) (authn.StoredJWTKey, error) {
	tenant, err := r.tenant(ctx)
	if err != nil {
		return authn.StoredJWTKey{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	keys := r.keys[tenant]
	for i := len(keys) - 1; i >= 0; i-- {
		if keys[i].Algorithm == algorithm && (keys[i].ExpiresAt == nil || keys[i].ExpiresAt.After(now)) {
			return keys[i], nil
		}
	}
	key, err := generate()
	if err != nil {
		return authn.StoredJWTKey{}, err
	}
	r.keys[tenant] = append(keys, key)
	r.generated[tenant]++
	return key, nil
}

func (r *tenantKeyring) PublicJWTKeys(ctx context.Context, cutoff time.Time) ([]authn.PublicJWTKey, error) {
	tenant, err := r.tenant(ctx)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []authn.PublicJWTKey
	for _, k := range r.keys[tenant] {
		if k.ExpiresAt == nil || k.ExpiresAt.After(cutoff) {
			out = append(out, k.PublicJWTKey)
		}
	}
	return out, nil
}

func (r *tenantKeyring) JWTKeyByID(ctx context.Context, id string) (authn.StoredJWTKey, error) {
	tenant, err := r.tenant(ctx)
	if err != nil {
		return authn.StoredJWTKey{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, k := range r.keys[tenant] {
		if k.ID == id {
			return k, nil
		}
	}
	return authn.StoredJWTKey{}, authn.ErrNotFound
}

// A host keyring outside the main store keeps the signing keys, and the
// request context chooses each tenant's keys for publication, issuance,
// session headers and verification.
func TestJWTKeyStoreSelectsTenantKeys(t *testing.T) {
	ctx := t.Context()
	store, err := sqlstore.Open(ctx, "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const base = "https://tenants.example"
	off := false
	build := func(opts jwt.Options) (*authn.Auth, error) {
		p, err := jwt.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		return authn.New(authn.Options{Store: store, BaseURL: base, Secret: strings.Repeat("k", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []authn.Plugin{p}})
	}
	if _, err := build(jwt.Options{}); err == nil || !strings.Contains(err.Error(), "install the jwt schema profile") {
		t.Fatal("main store without a key table accepted the plugin", err)
	}
	ring := &tenantKeyring{keys: map[string][]authn.StoredJWTKey{}, generated: map[string]int{}}
	a, err := build(jwt.Options{KeyStore: ring})
	if err != nil {
		t.Fatal(err)
	}
	serve := func(method, path, tenant, body string, status int, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, base+"/api/auth"+path, strings.NewReader(body))
		r.Header.Set("Origin", base)
		r.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tenantKey{}, tenant)))
		if w.Code != status {
			t.Fatalf("%s %s: HTTP %d, want %d: %s", method, path, w.Code, status, w.Body)
		}
		return w
	}
	signed := serve("POST", "/sign-up/email", "", `{"email":"tenant@example.test","password":"tenant-password","name":"Tenant"}`, 200)
	var account authn.AuthResult
	if err := json.Unmarshal(signed.Body.Bytes(), &account); err != nil {
		t.Fatal(err)
	}
	session := a.SessionCookie(account.Token, true)
	keySet := func(tenant string) jose.JSONWebKeySet {
		t.Helper()
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(serve("GET", "/jwks", tenant, "", 200).Body.Bytes(), &set); err != nil || len(set.Keys) != 1 {
			t.Fatal("a tenant key set did not hold one key", err)
		}
		return set
	}
	alpha, beta := keySet("alpha"), keySet("beta")
	if alpha.Keys[0].KeyID == beta.Keys[0].KeyID {
		t.Fatal("keyring selected the same key for two tenants")
	}
	if again := keySet("alpha"); again.Keys[0].KeyID != alpha.Keys[0].KeyID || ring.generated["alpha"] != 1 || ring.generated["beta"] != 1 {
		t.Fatal("tenant key was generated more than once", ring.generated)
	}
	serve("GET", "/jwks", "", "", 500)
	var issued struct{ Token string }
	if err := json.Unmarshal(serve("GET", "/token", "alpha", "", 200, session).Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	verify := func(set jose.JSONWebKeySet) error {
		_, err := libjwt.Parse(issued.Token, func(tok *libjwt.Token) (any, error) {
			for _, k := range set.Keys {
				if k.KeyID == tok.Header["kid"] {
					return k.Key, nil
				}
			}
			return nil, errors.New("unknown key")
		}, libjwt.WithValidMethods([]string{"EdDSA"}), libjwt.WithIssuer(base), libjwt.WithAudience(base))
		return err
	}
	if err := verify(alpha); err != nil {
		t.Fatal("tenant token was not signed with its tenant key", err)
	}
	if verify(beta) == nil {
		t.Fatal("token verified against another tenant's keys")
	}
	alphaCtx, betaCtx := context.WithValue(ctx, tenantKey{}, "alpha"), context.WithValue(ctx, tenantKey{}, "beta")
	if claims, err := a.VerifyJWT(alphaCtx, issued.Token, authn.JWTVerifyOptions{}); err != nil || claims["sub"] != account.User.ID {
		t.Fatal("host verification ignored the tenant keyring", err)
	}
	if _, err := a.VerifyJWT(betaCtx, issued.Token, authn.JWTVerifyOptions{}); !errors.Is(err, authn.ErrInvalidJWT) {
		t.Fatal("verified a token with another tenant's keyring", err)
	}
	if _, err := a.SignJWT(betaCtx, "worker", authn.JWTSignOptions{KeyID: alpha.Keys[0].KeyID}); err == nil {
		t.Fatal("signed with a key from another tenant's keyring")
	}
	if _, err := a.SignJWT(alphaCtx, "worker", authn.JWTSignOptions{KeyID: alpha.Keys[0].KeyID}); err != nil {
		t.Fatal("pinned tenant key was refused", err)
	}
	header := serve("GET", "/get-session", "beta", "", 200, session).Header().Get("Set-Auth-Jwt")
	parsed, _, err := libjwt.NewParser().ParseUnverified(header, libjwt.MapClaims{})
	if err != nil || parsed.Header["kid"] != beta.Keys[0].KeyID {
		t.Fatal("session token header ignored the tenant keyring", err)
	}
}
