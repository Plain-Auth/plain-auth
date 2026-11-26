package sqlstore

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	jwtplugin "github.com/Plain-Org/plain-auth/plugins/jwt"
	"github.com/Plain-Org/plain-auth/schema"
	jose "github.com/go-jose/go-jose/v4"
	libjwt "github.com/golang-jwt/jwt/v5"
)

func TestJWTIssuanceAndKeyRotation(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"jwt"})
			if err != nil {
				t.Fatal(err)
			}
			one, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer one.Close()
			two, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer two.Close()
			const origin = "https://jwt.auth.test"
			opts := jwtplugin.Options{Issuer: origin + "/issuer", Audience: "service", Expiration: 2 * time.Minute, RotationInterval: time.Hour, JWKSPath: "/public-keys"}
			makeAuth := func(store *Store, opts jwtplugin.Options) *auth.Auth {
				t.Helper()
				plugin, err := jwtplugin.New(opts)
				if err != nil {
					t.Fatal(err)
				}
				off := false
				server, err := auth.New(auth.Options{Store: store, BaseURL: origin, Secret: "local-jwt-test-secret-00000000000000", RateLimit: &off, EmailAndPassword: true, Plugins: []auth.Plugin{plugin}})
				if err != nil {
					t.Fatal(err)
				}
				return server
			}
			first, second := makeAuth(one, opts), makeAuth(two, opts)
			account, err := first.SignUpEmail(ctx, auth.SignUpInput{Name: "Test", Email: strings.ToLower(rand.Text()) + "@example.test", Password: "local-credential-fixture"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			c := first.SessionCookie(account.Token, true)
			call := func(a *auth.Auth, route string, cookie bool) *httptest.ResponseRecorder {
				r := httptest.NewRequest("GET", origin+"/api/auth/"+route, nil)
				if cookie {
					r.AddCookie(c)
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				return w
			}
			if w := call(first, "token", false); w.Code != 401 {
				t.Fatal("unauthenticated issuance succeeded")
			}
			// Two independent pools must initialize exactly one active signing key.
			var wg sync.WaitGroup
			responses := make(chan *httptest.ResponseRecorder, 4)
			for _, a := range []*auth.Auth{first, second, first, second} {
				wg.Add(1)
				go func() { defer wg.Done(); responses <- call(a, "public-keys", false) }()
			}
			wg.Wait()
			close(responses)
			var firstID, pub string
			for w := range responses {
				var set struct{ Keys []map[string]any }
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &set) != nil || len(set.Keys) != 1 {
					t.Fatalf("public bootstrap: %d %s", w.Code, w.Body)
				}
				key := set.Keys[0]
				if key["d"] != nil || key["k"] != nil || key["alg"] != "EdDSA" || key["crv"] != "Ed25519" {
					t.Fatal("invalid public key projection")
				}
				if firstID != "" && key["kid"] != firstID {
					t.Fatal("concurrent key duplication")
				}
				firstID = key["kid"].(string)
				pub = key["x"].(string)
			}
			var private string
			if err = one.db.QueryRowContext(ctx, one.bind(`SELECT "privateKey" FROM "jwks" WHERE "id"=?`), firstID).Scan(&private); err != nil || !strings.HasPrefix(private, "\"") || strings.Contains(private, pub) || strings.Contains(private, `"d"`) {
				t.Fatal("stored private signing key was unprotected")
			}
			if keys, err := one.PublicJWTKeys(ctx, time.Now().Add(-time.Hour)); err != nil || len(keys) != 1 || keys[0].ExpiresAt == nil || keys[0].ExpiresAt.Sub(keys[0].CreatedAt) != opts.RotationInterval {
				t.Fatal("first key does not expire one rotation interval after its creation", err)
			}
			verify := func(raw, issuer, aud string, when time.Time) (*libjwt.Token, error) {
				k, err := base64.RawURLEncoding.DecodeString(pub)
				if err != nil {
					return nil, err
				}
				return libjwt.Parse(raw, func(tok *libjwt.Token) (any, error) {
					if tok.Header["kid"] != firstID {
						return nil, errors.New("unknown key")
					}
					return ed25519.PublicKey(k), nil
				}, libjwt.WithValidMethods([]string{"EdDSA"}), libjwt.WithIssuer(issuer), libjwt.WithAudience(aud), libjwt.WithExpirationRequired(), libjwt.WithTimeFunc(func() time.Time { return when }))
			}
			w := call(second, "token", true)
			var issued struct{ Token string }
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &issued) != nil {
				t.Fatal("authenticated issuance failed", w.Code)
			}
			valid, err := verify(issued.Token, opts.Issuer, opts.Audience, time.Now())
			if err != nil || !valid.Valid {
				t.Fatal("independent verifier rejected signed JWT", err)
			}
			claims := valid.Claims.(libjwt.MapClaims)
			if claims["sub"] != account.User.ID || claims["email"] != account.User.Email || claims["exp"].(float64)-claims["iat"].(float64) != 120 {
				t.Fatal("incorrect default profile or configured lifetime")
			}
			if _, err = verify(issued.Token, origin, "other", time.Now()); err == nil {
				t.Fatal("unexpected issuer or audience accepted")
			}
			if _, err = verify(issued.Token, opts.Issuer, opts.Audience, time.Now().Add(3*time.Minute)); err == nil {
				t.Fatal("expired assertion accepted")
			}
			if w := call(first, "get-session", true); w.Code != 200 || w.Header().Get("Set-Auth-Jwt") == "" || !strings.Contains(w.Header().Get("Access-Control-Expose-Headers"), "set-auth-jwt") {
				t.Fatal("missing get-session JWT header")
			}
			opts.DisableHeader = true
			muted := makeAuth(one, opts)
			if w := call(muted, "get-session", true); w.Header().Get("Set-Auth-Jwt") != "" {
				t.Fatal("disabled JWT header emitted")
			}
			if _, err = one.db.ExecContext(ctx, one.bind(`UPDATE "jwks" SET "expiresAt"=? WHERE "id"=?`), one.date(time.Now().Add(-time.Minute)), firstID); err != nil {
				t.Fatal(err)
			}
			for _, a := range []*auth.Auth{first, second} {
				if w := call(a, "token", true); w.Code != 200 {
					t.Fatalf("rotation: %d %s", w.Code, w.Body)
				}
			}
			set, err := first.PublicJWKS(ctx)
			if err != nil || len(set.Keys) != 2 {
				t.Fatalf("public rotation grace: %v", err)
			}
			rotated, err := one.PublicJWTKeys(ctx, time.Now().Add(-time.Hour))
			if err != nil || len(rotated) != 2 {
				t.Fatal("rotation did not keep both keys", err)
			}
			for _, k := range rotated {
				if k.ID != firstID && (k.ExpiresAt == nil || k.ExpiresAt.Sub(k.CreatedAt) != opts.RotationInterval) {
					t.Fatal("replacement key does not expire one rotation interval after its creation")
				}
			}
			if _, err = one.db.ExecContext(ctx, one.bind(`UPDATE "jwks" SET "expiresAt"=? WHERE "id"=?`), one.date(time.Now().Add(-31*24*time.Hour)), firstID); err != nil {
				t.Fatal(err)
			}
			set, err = second.PublicJWKS(ctx)
			if err != nil || len(set.Keys) != 1 || set.Keys[0].KeyID == firstID {
				t.Fatal("expired key remained published")
			}
			customOpts := jwtplugin.Options{Algorithm: "ES256", DefinePayload: func(_ context.Context, s auth.SessionResult) (map[string]any, error) {
				return map[string]any{"employee": s.User.ID, "sub": "overridden"}, nil
			}}
			custom := makeAuth(two, customOpts)
			var es struct{ Token string }
			w = call(custom, "token", true)
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &es) != nil {
				t.Fatal("ES256 signing failed")
			}
			set, err = custom.PublicJWKS(ctx)
			if err != nil {
				t.Fatal(err)
			}
			esToken, err := libjwt.Parse(es.Token, func(t *libjwt.Token) (any, error) {
				for _, k := range set.Keys {
					if k.KeyID == t.Header["kid"] && k.Algorithm == "ES256" {
						return k.Key, nil
					}
				}
				return nil, errors.New("unknown ES256 key")
			}, libjwt.WithValidMethods([]string{"ES256"}), libjwt.WithIssuer(origin), libjwt.WithAudience(origin))
			if err != nil || !esToken.Valid {
				t.Fatalf("independent verifier rejected ES256: %v", err)
			}
			minted, err := two.PublicJWTKeys(ctx, time.Now().Add(-time.Hour))
			esKeys := 0
			for _, k := range minted {
				if k.Algorithm == "ES256" {
					esKeys++
					if k.ExpiresAt != nil {
						t.Fatal("a key minted without a rotation interval has an expiry")
					}
				}
			}
			if err != nil || esKeys == 0 {
				t.Fatal("the ES256 key was not stored", err)
			}
			esClaims := esToken.Claims.(libjwt.MapClaims)
			if esClaims["sub"] != account.User.ID || esClaims["employee"] != account.User.ID || esClaims["email"] != nil {
				t.Fatal("custom payload or subject binding changed")
			}
			if err = one.DeleteSession(ctx, account.Token); err != nil {
				t.Fatal(err)
			}
			if w := call(second, "token", true); w.Code != 401 {
				t.Fatal("revoked session issued another assertion")
			}
		})
	}
}

func TestServerJWTProfiles(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"jwt"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			profile := jwtplugin.Options{Issuer: "https://application.test", Audience: "reports", AdditionalAlgorithms: []string{"ES256", "ES512", "RS256", "PS256"}}
			plugin, err := jwtplugin.New(profile)
			if err != nil {
				t.Fatal(err)
			}
			a, err := auth.New(auth.Options{BaseURL: profile.Issuer, Secret: strings.Repeat("s", 32), Store: store, Plugins: []auth.Plugin{plugin}})
			if err != nil {
				t.Fatal(err)
			}
			for _, algorithm := range []string{"EdDSA", "ES256", "ES512", "PS256", "RS256"} {
				opts := auth.JWTSignOptions{Algorithm: algorithm, Type: "events+jwt", ContentType: "application/json", Claims: map[string]any{"event": "refresh", "sub": "untrusted"}}
				raw, err := a.SignJWT(ctx, "service-account", opts)
				if err != nil {
					t.Fatalf("%s: %v", algorithm, err)
				}
				set, err := a.PublicJWKS(ctx)
				if err != nil {
					t.Fatal(err)
				}
				token, err := libjwt.Parse(raw, func(token *libjwt.Token) (any, error) {
					for _, key := range set.Keys {
						if key.KeyID == token.Header["kid"] && key.Algorithm == algorithm && key.IsPublic() {
							return key.Key, nil
						}
					}
					return nil, errors.New("unrecognized key")
				}, libjwt.WithValidMethods([]string{algorithm}), libjwt.WithIssuer(profile.Issuer), libjwt.WithAudience("reports"), libjwt.WithExpirationRequired())
				if err != nil || !token.Valid || token.Header["typ"] != "events+jwt" || token.Header["cty"] != "application/json" {
					t.Fatalf("independent verifier rejected %s: %v", algorithm, err)
				}
				if algorithm == "RS256" || algorithm == "PS256" {
					for _, key := range set.Keys {
						if key.KeyID == token.Header["kid"] && key.Key.(*rsa.PublicKey).N.BitLen() != 2048 {
							t.Fatalf("%s key is not 2048 bits by default", algorithm)
						}
					}
				}
				claims, err := a.VerifyJWT(ctx, raw, auth.JWTVerifyOptions{Subject: "service-account"})
				if err != nil || claims["event"] != "refresh" || claims["sub"] != "service-account" {
					t.Fatalf("missing verified claims: %v", err)
				}
				opts.KeyID = token.Header["kid"].(string)
				if _, err := a.SignJWT(ctx, "service-account", opts); err != nil {
					t.Fatalf("valid pinned key: %v", err)
				}
				opts.Algorithm = "RS256"
				if algorithm == "RS256" {
					opts.Algorithm = "ES256"
				}
				if _, err := a.SignJWT(ctx, "service-account", opts); err == nil {
					t.Fatal("accepted mismatched pinned algorithm")
				}
				for _, constraints := range []auth.JWTVerifyOptions{{Audience: "billing"}, {Issuer: "https://unrelated.test"}, {Subject: "other-account"}} {
					if _, err := a.VerifyJWT(ctx, raw, constraints); !errors.Is(err, auth.ErrInvalidJWT) {
						t.Fatal("accepted mismatched verification constraints")
					}
				}
			}
			if _, err := a.SignJWT(ctx, "s", auth.JWTSignOptions{KeyID: "missing"}); err == nil {
				t.Fatal("missing key generated replacement")
			}
			if _, err := a.SignJWT(ctx, "s", auth.JWTSignOptions{Algorithm: "HS256"}); err == nil {
				t.Fatal("accepted unconfigured algorithm")
			}
			now := time.Now().UTC()
			for _, settings := range []auth.JWTSignOptions{{IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)}, {NotBefore: now.Add(time.Minute)}} {
				raw, err := a.SignJWT(ctx, "s", settings)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := a.VerifyJWT(ctx, raw, auth.JWTVerifyOptions{}); !errors.Is(err, auth.ErrInvalidJWT) {
					t.Fatal("accepted out-of-window assertion")
				}
			}
			raw, err := a.SignJWT(ctx, "subject", auth.JWTSignOptions{Audience: []string{"billing", "reporting"}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.VerifyJWT(ctx, raw, auth.JWTVerifyOptions{Audience: "reporting"}); err != nil {
				t.Fatal("multi-audience assertion rejected", err)
			}
			parts := strings.Split(raw, ".")
			parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"other"}`))
			if _, err := a.VerifyJWT(ctx, strings.Join(parts, "."), auth.JWTVerifyOptions{}); !errors.Is(err, auth.ErrInvalidJWT) {
				t.Fatal("accepted altered assertion")
			}
			req := httptest.NewRequest("POST", profile.Issuer+"/api/auth/sign-jwt", nil)
			res := httptest.NewRecorder()
			a.ServeHTTP(res, req)
			if res.Code != 404 {
				t.Fatal("server-only signer exposed as HTTP route", res.Code)
			}
		})
	}
}

// RS256 and PS256 keys use a configured modulus length, publish that size
// and verify their tokens.
func TestJWTRSAModulusLength(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			ddl, err := schema.Generate(dialect, []string{"jwt"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			const base = "https://rsa.auth.test"
			plugin, err := jwtplugin.New(jwtplugin.Options{Algorithm: "RS256", AdditionalAlgorithms: []string{"PS256"}, RSAModulusBits: 3072})
			if err != nil {
				t.Fatal(err)
			}
			a, err := auth.New(auth.Options{BaseURL: base, Secret: strings.Repeat("s", 32), Store: store, Plugins: []auth.Plugin{plugin}})
			if err != nil {
				t.Fatal(err)
			}
			for _, alg := range []string{"RS256", "PS256"} {
				raw, err := a.SignJWT(ctx, "service-account", auth.JWTSignOptions{Algorithm: alg})
				if err != nil {
					t.Fatal(err)
				}
				set, err := a.PublicJWKS(ctx)
				if err != nil {
					t.Fatal(err)
				}
				bits, encoded := 0, 0
				_, err = libjwt.Parse(raw, func(token *libjwt.Token) (any, error) {
					for _, key := range set.Keys {
						if key.KeyID == token.Header["kid"] && key.Algorithm == alg {
							bits = key.Key.(*rsa.PublicKey).N.BitLen()
							body, _ := json.Marshal(key)
							var jwk struct{ N string }
							_ = json.Unmarshal(body, &jwk)
							encoded = len(jwk.N)
							return key.Key, nil
						}
					}
					return nil, errors.New("unrecognized key")
				}, libjwt.WithValidMethods([]string{alg}), libjwt.WithIssuer(base), libjwt.WithAudience(base), libjwt.WithExpirationRequired())
				if err != nil {
					t.Fatalf("RSA verifier rejected %s with a configured modulus: %v", alg, err)
				}
				if bits != 3072 || encoded != 512 {
					t.Fatalf("%s published a %d-bit modulus", alg, bits)
				}
				if _, err := a.VerifyJWT(ctx, raw, auth.JWTVerifyOptions{Subject: "service-account"}); err != nil {
					t.Fatalf("%s token with a 3072-bit key failed verification: %v", alg, err)
				}
			}
		})
	}
}

// With encryption disabled, the private key is stored as the plain JWK of
// the published key and signs verifiable tokens; an instance that encrypts
// refuses to sign with it.
func TestJWTUnencryptedPrivateKey(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			ddl, err := schema.Generate(dialect, []string{"jwt"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			const origin = "https://plain-keys.auth.test"
			build := func(opts jwtplugin.Options) *auth.Auth {
				p, err := jwtplugin.New(opts)
				if err != nil {
					t.Fatal(err)
				}
				a, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("s", 32), Store: store, EmailAndPassword: true, Plugins: []auth.Plugin{p}})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			plain := build(jwtplugin.Options{DisablePrivateKeyEncryption: true})
			account, err := plain.SignUpEmail(ctx, auth.SignUpInput{Name: "Plain", Email: "plain@keys.test", Password: "plain-key-password"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			cookie := plain.SessionCookie(account.Token, true)
			token := func(a *auth.Auth) *httptest.ResponseRecorder {
				r := httptest.NewRequest("GET", origin+"/api/auth/token", nil)
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				return w
			}
			w := token(plain)
			var issued struct{ Token string }
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &issued) != nil || issued.Token == "" {
				t.Fatal("token issuance with an unencrypted key failed", w.Code, w.Body)
			}
			set, err := plain.PublicJWKS(ctx)
			if err != nil || len(set.Keys) != 1 {
				t.Fatal(err)
			}
			var private string
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "privateKey" FROM "jwks" WHERE "id"=?`), set.Keys[0].KeyID).Scan(&private); err != nil {
				t.Fatal(err)
			}
			var jwk jose.JSONWebKey
			if json.Unmarshal([]byte(private), &jwk) != nil || !jwk.Valid() || jwk.IsPublic() {
				t.Fatal("stored private key is not a plain private JWK")
			}
			public := jwk.Public()
			got, err := public.Thumbprint(crypto.SHA256)
			want, err2 := set.Keys[0].Thumbprint(crypto.SHA256)
			if err != nil || err2 != nil || string(got) != string(want) {
				t.Fatal("stored private key is not the plain JWK of the published key")
			}
			if _, err := libjwt.Parse(issued.Token, func(*libjwt.Token) (any, error) { return set.Keys[0].Key, nil }, libjwt.WithValidMethods([]string{"EdDSA"}), libjwt.WithIssuer(origin), libjwt.WithAudience(origin), libjwt.WithExpirationRequired()); err != nil {
				t.Fatal("independent verifier refused a token signed with an unencrypted key", err)
			}
			if w := token(build(jwtplugin.Options{})); w.Code != 500 {
				t.Fatal("an encrypting instance signed with an unencrypted key", w.Code)
			}
		})
	}
}

// With the plugin's SessionCookieCache, jwt-strategy session snapshots are
// signed with the published key, bound to the user and session token, and
// refused when signed any other way or by a key past its grace period.
func TestJWTSessionCookieCache(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			ddl, err := schema.Generate(dialect, []string{"jwt"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			const origin = "https://snapshots.auth.test"
			secret := strings.Repeat("s", 32)
			build := func(opts jwtplugin.Options, cache *auth.SessionCookieCacheOptions, logger *slog.Logger) (*auth.Auth, error) {
				p, err := jwtplugin.New(opts)
				if err != nil {
					return nil, err
				}
				return auth.New(auth.Options{Store: store, BaseURL: origin, Secret: secret, EmailAndPassword: true, Logger: logger, SessionCookieCache: cache, Plugins: []auth.Plugin{p}})
			}
			jwtCache := &auth.SessionCookieCacheOptions{Strategy: auth.SessionCacheJWT}
			for _, cache := range []*auth.SessionCookieCacheOptions{nil, {Strategy: auth.SessionCacheCompact}, {Strategy: auth.SessionCacheJWE}} {
				if _, err := build(jwtplugin.Options{SessionCookieCache: true, DisableHeader: true}, cache, nil); err == nil {
					t.Fatal("accepted plugin-signed snapshots without the jwt cache strategy")
				}
			}
			if _, err := build(jwtplugin.Options{SessionCookieCache: true}, jwtCache, nil); err == nil {
				t.Fatal("accepted plugin-signed snapshots with the session token header on")
			}
			sign := func(context.Context, auth.JWTSigningRequest) (string, error) { return "", nil }
			if _, err := build(jwtplugin.Options{SessionCookieCache: true, DisableHeader: true, Algorithm: "EdDSA", RemoteJWKSURL: "https://keys.example.test/jwks.json", Sign: sign}, jwtCache, nil); err == nil {
				t.Fatal("accepted plugin-signed snapshots with a custom signer")
			}
			var logs bytes.Buffer
			minute := time.Minute
			if _, err := build(jwtplugin.Options{SessionCookieCache: true, DisableHeader: true, GracePeriod: &minute}, &auth.SessionCookieCacheOptions{Strategy: auth.SessionCacheJWT, MaxAge: time.Hour}, slog.New(slog.NewTextHandler(&logs, nil))); err != nil || !strings.Contains(logs.String(), "grace period") {
				t.Fatal("missing warning about a grace period shorter than the snapshot lifetime", err)
			}
			a, err := build(jwtplugin.Options{SessionCookieCache: true, DisableHeader: true}, jwtCache, nil)
			if err != nil {
				t.Fatal(err)
			}
			call := func(method, path, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequest(method, origin+"/api/auth"+path, strings.NewReader(body))
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				for _, c := range cookies {
					r.AddCookie(c)
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatalf("%s %s: HTTP %d: %s", method, path, w.Code, w.Body)
				}
				return w
			}
			named := func(w *httptest.ResponseRecorder, suffix string) *http.Cookie {
				for _, c := range w.Result().Cookies() {
					if strings.HasSuffix(c.Name, suffix) && c.MaxAge >= 0 && c.Value != "" {
						return c
					}
				}
				return nil
			}
			signup := call("POST", "/sign-up/email", `{"email":"snap@example.test","password":"snapshot-password","name":"Before"}`, nil)
			var account auth.AuthResult
			if err := json.Unmarshal(signup.Body.Bytes(), &account); err != nil {
				t.Fatal(err)
			}
			original := []*http.Cookie{named(signup, ".session_token"), named(signup, ".session_data")}
			if original[0] == nil || original[1] == nil {
				t.Fatal("sign-up did not set the session and snapshot cookies")
			}
			keySet := func() jose.JSONWebKeySet {
				t.Helper()
				var set jose.JSONWebKeySet
				if err := json.Unmarshal(call("GET", "/jwks", "", nil).Body.Bytes(), &set); err != nil {
					t.Fatal(err)
				}
				return set
			}
			set := keySet()
			if len(set.Keys) != 1 {
				t.Fatal("expected one published key", len(set.Keys))
			}
			parsed, err := libjwt.Parse(original[1].Value, func(*libjwt.Token) (any, error) { return set.Keys[0].Key, nil }, libjwt.WithValidMethods([]string{"EdDSA"}), libjwt.WithIssuer(origin), libjwt.WithAudience("plainauth:session-cache"), libjwt.WithExpirationRequired())
			if err != nil {
				t.Fatal("snapshot failed verification with the published key", err)
			}
			if parsed.Header["kid"] != set.Keys[0].KeyID || parsed.Header["typ"] != "plainauth.session-cache+jwt" {
				t.Fatal("snapshot header does not name the published key and session-cache type", parsed.Header)
			}
			claims := parsed.Claims.(libjwt.MapClaims)
			session, _ := claims["session"].(map[string]any)
			if claims["sub"] != account.User.ID || claims["sid"] != account.Token || session["token"] != account.Token || claims["exp"].(float64)-claims["iat"].(float64) != 300 {
				t.Fatal("snapshot claims do not bind the user and session token", claims)
			}
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "name"='Live' WHERE "id"=?`), account.User.ID); err != nil {
				t.Fatal(err)
			}
			view := func(cookies []*http.Cookie) (string, string, *http.Cookie) {
				t.Helper()
				w := call("GET", "/get-session", "", cookies)
				var out auth.SessionResult
				if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
					t.Fatal(err, w.Body)
				}
				return out.User.Name, out.Session.Token, named(w, ".session_data")
			}
			if name, _, _ := view(original); name != "Before" {
				t.Fatal("browser view did not use the plugin-signed snapshot", name)
			}
			forge := func(method libjwt.SigningMethod, key any, header map[string]any) *http.Cookie {
				token := libjwt.NewWithClaims(method, claims)
				for k, v := range header {
					token.Header[k] = v
				}
				signed, err := token.SignedString(key)
				if err != nil {
					t.Fatal(err)
				}
				forged := *original[1]
				forged.Value = signed
				return &forged
			}
			name, _, replaced := view([]*http.Cookie{original[0], forge(libjwt.SigningMethodHS256, []byte(secret), nil)})
			if name != "Live" {
				t.Fatal("accepted a snapshot signed with the application secret")
			}
			if replaced == nil {
				t.Fatal("live read did not replace the snapshot with a plugin-signed one")
			}
			fresh, _, err := libjwt.NewParser().ParseUnverified(replaced.Value, libjwt.MapClaims{})
			if err != nil || fresh.Header["typ"] != "plainauth.session-cache+jwt" || fresh.Header["kid"] != set.Keys[0].KeyID {
				t.Fatal("live read did not replace the snapshot with a plugin-signed one", err)
			}
			_, other, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if name, _, _ := view([]*http.Cookie{original[0], forge(libjwt.SigningMethodEdDSA, other, map[string]any{"kid": set.Keys[0].KeyID, "typ": "plainauth.session-cache+jwt"})}); name != "Live" {
				t.Fatal("accepted a snapshot signed by another key under the published key ID")
			}
			// Snapshots minted with the same key but the wrong type, audience,
			// subject, session or issuer are refused.
			base := map[string]any{}
			for k, v := range claims {
				switch k {
				case "sub", "iss", "aud", "iat", "exp", "nbf":
				default:
					base[k] = v
				}
			}
			minted := func(subject, typ, audience, issuer, sid string) []*http.Cookie {
				t.Helper()
				c := map[string]any{}
				for k, v := range base {
					c[k] = v
				}
				c["sid"] = sid
				opts := auth.JWTSignOptions{Type: typ, Issuer: issuer, Claims: c}
				if audience != "" {
					opts.Audience = []string{audience}
				}
				raw, err := a.SignJWT(ctx, subject, opts)
				if err != nil {
					t.Fatal(err)
				}
				forged := *original[1]
				forged.Value = raw
				return []*http.Cookie{original[0], &forged}
			}
			const typ, aud = "plainauth.session-cache+jwt", "plainauth:session-cache"
			if name, _, _ := view(minted(account.User.ID, typ, aud, "", account.Token)); name != "Before" {
				t.Fatal("a correctly minted snapshot was refused")
			}
			if name, _, _ := view(minted(account.User.ID, typ, "", "", account.Token)); name != "Live" {
				t.Fatal("accepted a snapshot without the session-cache audience")
			}
			if name, _, _ := view(minted(account.User.ID, "", aud, "", account.Token)); name != "Live" {
				t.Fatal("accepted a snapshot without the session-cache type")
			}
			if name, _, _ := view(minted("other", typ, aud, "", account.Token)); name != "Live" {
				t.Fatal("accepted a snapshot whose subject is another user")
			}
			if name, _, _ := view(minted(account.User.ID, typ, aud, "", "other")); name != "Live" {
				t.Fatal("accepted a snapshot whose sid is another session")
			}
			if name, _, _ := view(minted(account.User.ID, typ, aud, "https://elsewhere.test", account.Token)); name != "Live" {
				t.Fatal("accepted a snapshot from another issuer")
			}
			second := call("POST", "/sign-in/email", `{"email":"snap@example.test","password":"snapshot-password"}`, nil)
			var again auth.AuthResult
			if err := json.Unmarshal(second.Body.Bytes(), &again); err != nil {
				t.Fatal(err)
			}
			if name, token, _ := view([]*http.Cookie{named(second, ".session_token"), original[1]}); name != "Live" || token != again.Token {
				t.Fatal("accepted another session's snapshot", name)
			}
			firstKey := set.Keys[0].KeyID
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "jwks" SET "expiresAt"=? WHERE "id"=?`), store.date(time.Now().Add(-time.Minute)), firstKey); err != nil {
				t.Fatal(err)
			}
			call("GET", "/token", "", original[:1])
			if name, _, _ := view(original); name != "Before" {
				t.Fatal("rotated key stopped verifying a snapshot inside the grace period", name)
			}
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "jwks" SET "expiresAt"=? WHERE "id"=?`), store.date(time.Now().Add(-31*24*time.Hour)), firstKey); err != nil {
				t.Fatal(err)
			}
			name, _, replaced = view(original)
			if name != "Live" {
				t.Fatal("accepted a snapshot signed by a key past its grace period")
			}
			current := keySet()
			after, _, err := libjwt.NewParser().ParseUnverified(replaced.Value, libjwt.MapClaims{})
			if err != nil || len(current.Keys) != 1 || after.Header["kid"] != current.Keys[0].KeyID || current.Keys[0].KeyID == firstKey {
				t.Fatal("replacement snapshot after rotation is not signed by the new key", err)
			}
		})
	}
}
