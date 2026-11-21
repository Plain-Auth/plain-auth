package sqlstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	libjwt "github.com/golang-jwt/jwt/v5"
	auth "github.com/Stonewrit/stonewrit-auth"
	jwtplugin "github.com/Stonewrit/stonewrit-auth/plugins/jwt"
	"github.com/Stonewrit/stonewrit-auth/schema"
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
			profile := jwtplugin.Options{Issuer: "https://application.test", Audience: "reports", AdditionalAlgorithms: []string{"ES256", "ES512", "RS256", "PS256"}, RSAModulusBits: 2048}
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
