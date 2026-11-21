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
	auth "github.com/nabuhadba/go-better-auth"
	jwtplugin "github.com/nabuhadba/go-better-auth/plugins/jwt"
	"github.com/nabuhadba/go-better-auth/schema"
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
