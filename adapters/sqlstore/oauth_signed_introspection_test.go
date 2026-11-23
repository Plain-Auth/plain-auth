package sqlstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
	jose "github.com/go-jose/go-jose/v4"
)

type introspectionKeys struct {
	*Store
	beforeRead func()
	failure    error
}

func (s *introspectionKeys) PublicJWTKeys(ctx context.Context, cutoff time.Time) ([]auth.PublicJWTKey, error) {
	if s.beforeRead != nil {
		before := s.beforeRead
		s.beforeRead = nil
		before()
	}
	if s.failure != nil {
		return nil, s.failure
	}
	return s.Store.PublicJWTKeys(ctx, cutoff)
}

func TestSignedAccessIntrospection(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider", "jwt"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			peer, err := Open(ctx, dialect, dsn)
			must(err)
			t.Cleanup(func() { peer.Close() })
			keys := &introspectionKeys{Store: s}
			write := func(q string, args ...any) {
				t.Helper()
				_, err := peer.db.ExecContext(ctx, peer.bind(q), args...)
				must(err)
			}
			for _, id := range []string{"App", "API", "Other"} {
				write(`INSERT INTO "oauthClient" ("id","clientId","clientSecret","redirectUris") VALUES (?,?,?,'[]')`, id, id, "secret")
			}
			const origin = "https://host.example.test"
			const issuer = "https://issuer.example.test/v1"
			const userInfo = origin + "/identity/oauth2/userinfo"
			const audience = "urn:reports"
			now := time.Now().UTC().Truncate(time.Second)
			until := now.Add(time.Hour)
			write(`INSERT INTO "user" ("id","email","name","emailVerified","createdAt","updatedAt") VALUES ('user','person@example.test','U',?,?,?)`, true, s.date(now), s.date(now))
			write(`INSERT INTO "session" ("id","token","userId","createdAt","updatedAt","expiresAt") VALUES ('Session','browser','user',?,?,?)`, s.date(now), s.date(now), s.date(until))
			write(`INSERT INTO "oauthResource" ("id","identifier","name","customClaims","disabled") VALUES ('r',?,'Reports',?,?)`, audience, `{"fromPolicy":true}`, true)
			write(`INSERT INTO "oauthClientResource" ("id","clientId","resourceId") VALUES ('l','API',?)`, audience)
			write(`INSERT INTO "oauthAccessToken" ("id","token","clientId","scopes","createdAt","expiresAt") VALUES ('opaque','stored','App',?,?,?)`, `["opaque"]`, s.date(now), s.date(until))
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			must(err)
			public, err := json.Marshal(jose.JSONWebKey{Key: pub})
			must(err)
			const insertKey = `INSERT INTO "jwks" ("id","publicKey","privateKey","createdAt","alg","crv") VALUES (?,?,'unused',?,'EdDSA','Ed25519')`
			write(insertKey, "signer", string(public), s.date(now))
			plugin, err := op.New(op.Options{Registration: op.RegistrationOptions{VerifySecret: func(_ context.Context, raw, stored string) (bool, error) { return raw == stored, nil }},
				Tokens: op.TokenOptions{HashOpaqueToken: func(context.Context, string) (string, error) { return "stored", nil }}})
			must(err)
			jwtPlugin, err := auth.NewJWT(auth.JWTOptions{Issuer: issuer})
			must(err)
			off := false
			host, err := auth.New(auth.Options{BaseURL: origin, BasePath: "/identity", Secret: strings.Repeat("s", 40), Store: keys, Plugins: []auth.Plugin{jwtPlugin, plugin}, RateLimit: &off})
			must(err)
			encode := base64.RawURLEncoding.EncodeToString
			sign := func(header, payload string, unencoded bool) string {
				body := encode([]byte(payload))
				if unencoded {
					body = payload
				}
				message := encode([]byte(header)) + "." + body
				return message + "." + encode(ed25519.Sign(priv, []byte(message)))
			}
			const header = `{"alg":"EdDSA","kid":"signer"}`
			makeToken := func(fields map[string]any) string {
				t.Helper()
				claims := map[string]any{"azp": "App", "iss": issuer, "exp": until.Unix()}
				for key, value := range fields {
					claims[key] = value
				}
				payload, err := json.Marshal(claims)
				must(err)
				return sign(header, string(payload), false)
			}
			call := func(caller, token string, status int) map[string]any {
				t.Helper()
				values := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
				r := httptest.NewRequest(http.MethodPost, origin+"/identity/oauth2/introspect", strings.NewReader(values.Encode()))
				r.SetBasicAuth(caller, "secret")
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()
				host.ServeHTTP(w, r)
				if w.Code != status || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "internal key failure") {
					t.Fatalf("unexpected response %d %s", w.Code, w.Body.String())
				}
				var result map[string]any
				must(json.Unmarshal(w.Body.Bytes(), &result))
				return result
			}
			inactive := func(caller, token string) {
				t.Helper()
				result := call(caller, token, 200)
				if len(result) != 1 || result["active"] != false {
					t.Fatal("inactive token disclosed claims", result)
				}
			}
			token := makeToken(map[string]any{"sub": "user", "sid": "Session", "aud": []string{audience, userInfo}, "cnf": map[string]string{"jkt": "thumb"}, "fromToken": "retained"})
			for _, caller := range []string{"App", "API"} {
				result := call(caller, token, 200)
				if result["active"] != true || result["sub"] != "user" || result["sid"] != "Session" || result["client_id"] != "App" || result["token_type"] != "DPoP" || result["fromPolicy"] != nil || result["fromToken"] != "retained" {
					t.Fatal("unexpected signed claims", result)
				}
			}
			inactive("Other", token)
			inactive("API", makeToken(map[string]any{"aud": userInfo}))
			inactive("App", makeToken(map[string]any{"aud": issuer + "/oauth2/userinfo"}))
			inactive("App", makeToken(map[string]any{"azp": "app"}))
			inactive("App", makeToken(map[string]any{"sid": "session"}))
			inactive("App", makeToken(map[string]any{"aud": []any{audience, 3}}))
			for _, payload := range []string{"null", "[]", "{bad JSON"} {
				inactive("App", sign(header, payload, false))
			}
			inactive("App", sign(`{"alg":"EdDSA","kid":"signer","crit":["b64"],"b64":false}`, "unencoded", true))
			inactive("App", makeToken(map[string]any{"exp": now.Unix()}))
			for _, shadow := range []string{
				makeToken(map[string]any{"iss": "wrong", "exp": 1}), makeToken(map[string]any{"nbf": until.Unix()}),
				makeToken(map[string]any{"iat": true}), sign(`{"alg":"EdDSA","kid":"unknown"}`, `{}`, false),
			} {
				if result := call("App", shadow, 200); result["active"] != true || result["scope"] != "opaque" {
					t.Fatal("stored token lookup was skipped", result)
				}
			}
			keys.beforeRead = func() { write(`UPDATE "oauthClient" SET "clientSecret"='new' WHERE "id"='API'`) }
			call("API", token, 401)
			write(`UPDATE "oauthClient" SET "clientSecret"='secret' WHERE "id"='API'`)
			keys.beforeRead = func() { write(`UPDATE "oauthClient" SET "disabled"=TRUE WHERE "id"='App'`) }
			inactive("API", token)
			write(`UPDATE "oauthClient" SET "disabled"=FALSE WHERE "id"='App'`)
			must(peer.DeleteSession(ctx, "browser"))
			inactive("App", token)
			keys.failure = errors.New("internal key failure")
			call("App", token, 500)
			keys.failure = nil
			noKid := sign(`{"alg":"EdDSA"}`, `{"iss":"https://issuer.example.test/v1","azp":"App"}`, false)
			if call("App", noKid, 200)["active"] != true {
				t.Fatal("unambiguous key rejected")
			}
			write(insertKey, "second", string(public), s.date(now))
			call("App", noKid, 500)
			write(`UPDATE "jwks" SET "publicKey"='invalid' WHERE "id"='signer'`)
			call("App", token, 500)
		})
	}
}
