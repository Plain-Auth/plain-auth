package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestOAuthRefreshIntrospection(t *testing.T) {
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
			s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			peer, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { peer.Close() })
			write := func(q string, args ...any) {
				t.Helper()
				_, err := peer.db.ExecContext(ctx, peer.bind(q), args...)
				must(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			until := now.Add(time.Hour)
			write(`INSERT INTO "user" ("id","email","name","emailVerified","createdAt","updatedAt") VALUES ('user','u@example.test','U',?,?,?)`, true, s.date(now), s.date(now))
			write(`INSERT INTO "session" ("id","token","userId","createdAt","updatedAt","expiresAt") VALUES ('browser','cookie','user',?,?,?)`, s.date(now), s.date(now), s.date(until))
			for _, id := range []string{"app", "other"} {
				write(`INSERT INTO "oauthClient" ("id","clientId","clientSecret","redirectUris") VALUES (?,?,?,?)`, id, id, "stored", "[]")
			}
			write(`INSERT INTO "oauthRefreshToken" ("id","clientId","userId","sessionId","authorizationCodeId","token","createdAt","expiresAt","scopes") VALUES ('grant','app','user','browser','code','StoredRefresh',?,?,?)`, s.date(now), s.date(until), `["read"]`)
			var beforeRead func()
			var decodes int
			opts := op.Options{Registration: op.RegistrationOptions{VerifySecret: func(_ context.Context, raw, stored string) (bool, error) {
				return raw == "secret" && stored == "stored", nil
			}},
				Tokens: op.TokenOptions{RefreshPrefix: "token-", OpaquePrefix: "token-", HashOpaqueToken: func(context.Context, string) (string, error) { return "StoredAccess", nil },
					DecodeRefreshToken: func(_ context.Context, v string) (string, error) {
						decodes++
						if v == "failed" {
							return "", errors.New("private decoder error")
						}
						returnValue, ok := strings.CutPrefix(v, "wrapped.")
						if !ok {
							return "", op.ErrInvalidRefreshToken
						}
						return returnValue, nil
					}, HashRefreshToken: func(_ context.Context, v string) (string, error) {
						if beforeRead != nil {
							beforeRead()
						}
						switch v {
						case "value":
							return "StoredRefresh", nil
						case "error":
							return "", errors.New("private hash error")
						default:
							return v, nil
						}
					}}}
			p, err := op.New(opts)
			must(err)
			const origin = "https://host.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, BasePath: "/identity", Store: s, Secret: strings.Repeat("s", 40), Plugins: []auth.Plugin{p}, RateLimit: &off})
			must(err)
			call := func(clientID, token, hint string, status int) map[string]any {
				t.Helper()
				form := url.Values{"token": {token}}
				if hint != "" {
					form.Set("token_type_hint", hint)
				}
				req := httptest.NewRequest(http.MethodPost, origin+"/identity/oauth2/introspect", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth(clientID, "secret")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, req)
				if w.Code != status || strings.Contains(w.Body.String(), "private ") || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("introspection returned %d %s", w.Code, w.Body.String())
				}
				var body map[string]any
				must(json.Unmarshal(w.Body.Bytes(), &body))
				return body
			}
			const token = "token-wrapped.value"
			const hint = "refresh_token"
			want := map[string]any{"active": true, "client_id": "app", "sub": "user", "sid": "browser", "iss": origin + "/identity", "exp": float64(until.Unix()), "iat": float64(now.Unix()), "scope": "read", "token_type": "Bearer"}
			wantActive := func(hint string) {
				t.Helper()
				if v := call("app", token, hint, 200); !reflect.DeepEqual(v, want) {
					t.Fatalf("got %v, want %v", v, want)
				}
			}
			inactive := func(id, raw, hint string) {
				t.Helper()
				v := call(id, raw, hint, 200)
				if !reflect.DeepEqual(v, map[string]any{"active": false}) {
					t.Fatal("inactive response disclosed claims", v)
				}
			}
			wantActive(hint)
			wantActive("unknown")
			write(`UPDATE "oauthClient" SET "subjectType"='pairwise' WHERE "clientId"='app'`)
			if result := call("app", token, hint, 500); result["sub"] != nil {
				t.Fatal("pairwise client disclosed a public subject without a secret")
			}
			write(`UPDATE "oauthClient" SET "subjectType"='public' WHERE "clientId"='app'`)
			inactive("other", token, hint)
			inactive("app", "token-invalid", hint)
			inactive("app", "wrapped.value", hint)
			inactive("app", "token-wrapped.storedrefresh", hint)
			call("app", "token-failed", hint, 500)
			call("app", "token-wrapped.error", hint, 500)
			before := decodes
			inactive("app", "token-failed", "access_token")
			if decodes != before {
				t.Fatal("explicit access hint invoked the refresh decoder")
			}

			// Even a revoked, foreign access token is a recognized access token:
			// a missing hint must not bypass its inactive result by trying the other kind.
			write(`INSERT INTO "oauthAccessToken" ("id","clientId","token","scopes","createdAt","expiresAt","revoked") VALUES ('collision','other','StoredAccess','[]',?,?,?)`, s.date(now), s.date(until), s.date(now))
			inactive("app", token, "")
			if decodes != before {
				t.Fatal("known inactive access token invoked the refresh decoder")
			}
			wantActive(hint)

			write(`UPDATE "oauthRefreshToken" SET "expiresAt"=? WHERE "id"='grant'`, s.date(now.Add(-time.Hour)))
			inactive("app", token, hint)
			write(`UPDATE "oauthRefreshToken" SET "expiresAt"=? WHERE "id"='grant'`, s.date(until))
			write(`DELETE FROM "session" WHERE "id"='browser'`)
			delete(want, "sid")
			inactive("app", token, hint)
			write(`UPDATE "oauthRefreshToken" SET "scopes"=? WHERE "id"='grant'`, `["read","offline_access"]`)
			want["scope"] = "read offline_access"
			wantActive(hint)
			write(`UPDATE "oauthRefreshToken" SET "authorizationCodeId"=NULL, "scopes"=?, "confirmation"=? WHERE "id"='grant'`, `["device"]`, `{"jkt":"device-key"}`)
			want["scope"], want["token_type"], want["cnf"] = "device", "DPoP", map[string]any{"jkt": "device-key"}
			wantActive(hint)
			beforeRead = func() { write(`UPDATE "oauthRefreshToken" SET "revoked"=? WHERE "id"='grant'`, s.date(now)) }
			inactive("app", token, hint)
			beforeRead = func() { write(`UPDATE "oauthClient" SET "clientSecret"='rotated' WHERE "clientId"='app'`) }
			call("app", token, hint, 401)
		})
	}
}
