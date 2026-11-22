package sqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	sdk "github.com/Plain-Auth/plain-auth/client"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestOAuthUserInfoClaims(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx := t.Context()
			s, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			write := func(q string, args ...any) {
				t.Helper()
				_, err := s.db.ExecContext(ctx, s.bind(q), args...)
				must(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			date := s.date(now)
			until := s.date(now.Add(time.Hour))
			write(`INSERT INTO "user" ("id","email","name","emailVerified","createdAt","updatedAt") VALUES ('user','a@example.test','Sol',?,?,?)`, false, date, date)
			write(`INSERT INTO "session" ("id","token","userId","createdAt","updatedAt","expiresAt") VALUES ('sid','cookie','user',?,?,?)`, date, date, until)
			write(`INSERT INTO "oauthClient" ("id","clientId","redirectUris") VALUES ('other','other',?)`, `[]`)
			write(`INSERT INTO "oauthClient" ("id","clientId","redirectUris","subjectType","metadata") VALUES ('row','app',?,'pairwise',?)`, `["https://reports.example.test/callback"]`, `{"theme":"blue"}`)
			sum := sha256.Sum256([]byte("grant"))
			write(`INSERT INTO "oauthAccessToken" ("id","token","clientId","userId","sessionId","scopes","requestedUserInfoClaims","createdAt","expiresAt") VALUES ('at',?,'app','user','sid',?,?,?,?)`, base64.RawURLEncoding.EncodeToString(sum[:]), `["openid","profile"]`, `["email_verified"]`, date, until)
			called := 0
			var suppress bool
			opts := op.Options{PairwiseSecret: strings.Repeat("p", 32), UserInfo: op.UserInfoOptions{
				Extensions: []op.UserInfoClaimsFunc{
					func(ctx context.Context, in op.UserInfoInput) (map[string]any, error) {
						if in.Client == nil || in.Client.ClientID != "app" || string(in.Client.Extensions["theme"]) != `"blue"` || in.User.ID != "user" || in.Token["sub"] != "user" || in.Token["azp"] != "app" || len(in.RequestedClaims) != 1 || in.RequestedClaims[0] != "email_verified" {
							return nil, errors.New("unexpected extension context")
						}
						called++
						return map[string]any{"sub": "other", "given_name": "unexpected", "family_name": "unexpected", "picture": "unexpected", "name": "unsafe", "first": "A", "extra": "present", "nilExtension": nil}, nil
					},
					func(context.Context, op.UserInfoInput) (map[string]any, error) {
						return map[string]any{"first": "B"}, nil
					},
				},
				CustomClaims: func(_ context.Context, in op.UserInfoInput) (map[string]any, error) {
					if suppress {
						return nil, errors.New("private callback error")
					}
					return map[string]any{"name": in.User.Name + "!", "sub": "wrong", "extra": "operator"}, nil
				},
			}}
			var observed error
			host := func(options op.Options) *auth.Auth {
				t.Helper()
				plug, err := op.New(options)
				must(err)
				for _, ep := range plug.Endpoints {
					if ep.Path == "/oauth2/userinfo" && !json.Valid(ep.OpenAPI) {
						t.Fatal("invalid UserInfo OpenAPI")
					}
				}
				off := false
				server, err := auth.New(auth.Options{OnAPIError: func(_ auth.ErrorContext, err error) error { observed = err; return nil }, Store: s, BaseURL: "https://issuer.example.test", BasePath: "/identity", Secret: strings.Repeat("s", 40), RateLimit: &off, Plugins: []auth.Plugin{plug}})
				must(err)
				return server
			}
			enriched, plain := host(opts), host(op.Options{PairwiseSecret: opts.PairwiseSecret})
			get := func(handler http.Handler, status int, authz ...string) map[string]any {
				t.Helper()
				r := httptest.NewRequest("GET", "https://internal.test/identity/oauth2/userinfo", nil)
				w := httptest.NewRecorder()
				w.Header().Set("Access-Control-Expose-Headers", "X-Trace")
				for _, v := range authz {
					r.Header.Add("Authorization", v)
				}
				handler.ServeHTTP(w, r)
				if w.Code != status || strings.Contains(w.Body.String(), "private callback error") {
					t.Fatalf("got %d %s, want %d (handler: %v)", w.Code, w.Body.String(), status, observed)
				}
				if status == 401 && !strings.Contains(strings.Join(w.Header().Values("Access-Control-Expose-Headers"), ","), "X-Trace,WWW-Authenticate") {
					t.Fatal("challenge not exposed with existing headers", w.Header())
				}
				var result map[string]any
				must(json.Unmarshal(w.Body.Bytes(), &result))
				return result
			}
			const bearer = "Bearer grant"
			baseline := get(plain, 200, bearer)
			if len(baseline) != 3 || baseline["sub"] == nil || baseline["sub"] == "user" || baseline["name"] != "Sol" || baseline["email_verified"] != false {
				t.Fatal("unexpected individual claims", baseline)
			}
			reader, err := sdk.New("https://issuer.example.test/identity", &http.Client{Transport: guestTransport{plain}})
			must(err)
			claims, headers, err := reader.OAuthUserInfo(ctx, "grant", "")
			must(err)
			if string(claims["sub"]) != `"`+baseline["sub"].(string)+`"` || headers.Get("Cache-Control") != "no-store" {
				t.Fatal("unexpected SDK UserInfo", claims, headers)
			}
			_, headers, err = reader.OAuthUserInfo(ctx, "grant", "proof")
			var problem *auth.APIError
			if !errors.As(err, &problem) || problem.Code != "invalid_token" || !strings.HasPrefix(headers.Get("WWW-Authenticate"), "DPoP ") {
				t.Fatal("missing SDK challenge", err, headers)
			}
			result := get(enriched, 200, bearer)
			if len(result) != 6 || result["name"] != "Sol!" || result["first"] != "A" || result["extra"] != "operator" || result["sub"] != baseline["sub"] || result["email_verified"] != false || called != 1 {
				t.Fatal("claim authority", result, called)
			}
			if v, ok := result["nilExtension"]; !ok || v != nil {
				t.Fatal("missing explicit null", result)
			}
			suppress = true
			get(enriched, 500, bearer)
			suppress = false
			write(`UPDATE "user" SET "name"='  Mary   Ann  Lee ', "image"='https://profile.test/a', "emailVerified"=? WHERE "id"='user'`, true)
			write(`UPDATE "oauthAccessToken" SET "scopes"=? WHERE "id"='at'`, `["openid","profile","email"]`)
			result = get(plain, 200, bearer)
			if len(result) != 7 || result["given_name"] != "Mary Ann" || result["family_name"] != "Lee" || result["picture"] != "https://profile.test/a" || result["email_verified"] != true || result["email"] != "a@example.test" {
				t.Fatal("profile and email", result)
			}
			write(`UPDATE "user" SET "name"='' WHERE "id"='user'`)
			result = get(plain, 200, bearer)
			if name, ok := result["name"]; !ok || name != "" {
				t.Fatal("lost empty name", result)
			}
			get(plain, 400, bearer, bearer)
			get(plain, 401)
			write(`UPDATE "oauthAccessToken" SET "revoked"=? WHERE "id"='at'`, date)
			get(plain, 401, bearer)
			write(`UPDATE "oauthAccessToken" SET "revoked"=NULL,"expiresAt"=? WHERE "id"='at'`, s.date(now.Add(-time.Hour)))
			get(plain, 401, bearer)
			write(`UPDATE "oauthAccessToken" SET "expiresAt"=?,"scopes"=? WHERE "id"='at'`, until, `["profile"]`)
			if got := get(plain, 400, bearer); got["error"] != "invalid_scope" {
				t.Fatal(got)
			}
			write(`UPDATE "oauthAccessToken" SET "userId"=NULL,"sessionId"=NULL,"scopes"=? WHERE "id"='at'`, `["openid"]`)
			if got := get(plain, 400, bearer); got["error"] != "invalid_request" {
				t.Fatal(got)
			}
			write(`UPDATE "oauthClient" SET "disabled"=? WHERE "clientId"='app'`, true)
			get(plain, 401, bearer)
			if called != 2 {
				t.Fatal("extension called without authorized grant", called)
			}
		})
	}
}
