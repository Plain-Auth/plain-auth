package sqlstore

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/schema"
	"golang.org/x/oauth2"
)

func TestRefreshGrantExchange(t *testing.T) {
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
			open := func() *Store {
				t.Helper()
				s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
				must(err)
				t.Cleanup(func() { s.Close() })
				return s
			}
			s, peer := open(), open()
			write := func(q string, args ...any) {
				t.Helper()
				_, err := peer.db.ExecContext(ctx, peer.bind(q), args...)
				must(err)
			}
			count := func(q string, args ...any) int {
				t.Helper()
				var n int
				must(peer.db.QueryRowContext(ctx, peer.bind(q), args...).Scan(&n))
				return n
			}
			now := time.Now().UTC().Truncate(time.Second)
			const scopes = `["reports","offline_access"]`
			const claims = `["name"]`
			for _, id := range []string{"app", "other"} {
				write(`INSERT INTO "oauthClient" ("id","clientId","tokenEndpointAuthMethod","redirectUris","scopes") VALUES (?,?,'none',?,?)`, id, id, "[]", scopes)
				write(`INSERT INTO "user" ("id","email","name","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`, id, id+"@example.test", id, true, s.date(now), s.date(now))
			}
			write(`INSERT INTO "session" ("id","token","userId","createdAt","updatedAt","expiresAt") VALUES ('browser','cookie','app',?,?,?)`, s.date(now), s.date(now), s.date(now.Add(time.Hour)))
			seed := func(id, client, user string) {
				var sid any
				if user == "app" {
					sid = "browser"
				}
				write(`INSERT INTO "oauthRefreshToken" ("id","token","clientId","userId","sessionId","authorizationCodeId","referenceId","requestedUserInfoClaims","scopes","createdAt","expiresAt","authTime") VALUES (?,?,?,?,?,?,'tenant',?,?,?,?,?)`, id, "db/"+id, client, user, sid, "code/"+id, claims, scopes, s.date(now), s.date(now.Add(time.Hour)), s.date(now.Add(-time.Hour)))
			}
			seed("initial", "app", "app")
			var beforeEncode func(context.Context) error
			var collide bool
			plugin, err := op.New(op.Options{Tokens: op.TokenOptions{
				AccessLifetime: time.Minute, RefreshLifetime: 17 * time.Minute, RefreshPrefix: "rt_",
				HashRefreshToken: func(_ context.Context, raw string) (string, error) { return "db/" + raw, nil },
				GenerateOpaqueToken: func(context.Context) (string, error) {
					if collide {
						return "fixed-access", nil
					}
					return rand.Text(), nil
				},
				DecodeRefreshToken: func(_ context.Context, v string) (string, error) {
					raw, ok := strings.CutPrefix(v, "browser.")
					if !ok {
						return "", op.ErrInvalidRefreshToken
					}
					return raw, nil
				},
				EncodeRefreshToken: func(ctx context.Context, raw, sid string) (string, error) {
					if beforeEncode != nil {
						if err := beforeEncode(ctx); err != nil {
							return "", err
						}
					}
					return sid + "." + raw, nil
				},
			}})
			must(err)
			const origin = "https://issuer.example.test"
			host := func(store *Store) *auth.Auth {
				t.Helper()
				off := false
				h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("s", 40), RateLimit: &off, Store: store, Plugins: []auth.Plugin{plugin}})
				must(err)
				return h
			}
			first, second := host(s), host(peer)
			call := func(h *auth.Auth, client, token string) *httptest.ResponseRecorder {
				form := url.Values{"client_id": {client}, "grant_type": {"refresh_token"}, "refresh_token": {token}}
				req := httptest.NewRequest("POST", origin+"/api/auth/oauth2/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				return out
			}
			expect := func(client, token string, status int, code string) op.DelegatedToken {
				t.Helper()
				out := call(first, client, token)
				var body struct {
					op.DelegatedToken
					Error string
				}
				must(json.Unmarshal(out.Body.Bytes(), &body))
				if out.Code != status || code != "" && body.Error != code || status != 200 && (body.AccessToken != "" || body.RefreshToken != "") {
					t.Fatalf("unexpected refresh response %d %s", out.Code, body.Error)
				}
				return body.DelegatedToken
			}
			const original = "rt_browser.initial"
			expect("other", original, 400, "invalid_grant")
			expect("app", "bad-format", 400, "invalid_grant")
			expect("missing", "bad-format", 400, "invalid_client")
			write(`UPDATE "oauthRefreshToken" SET "expiresAt"=? WHERE "id"='initial'`, s.date(now))
			expect("app", original, 400, "invalid_grant")
			write(`UPDATE "oauthRefreshToken" SET "expiresAt"=?, "resources"=? WHERE "id"='initial'`, s.date(now.Add(time.Hour)), `["https://api.example.test"]`)
			expect("app", original, 501, "server_error")
			write(`UPDATE "oauthRefreshToken" SET "resources"=NULL,"confirmation"=? WHERE "id"='initial'`, `{"jkt":"bound"}`)
			expect("app", original, 400, "invalid_dpop_proof")
			write(`UPDATE "oauthRefreshToken" SET "confirmation"=NULL WHERE "id"='initial'`)
			write(`UPDATE "oauthClient" SET "grantTypes"=? WHERE "id"='app'`, `["client_credentials"]`)
			expect("app", original, 400, "unauthorized_client")
			write(`UPDATE "oauthClient" SET "grantTypes"=? WHERE "id"='app'`, `["authorization_code"]`)
			beforeEncode = func(context.Context) error { return errors.New("formatter unavailable") }
			expect("app", original, 500, "")
			beforeEncode = func(context.Context) error {
				write(`UPDATE "oauthClient" SET "scopes"=? WHERE "id"='app'`, "[]")
				return nil
			}
			expect("app", original, 400, "invalid_scope")
			beforeEncode = nil
			write(`UPDATE "oauthClient" SET "scopes"=? WHERE "id"='app'`, scopes)
			// The second exchange collides on the access insert, after updating
			// the parent and inserting its replacement inside the transaction.
			collide = true
			seed("preexisting", "app", "app")
			expect("app", "rt_browser.preexisting", 200, "")
			expect("app", original, 500, "")
			if count(`SELECT COUNT(*) FROM "oauthRefreshToken" WHERE "authorizationCodeId"='code/initial' AND "revoked" IS NULL`) != 1 || count(`SELECT COUNT(*) FROM "oauthRefreshToken" WHERE "authorizationCodeId"='code/initial'`) != 1 {
				t.Fatal("failed rotation changed the parent or left a replacement")
			}
			collide = false
			server := httptest.NewServer(first)
			t.Cleanup(server.Close)
			cfg := oauth2.Config{ClientID: "app", Endpoint: oauth2.Endpoint{TokenURL: server.URL + "/api/auth/oauth2/token", AuthStyle: oauth2.AuthStyleInParams}}
			next, err := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: original}).Token()
			must(err)
			raw, ok := strings.CutPrefix(next.RefreshToken, "rt_browser.")
			if !next.Valid() || !ok || raw == "" || next.Extra("scope") != "reports offline_access" {
				t.Fatal("Go OAuth client did not receive the replacement grant")
			}
			var issued, end, authTime time.Time
			var code, ref, accessSID string
			var refreshClaims, accessClaims []byte
			must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT r."createdAt",r."expiresAt",r."authTime",r."authorizationCodeId",r."referenceId",a."sessionId",a."requestedUserInfoClaims",r."requestedUserInfoClaims" FROM "oauthRefreshToken" r JOIN "oauthAccessToken" a ON a."refreshId"=r."id" WHERE r."token"=?`), "db/"+raw).Scan(&issued, &end, &authTime, &code, &ref, &accessSID, &accessClaims, &refreshClaims))
			if end.Sub(issued) != 17*time.Minute || !authTime.Equal(now.Add(-time.Hour)) || code != "code/initial" || ref != "tenant" || accessSID != "browser" {
				t.Fatal("replacement lifetime or grant lineage changed")
			}
			for _, b := range [][]byte{refreshClaims, accessClaims} {
				var got []string
				must(json.Unmarshal(b, &got))
				if !slices.Equal(got, []string{"name"}) {
					t.Fatal("lost authorized claims")
				}
			}
			// A foreign issuer's still-open retry window must preserve the family.
			write(`UPDATE "oauthRefreshToken" SET "rotationReplayExpiresAt"=? WHERE "id"='initial'`, s.date(now.Add(time.Hour)))
			expect("app", original, 400, "invalid_grant")
			if count(`SELECT COUNT(*) FROM "oauthRefreshToken" WHERE "token"=?`, "db/"+raw) != 1 {
				t.Fatal("an in-window retry invalidated the replacement")
			}
			seed("other-client", "other", "app")
			seed("other-user", "app", "other")
			seed("race", "app", "app")
			start := make(chan struct{}, 2)
			resume := make(chan struct{})
			results := make(chan int, 2)
			beforeEncode = func(ctx context.Context) error {
				start <- struct{}{}
				select {
				case <-resume:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			for _, h := range []*auth.Auth{first, second} {
				go func() { results <- call(h, "app", "rt_browser.race").Code }()
			}
			for range 2 {
				select {
				case <-start:
				case <-time.After(10 * time.Second):
					close(resume)
					t.Fatal("refresh callbacks blocked each other")
				}
			}
			close(resume)
			statuses := []int{<-results, <-results}
			slices.Sort(statuses)
			if !slices.Equal(statuses, []int{200, 400}) || count(`SELECT COUNT(*) FROM "oauthRefreshToken" WHERE "clientId"='app' AND "userId"='app'`) != 0 || count(`SELECT COUNT(*) FROM "oauthAccessToken" WHERE "refreshId" IS NOT NULL`) != 0 {
				t.Fatal("concurrent rotations left a usable family", statuses)
			}
			if count(`SELECT COUNT(*) FROM "oauthRefreshToken" WHERE "id" IN ('other-client','other-user')`) != 2 {
				t.Fatal("replay affected another client or user")
			}
		})
	}
}
