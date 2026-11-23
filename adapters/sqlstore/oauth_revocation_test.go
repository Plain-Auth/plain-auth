package sqlstore

import (
	"context"
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
)

func TestOAuthTokenRevocation(t *testing.T) {
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
			store, peer := open(), open()
			write := func(q string, args ...any) {
				t.Helper()
				_, err := peer.db.ExecContext(ctx, peer.bind(q), args...)
				must(err)
			}
			count := func(want int, q string, args ...any) {
				t.Helper()
				var n int
				must(peer.db.QueryRowContext(ctx, peer.bind(q), args...).Scan(&n))
				if n != want {
					t.Fatalf("%s returned %d, want %d", q, n, want)
				}
			}
			now := time.Now().UTC()
			const insertClient = `INSERT INTO "oauthClient" ("id","clientId","clientSecret","tokenEndpointAuthMethod","redirectUris") VALUES (?,?,?,?,?)`
			addClient := func(row, id string) { write(insertClient, row, id, "saved", "client_secret_basic", `[]`) }
			addClient("first", "Reports")
			addClient("second", "Other")
			for _, user := range []string{"one", "two"} {
				write(`INSERT INTO "user" ("id","email","name","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`, user, user+"@test.local", user, true, store.date(now), store.date(now))
			}
			access := func(id, clientID string, refresh any) {
				write(`INSERT INTO "oauthAccessToken" ("id","token","clientId","refreshId","createdAt","expiresAt","scopes") VALUES (?,?,?,?,?,?,?)`,
					id, "access-"+id, clientID, refresh, store.date(now), store.date(now.Add(time.Hour)), `["read"]`)
			}
			refresh := func(id, clientID, user string) {
				write(`INSERT INTO "oauthRefreshToken" ("id","token","clientId","userId","createdAt","expiresAt","scopes") VALUES (?,?,?,?,?,?,?)`,
					id, "refresh-"+id, clientID, user, store.date(now), store.date(now.Add(time.Hour)), `["read"]`)
				access(id, clientID, id)
			}
			refresh("old", "Reports", "one")
			refresh("new", "Reports", "one")
			refresh("other-user", "Reports", "two")
			refresh("other-client", "Other", "one")
			access("standalone", "Reports", nil)
			var duringHash func()
			opts := op.Options{Registration: op.RegistrationOptions{VerifySecret: func(_ context.Context, raw, stored string) (bool, error) {
				return raw == "secret" && stored == "saved", nil
			}}, Tokens: op.TokenOptions{OpaquePrefix: "at_", RefreshPrefix: "rt_",
				HashOpaqueToken: func(_ context.Context, value string) (string, error) {
					if duringHash != nil {
						duringHash()
					}
					return "access-" + value, nil
				},
				DecodeRefreshToken: func(_ context.Context, value string) (string, error) {
					if value == "key-error" {
						return "", errors.New("private key failure")
					}
					raw, ok := strings.CutPrefix(value, "wrapped.")
					if !ok {
						return "", op.ErrInvalidRefreshToken
					}
					return raw, nil
				},
				HashRefreshToken: func(_ context.Context, value string) (string, error) { return "refresh-" + value, nil },
			}}
			off := false
			const origin = "https://issuer.example.test"
			makeHost := func(s *Store) *auth.Auth {
				t.Helper()
				p, err := op.New(opts)
				must(err)
				h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("s", 40), Store: s, Plugins: []auth.Plugin{p}, RateLimit: &off})
				must(err)
				return h
			}
			host, otherHost := makeHost(store), makeHost(peer)
			send := func(h *auth.Auth, clientID, token, hint string) *httptest.ResponseRecorder {
				body := url.Values{"token": {token}, "token_type_hint": {hint}}
				r := httptest.NewRequest(http.MethodPost, origin+"/api/auth/oauth2/revoke", strings.NewReader(body.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.SetBasicAuth(clientID, "secret")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			expect := func(w *httptest.ResponseRecorder, status int) {
				t.Helper()
				if w.Code != status || status == 200 && w.Body.Len() != 0 || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "private key failure") {
					t.Fatalf("unexpected revocation response %d %q", w.Code, w.Body.String())
				}
			}
			revoke := func(id, token, hint string, status int) { t.Helper(); expect(send(host, id, token, hint), status) }
			const accessCount = `SELECT count(*) FROM "oauthAccessToken" WHERE "id"=?`
			const refreshCount = `SELECT count(*) FROM "oauthRefreshToken" WHERE "id"=?`
			revoke("Other", "at_standalone", "", 200)
			revoke("Reports", "at_STANDALONE", "", 200)
			revoke("reports", "at_standalone", "", 401)
			revoke("Reports", "rt_key-error", "refresh_token", 500)
			revoke("Reports", "rt_invalid", "refresh_token", 200)
			count(1, accessCount, "standalone")
			access("linked", "Reports", "old")
			revoke("Reports", "at_linked", "", 200)
			count(0, accessCount, "linked")
			count(1, refreshCount, "old")
			access("looks.like.jwt", "Reports", nil)
			revoke("Reports", "at_looks.like.jwt", "", 200)
			count(0, accessCount, "looks.like.jwt")
			duringHash = func() { write(`UPDATE "oauthClient" SET "clientSecret"='rotated' WHERE "id"='first'`) }
			revoke("Reports", "at_standalone", "", 401)
			write(`UPDATE "oauthClient" SET "clientSecret"='saved' WHERE "id"='first'`)
			duringHash = func() { write(`UPDATE "oauthClient" SET "disabled"=TRUE WHERE "id"='first'`) }
			revoke("Reports", "at_standalone", "", 401)
			write(`UPDATE "oauthClient" SET "disabled"=FALSE WHERE "id"='first'`)
			duringHash = nil
			count(1, accessCount, "standalone")
			// A dependent application row can reject the linked-token deletion
			// after the refresh row was updated. Both writes must roll back.
			write(`CREATE TABLE "revocationGuard" ("tokenId" VARCHAR(36) NOT NULL, FOREIGN KEY ("tokenId") REFERENCES "oauthAccessToken" ("id"))`)
			defer func() { _, _ = peer.db.ExecContext(ctx, peer.bind(`DROP TABLE IF EXISTS "revocationGuard"`)) }()
			write(`INSERT INTO "revocationGuard" ("tokenId") VALUES ('old')`)
			revoke("Reports", "rt_wrapped.old", "refresh_token", 500)
			count(1, `SELECT count(*) FROM "oauthRefreshToken" WHERE "id"='old' AND "revoked" IS NULL`)
			count(1, accessCount, "old")
			write(`DELETE FROM "revocationGuard" WHERE "tokenId"='old'`)
			// Two independent pools racing to revoke the same refresh token
			// must serialize the first revocation and the subsequent family cleanup.
			start := make(chan struct{})
			responses := make(chan *httptest.ResponseRecorder, 2)
			for _, h := range []*auth.Auth{host, otherHost} {
				go func() { <-start; responses <- send(h, "Reports", "rt_wrapped.old", "access_token") }()
			}
			close(start)
			expect(<-responses, 200)
			expect(<-responses, 200)
			for _, id := range []string{"old", "new"} {
				count(0, refreshCount, id)
				count(0, accessCount, id)
			}
			for _, id := range []string{"other-user", "other-client"} {
				count(1, refreshCount, id)
				count(1, accessCount, id)
			}
			count(1, accessCount, "standalone")
			revoke("Reports", "at_standalone", "refresh_token", 200)
			revoke("Reports", "at_standalone", "", 200)
			count(0, accessCount, "standalone")
			duringHash = func() {
				write(`DELETE FROM "oauthClient" WHERE "id"='first'`)
				addClient("replacement", "Reports")
				access("replacement-token", "Reports", nil)
			}
			revoke("Reports", "at_replacement-token", "", 401)
			count(1, accessCount, "replacement-token")
		})
	}
}
