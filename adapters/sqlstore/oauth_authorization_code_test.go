package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/schema"
	"golang.org/x/oauth2"
)

func TestAuthorizationCodeRedemption(t *testing.T) {
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
				_, err := s.db.ExecContext(ctx, s.bind(q), args...)
				must(err)
			}
			count := func(q string, args ...any) int {
				t.Helper()
				var n int
				must(s.db.QueryRowContext(ctx, s.bind(q), args...).Scan(&n))
				return n
			}
			hash := func(raw string) string {
				sum := sha256.Sum256([]byte(raw))
				return base64.RawURLEncoding.EncodeToString(sum[:])
			}
			var collision atomic.Bool
			p, err := op.New(op.Options{Tokens: op.TokenOptions{
				AccessLifetime:        2 * time.Minute,
				HashAuthorizationCode: func(_ context.Context, raw string) (string, error) { return "code-" + hash(raw), nil },
				GenerateOpaqueToken: func(context.Context) (string, error) {
					if collision.Load() {
						return "collision", nil
					}
					return rand.Text(), nil
				},
			}})
			must(err)
			const origin = "https://issuer.example.test"
			host := func(store *Store) *auth.Auth {
				t.Helper()
				off := false
				h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("a", 40), Store: store, Plugins: []auth.Plugin{p}, RateLimit: &off})
				must(err)
				return h
			}
			first, second := host(s), host(peer)
			now := time.Now().UTC().Truncate(time.Second)
			until := now.Add(time.Hour)
			write(`INSERT INTO "user" ("id","email","name","emailVerified","createdAt","updatedAt") VALUES ('u','pkce@example.test','U',?,?,?)`, true, s.date(now), s.date(now))
			write(`INSERT INTO "session" ("id","token","userId","createdAt","updatedAt","expiresAt") VALUES ('sid','browser','u',?,?,?)`, s.date(now), s.date(now), s.date(until))
			for _, id := range []string{"client", "other"} {
				write(`INSERT INTO "oauthClient" ("id","clientId","tokenEndpointAuthMethod","redirectUris","scopes","requirePKCE") VALUES (?,?,'none',?,?,?)`, id, id, "[]", `["reports"]`, false)
			}
			verifier := strings.Repeat("a", 64)
			value := func(owner, session string) string {
				b, err := json.Marshal(map[string]any{"type": "authorization_code", "userId": owner, "sessionId": session, "referenceId": "tenant", "query": map[string]any{
					"client_id": "client", "scope": "reports", "code_challenge": hash(verifier), "code_challenge_method": "S256",
				}})
				must(err)
				return string(b)
			}
			seed := func(raw, blob string, created, expires time.Time) {
				t.Helper()
				write(`INSERT INTO "verification" ("id","identifier","value","createdAt","updatedAt","expiresAt") VALUES (?,?,?,?,?,?)`, rand.Text(), "code-"+hash(raw), blob, s.date(created), s.date(created), s.date(expires))
			}
			call := func(h *auth.Auth, raw, client, redirect, verifier string) *httptest.ResponseRecorder {
				form := url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "code": {raw}, "code_verifier": {verifier}}
				if redirect != "" {
					form.Set("redirect_uri", redirect)
				}
				req := httptest.NewRequest("POST", origin+"/api/auth/oauth2/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				return out
			}
			check := func(out *httptest.ResponseRecorder, status int, code string) {
				t.Helper()
				var reply struct {
					Error     string
					ExpiresIn int64 `json:"expires_in"`
				}
				must(json.Unmarshal(out.Body.Bytes(), &reply))
				if out.Code != status || reply.Error != code || status == 200 && reply.ExpiresIn != 120 {
					t.Fatalf("status=%d body=%s", out.Code, out.Body.String())
				}
			}
			valid := value("u", "sid")
			seed("fresh", valid, now, until)
			check(call(first, "fresh", "client", "", ""), 400, "invalid_request")
			check(call(first, "fresh", "other", "", verifier), 400, "invalid_grant")
			check(call(first, "fresh", "client", "https://example.test/cb", verifier), 400, "invalid_grant")
			check(call(first, "fresh", "client", "", "wrong"), 400, "invalid_grant")
			write(`UPDATE "oauthClient" SET "scopes"=? WHERE "id"='client'`, "[]")
			check(call(first, "fresh", "client", "", verifier), 400, "invalid_scope")
			write(`UPDATE "oauthClient" SET "scopes"=? WHERE "id"='client'`, `["reports"]`)
			write(`UPDATE "session" SET "expiresAt"=? WHERE "id"='sid'`, s.date(now))
			check(call(first, "fresh", "client", "", verifier), 400, "invalid_request")
			write(`UPDATE "session" SET "expiresAt"=? WHERE "id"='sid'`, s.date(until))
			// An older corrupt duplicate cannot replace the newest value.
			seed("fresh", "{}", now.Add(-time.Hour), until)
			check(call(first, "fresh", "client", "", verifier), 200, "")
			if n := count(`SELECT COUNT(*) FROM "verification" WHERE "identifier"=?`, "code-"+hash("fresh")); n != 0 {
				t.Fatal("duplicates remain", n)
			}
			check(call(second, "fresh", "other", "", verifier), 400, "invalid_grant")
			if n := count(`SELECT COUNT(*) FROM "oauthAccessToken" WHERE "referenceId"='tenant'`); n != 1 {
				t.Fatal("unrelated client affected grant", n)
			}
			seed("bad-user", value("missing", "sid"), now, until)
			check(call(first, "bad-user", "client", "", verifier), 400, "invalid_user")
			seed("expired", valid, now.Add(-time.Hour), now)
			check(call(first, "expired", "client", "", verifier), 400, "invalid_grant")
			seed("bad-shape", "{}", now, until)
			check(call(first, "bad-shape", "client", "", verifier), 400, "invalid_grant")
			// An insert failure must roll back code consumption.
			collision.Store(true)
			seed("reserved", valid, now, until)
			check(call(first, "reserved", "client", "", verifier), 200, "")
			seed("retried", valid, now, until)
			if out := call(first, "retried", "client", "", verifier); out.Code != 500 {
				t.Fatalf("expected insertion failure, got %d", out.Code)
			}
			collision.Store(false)
			check(call(second, "retried", "client", "", verifier), 200, "")
			seed("race", valid, now, until)
			// Model an earlier refresh descendant and verify cleanup commits even
			// though the losing HTTP request returns invalid_grant.
			write(`INSERT INTO "oauthRefreshToken" ("id","clientId","userId","sessionId","authorizationCodeId","token","createdAt","expiresAt","scopes") VALUES ('descendant','client','u','sid',?,'digest',?,?,?)`, "code-"+hash("race"), s.date(now), s.date(until), `["offline_access"]`)
			results := make(chan *httptest.ResponseRecorder, 2)
			start := make(chan struct{})
			for _, h := range []*auth.Auth{first, second} {
				go func() { <-start; results <- call(h, "race", "client", "", verifier) }()
			}
			close(start)
			a, b := <-results, <-results
			if b.Code == 200 {
				a, b = b, a
			}
			check(a, 200, "")
			check(b, 400, "invalid_grant")
			if n := count(`SELECT COUNT(*) FROM "oauthAccessToken" WHERE "authorizationCodeId"=?`, "code-"+hash("race")); n != 0 {
				t.Fatal("replay left access tokens", n)
			}
			if n := count(`SELECT COUNT(*) FROM "oauthRefreshToken" WHERE "id"='descendant'`); n != 0 {
				t.Fatal("replay left refresh tokens", n)
			}
			if n := count(`SELECT COUNT(*) FROM "oauthAccessToken"`); n != 3 {
				t.Fatal("unexpected surviving grants", n)
			}
			seed("go-client", valid, now, until)
			server := httptest.NewServer(first)
			t.Cleanup(server.Close)
			cfg := oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{
				TokenURL: server.URL + "/api/auth/oauth2/token", AuthStyle: oauth2.AuthStyleInParams,
			}}
			token, err := cfg.Exchange(ctx, "go-client", oauth2.VerifierOption(verifier))
			must(err)
			if !token.Valid() || token.Extra("scope") != "reports" {
				t.Fatal("Go OAuth client received an unusable delegated token")
			}
			t.Run("offline", func(t *testing.T) {
				testOfflineCodeTransactions(t, s, peer, verifier, now)
			})
		})
	}
}
