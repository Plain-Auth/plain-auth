package sqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/schema"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func TestOAuthMachineToken(t *testing.T) {
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
			const id = "service:帳戶 +%/app"
			const raw = "shared:s +%é&="
			const prefix = "svc_"
			hash := func(v string) string {
				sum := sha256.Sum256([]byte(v))
				return hex.EncodeToString(sum[:])
			}
			var count atomic.Int64
			var beforeIssue func() error
			opts := op.Options{
				Registration: op.RegistrationOptions{SecretPrefix: prefix, VerifySecret: func(_ context.Context, supplied, stored string) (bool, error) {
					if supplied == "callback-error" {
						return false, errors.New("private comparison failure")
					}
					return stored == "custom:"+hash(supplied), nil
				}},
				Tokens: op.TokenOptions{MachineLifetime: 3 * time.Minute, ScopeLifetimes: map[string]time.Duration{"reports": 30 * time.Second}, OpaquePrefix: "at_",
					GenerateOpaqueToken: func(context.Context) (string, error) {
						if beforeIssue != nil {
							if err := beforeIssue(); err != nil {
								return "", err
							}
						}
						return "secret-" + strconv.FormatInt(count.Add(1), 10), nil
					},
					HashOpaqueToken: func(_ context.Context, value string) (string, error) { return hash(value), nil },
				},
			}
			const insert = `INSERT INTO "oauthClient" ("id","clientId","clientSecret","tokenEndpointAuthMethod","grantTypes","clientCredentialsScopes","scopes","redirectUris") VALUES (?,?,?,?,?,?,?,?)`
			seed := func(row string) {
				write(insert, row, id, "custom:"+hash(raw), "client_secret_basic", `["client_credentials"]`, `["reports","export"]`, `["email"]`, `[]`)
			}
			seed("first")
			p, err := op.New(opts)
			must(err)
			off := false
			const origin = "https://machine.example.test"
			host, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("s", 40), Store: s, Plugins: []auth.Plugin{p}, RateLimit: &off})
			must(err)
			httpContext := context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Transport: guestTransport{host}})
			fetch := func(secret string, style oauth2.AuthStyle, scopes ...string) (*oauth2.Token, error) {
				conf := clientcredentials.Config{ClientID: id, ClientSecret: secret, TokenURL: origin + "/api/auth/oauth2/token", AuthStyle: style, Scopes: scopes}
				return conf.Token(httpContext)
			}
			requireError := func(status int, code string, err error) {
				t.Helper()
				var r *oauth2.RetrieveError
				if !errors.As(err, &r) || r.Response.StatusCode != status || (code != "" && r.ErrorCode != code) {
					t.Fatalf("expected token endpoint %d %q; got %v", status, code, err)
				}
				if strings.Contains(string(r.Body), "private comparison") || strings.Contains(string(r.Body), "private generation") {
					t.Fatal("host callback detail exposed")
				}
			}
			total := func() int {
				t.Helper()
				var n int
				must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT COUNT(*) FROM "oauthAccessToken" WHERE "clientId"=?`), id).Scan(&n))
				return n
			}
			token, err := fetch(prefix+raw, oauth2.AuthStyleInHeader)
			must(err)
			if token.AccessToken != "at_secret-1" || token.Type() != "Bearer" || token.RefreshToken != "" || token.Extra("scope") != "reports export" {
				t.Fatal("unexpected client credentials response", token.Extra("scope"))
			}
			var stored string
			var scopes []byte
			var user, session, refresh *string
			var created, expires time.Time
			must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT "token","scopes","userId","sessionId","refreshId","createdAt","expiresAt" FROM "oauthAccessToken" WHERE "clientId"=?`), id).Scan(&stored, &scopes, &user, &session, &refresh, &created, &expires))
			var names []string
			must(json.Unmarshal(scopes, &names))
			if stored != hash("secret-1") || !slices.Equal(names, []string{"reports", "export"}) || user != nil || session != nil || refresh != nil || expires.Sub(created) != 30*time.Second {
				t.Fatal("machine token persistence or lifetime incorrect")
			}
			_, err = fetch("callback-error", oauth2.AuthStyleInHeader)
			requireError(401, "invalid_client", err)
			_, err = fetch(prefix+"callback-error", oauth2.AuthStyleInHeader)
			requireError(500, "", err)
			beforeIssue = func() error { return errors.New("private generation failure") }
			_, err = fetch(prefix+raw, oauth2.AuthStyleInHeader)
			requireError(500, "", err)
			beforeIssue = func() error {
				write(`UPDATE "oauthClient" SET "clientSecret"=? WHERE "clientId"=?`, "custom:"+hash("replacement"), id)
				return nil
			}
			_, err = fetch(prefix+raw, oauth2.AuthStyleInHeader)
			requireError(401, "invalid_client", err)
			write(`UPDATE "oauthClient" SET "clientSecret"=? WHERE "clientId"=?`, "custom:"+hash(raw), id)
			beforeIssue = func() error {
				write(`UPDATE "oauthClient" SET "clientCredentialsScopes"=? WHERE "clientId"=?`, `["export"]`, id)
				return nil
			}
			_, err = fetch(prefix+raw, oauth2.AuthStyleInHeader, "reports")
			requireError(400, "invalid_scope", err)
			beforeIssue = func() error {
				write(`UPDATE "oauthClient" SET "metadata"=? WHERE "clientId"=?`, `{"dpop_bound_access_tokens":true}`, id)
				return nil
			}
			_, err = fetch(prefix+raw, oauth2.AuthStyleInHeader)
			requireError(400, "invalid_dpop_proof", err)
			write(`UPDATE "oauthClient" SET "metadata"=NULL WHERE "clientId"=?`, id)
			beforeIssue = func() error { write(`UPDATE "oauthClient" SET "disabled"=? WHERE "clientId"=?`, true, id); return nil }
			_, err = fetch(prefix+raw, oauth2.AuthStyleInHeader)
			requireError(401, "invalid_client", err)
			if total() != 1 {
				t.Fatal("failed exchanges persisted access tokens")
			}
			write(`UPDATE "oauthClient" SET "disabled"=? WHERE "clientId"=?`, false, id)
			beforeIssue = func() error {
				write(`DELETE FROM "oauthClient" WHERE "clientId"=?`, id)
				seed("replacement")
				return nil
			}
			_, err = fetch(prefix+raw, oauth2.AuthStyleInHeader)
			requireError(401, "invalid_client", err)
			if total() != 0 {
				t.Fatal("replacement registration received a token for its predecessor")
			}
			beforeIssue = nil
			write(`UPDATE "oauthClient" SET "tokenEndpointAuthMethod"='client_secret_post' WHERE "clientId"=?`, id)
			token, err = fetch(prefix+raw, oauth2.AuthStyleInParams, "export")
			must(err)
			if token.Extra("scope") != "export" || token.Extra("expires_in") != float64(180) || !token.Valid() {
				t.Fatal("wrong single-scope lifetime")
			}
			const callers = 6
			results := make(chan error, callers)
			for range callers {
				go func() { _, e := fetch(prefix+raw, oauth2.AuthStyleInParams, "reports"); results <- e }()
			}
			for range callers {
				must(<-results)
			}
			if total() != callers+1 {
				t.Fatal("concurrent callers did not each receive a persisted access token")
			}
		})
	}
}
