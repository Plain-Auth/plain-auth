package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestOAuthClientDeletion(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			wantStatus := func(err error, status int) {
				t.Helper()
				var e *auth.APIError
				if !errors.As(err, &e) || e.Status != status {
					t.Fatalf("want HTTP %d, got %v", status, err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			open := func() *Store {
				t.Helper()
				s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider", "admin"}, schema.Options{})
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
			var transferDuringLookup bool
			plugin, err := op.New(op.Options{ClientReference: func(context.Context, op.RegistrationAccess) (string, error) {
				if transferDuringLookup {
					write(`UPDATE "oauthClient" SET "referenceId"='new-team' WHERE "clientId"='team-app'`)
				}
				return "Team", nil
			}})
			must(err)
			const origin = "https://deletion.example.test"
			h, err := auth.New(auth.Options{BaseURL: origin, Store: s, Secret: strings.Repeat("s", 40), Plugins: []auth.Plugin{plugin}, EmailAndPassword: true})
			must(err)
			sdk, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
			must(err)
			account, err := sdk.SignUpEmail(ctx, client.SignUpRequest{Email: "owner@deletion.test", Name: "owner", Password: "local deletion password"})
			must(err)
			owner := account.User.ID
			now := time.Now().UTC().Truncate(time.Millisecond)
			write(`INSERT INTO "oauthResource" ("id","identifier","name") VALUES ('resource','urn:reports','Reports')`)
			for _, id := range []string{"remove", "keep"} {
				write(`INSERT INTO "oauthClient" ("id","clientId","userId","redirectUris") VALUES (?,?,?,?)`, id, id, owner, "[]")
				write(`INSERT INTO "oauthConsent" ("id","clientId","userId","scopes","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`, id, id, owner, "[]", now, now)
				write(`INSERT INTO "oauthClientResource" ("id","clientId","resourceId") VALUES (?,?,'urn:reports')`, id, id)
				write(`INSERT INTO "oauthRefreshToken" ("id","clientId","userId","token","scopes","createdAt","expiresAt") VALUES (?,?,?,?,?,?,?)`, id, id, owner, id, "[]", now, now.Add(time.Hour))
				write(`INSERT INTO "oauthAccessToken" ("id","clientId","refreshId","token","scopes","createdAt","expiresAt") VALUES (?,?,?,?,?,?,?)`, id, id, id, id, "[]", now, now.Add(time.Hour))
			}
			checkRows := func(id string, want int) {
				t.Helper()
				for _, table := range []string{"oauthClient", "oauthConsent", "oauthClientResource", "oauthAccessToken", "oauthRefreshToken"} {
					var n int
					must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT COUNT(*) FROM "`+table+`" WHERE "clientId"=?`), id).Scan(&n))
					if n != want {
						t.Fatalf("%s rows for %s: got %d, want %d", table, id, n, want)
					}
				}
			}
			write(`UPDATE "session" SET "impersonatedBy"='administrator' WHERE "userId"=?`, owner)
			wantStatus(sdk.DeleteOAuthClient(ctx, "remove"), 403)
			checkRows("remove", 1)
			write(`UPDATE "session" SET "impersonatedBy"=NULL WHERE "userId"=?`, owner)
			must(sdk.DeleteOAuthClient(ctx, "remove"))
			checkRows("remove", 0)
			checkRows("keep", 1)
			wantStatus(sdk.DeleteOAuthClient(ctx, "remove"), 404)
			var resourceName string
			must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT "name" FROM "oauthResource" WHERE "identifier"=?`), "urn:reports").Scan(&resourceName))
			if resourceName != "Reports" {
				t.Fatal("client deletion changed the underlying resource")
			}
			write(`INSERT INTO "oauthClient" ("id","clientId","referenceId","redirectUris") VALUES ('tenant','team-app','Team','[]')`)
			transferDuringLookup = true
			wantStatus(sdk.DeleteOAuthClient(ctx, "team-app"), 401)
			transferDuringLookup = false
			// The former tenant has lost ownership during the preceding request.
			wantStatus(sdk.DeleteOAuthClient(ctx, "team-app"), 401)
			if err := peer.DeleteOAuthClient(ctx, "team-app", "", "NEW-TEAM"); !errors.Is(err, auth.StatusOnlyError(401)) {
				t.Fatalf("case-variant tenant deletion: %v", err)
			}
			must(peer.DeleteOAuthClient(ctx, "team-app", "", "new-team"))
			// Independent database handles competing for the same registration can delete it once.
			start := make(chan struct{})
			results := make(chan error, 2)
			for _, db := range []*Store{s, peer} {
				go func() {
					<-start
					results <- db.DeleteOAuthClient(ctx, "keep", owner, "")
				}()
			}
			close(start)
			a, b := <-results, <-results
			if !(a == nil && errors.Is(b, op.ErrClientNotFound) || b == nil && errors.Is(a, op.ErrClientNotFound)) {
				t.Fatalf("concurrent deletion outcomes: %v, %v", a, b)
			}
			checkRows("keep", 0)
		})
	}
}
