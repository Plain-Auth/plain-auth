package sqlstore

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Plain-Auth/plain-auth/schema"
)

func TestOAuthProviderSchema(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			open := func(profiles ...string) *Store {
				t.Helper()
				store, err := OpenWithOptions(ctx, dialect, dsn, profiles, schema.Options{})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { store.Close() })
				return store
			}
			s := open()
			exec := func(query string, args ...any) error {
				_, err := s.db.ExecContext(ctx, s.bind(query), args...)
				return err
			}
			write := func(query string, args ...any) {
				t.Helper()
				if err := exec(query, args...); err != nil {
					t.Fatal(err)
				}
			}
			reject := func(query string, args ...any) {
				t.Helper()
				if err := exec(query, args...); err == nil {
					t.Fatalf("expected a constraint to reject %s", query)
				}
			}
			count := func(want int, query string, args ...any) {
				t.Helper()
				var n int
				if err := s.db.QueryRowContext(ctx, s.bind(query), args...).Scan(&n); err != nil || n != want {
					t.Fatalf("%s: got %d, want %d, error %v", query, n, want, err)
				}
			}
			now := time.Now().UTC().Truncate(time.Millisecond)
			write(`INSERT INTO "user" ("id","email","name","emailVerified","createdAt","updatedAt") VALUES ('owner','owner@example.test','Owner',?,?,?)`, true, now, now)
			write(`INSERT INTO "session" ("id","userId","token","createdAt","updatedAt","expiresAt") VALUES ('session','owner','session-token',?,?,?)`, now, now, now.Add(time.Hour))
			profiles := []string{"oauth-provider", "jwt", "device-authorization"}
			s = open(profiles...)
			findings, err := CheckSchema(ctx, dialect, dsn, profiles)
			if err != nil || len(findings) != 0 {
				t.Fatal("schema check", findings, err)
			}

			// Public client and resource identifiers may be longer than internal row IDs.
			client := strings.Repeat("c", 252) + "App"
			const origin = "https://api.example.test/"
			resource := origin + strings.Repeat("r", 255-len(origin))
			const clientRow = `INSERT INTO "oauthClient" ("id","clientId","userId","redirectUris") VALUES (?,?,?,?)`
			write(clientRow, "client-row", client, "owner", `["https://app.example.test/callback"]`)
			reject(clientRow, "duplicate", client, "owner", `[]`)
			write(clientRow, "other-client", strings.ToLower(client), nil, `[]`)
			const resourceRow = `INSERT INTO "oauthResource" ("id","identifier","name","allowedScopes","customClaims","policyVersion") VALUES (?,?,?,?,?,?)`
			write(resourceRow, "api", resource, "API", `["read"]`, `{"tier":"trial"}`, 1)
			reject(resourceRow, "duplicate", resource, "Other", nil, nil, nil)
			const linkRow = `INSERT INTO "oauthClientResource" ("id","clientId","resourceId") VALUES (?,?,?)`
			write(linkRow, "link", client, resource)
			reject(linkRow, "duplicate", client, resource)
			reject(linkRow, "orphan", client, "missing-resource")
			const refreshRow = `INSERT INTO "oauthRefreshToken" ("id","token","clientId","userId","sessionId","expiresAt","createdAt","scopes","confirmation") VALUES (?,?,?,'owner','session',?,?,?,?)`
			write(refreshRow, "refresh", "refresh-value", client, now.Add(time.Hour), now, `["read"]`, `{"jkt":"thumbprint"}`)
			reject(refreshRow, "duplicate", "refresh-value", client, now.Add(time.Hour), now, `[]`, nil)
			const accessRow = `INSERT INTO "oauthAccessToken" ("id","token","clientId","sessionId","refreshId","expiresAt","createdAt","scopes") VALUES (?,?,?,?,?,?,?,?)`
			write(accessRow, "access", "OpaqueToken", client, "session", "refresh", now.Add(time.Hour), now, `["read"]`)
			reject(accessRow, "duplicate", "OpaqueToken", client, nil, nil, now.Add(time.Hour), now, `[]`)
			write(accessRow, "machine", "opaquetoken", client, nil, nil, now.Add(time.Hour), now, `[]`)
			const consentRow = `INSERT INTO "oauthConsent" ("id","clientId","userId","scopes","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`
			write(consentRow, "consent", client, "owner", `["read"]`, now, now)
			reject(consentRow, "orphan", "missing-client", "owner", `[]`, now, now)
			const assertionRow = `INSERT INTO "oauthClientAssertion" ("id","expiresAt") VALUES (?,?)`
			write(assertionRow, "assertion-digest", now.Add(time.Hour))

			if dialect == "mysql" {
				write(`ALTER TABLE "oauthClientResource" DROP FOREIGN KEY "oauthClientResource_resourceId_fk"`)
			}
			before := s
			s = open(profiles...)
			count(1, `SELECT COUNT(*) FROM "user" WHERE "id"='owner'`)
			count(1, `SELECT COUNT(*) FROM "session" WHERE "id"='session'`)
			reject(assertionRow, "assertion-digest", now.Add(time.Hour))
			// Independent processes inserting the same assertion can claim it only once.
			results := make(chan error, 2)
			start := make(chan struct{})
			for _, store := range []*Store{before, s} {
				go func() {
					<-start
					_, err := store.db.ExecContext(ctx, store.bind(assertionRow), "racing-digest", now.Add(time.Hour))
					results <- err
				}()
			}
			close(start)
			first, second := <-results, <-results
			if (first == nil) == (second == nil) {
				t.Fatalf("expected one recorded assertion: %v, %v", first, second)
			}
			var raw []byte
			var scopes []string
			if err := s.db.QueryRowContext(ctx, s.bind(`SELECT "scopes" FROM "oauthConsent" WHERE "id"='consent'`)).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &scopes); err != nil || !slices.Equal(scopes, []string{"read"}) {
				t.Fatal("consent scopes after migration", scopes, err)
			}
			reject(linkRow, "orphan", client, "missing-resource")
			write(`DELETE FROM "oauthResource" WHERE "id"='api'`)
			count(0, `SELECT COUNT(*) FROM "oauthClientResource"`)
			write(`DELETE FROM "session" WHERE "id"='session'`)
			count(1, `SELECT COUNT(*) FROM "oauthRefreshToken" WHERE "id"='refresh' AND "sessionId" IS NULL`)
			count(1, `SELECT COUNT(*) FROM "oauthAccessToken" WHERE "id"='access' AND "sessionId" IS NULL`)
			write(`DELETE FROM "oauthRefreshToken" WHERE "id"='refresh'`)
			count(0, `SELECT COUNT(*) FROM "oauthAccessToken" WHERE "id"='access'`)
			count(1, `SELECT COUNT(*) FROM "oauthAccessToken" WHERE "id"='machine'`)
			write(`DELETE FROM "user" WHERE "id"='owner'`)
			count(0, `SELECT COUNT(*) FROM "oauthConsent"`)
			count(0, `SELECT COUNT(*) FROM "oauthAccessToken"`)
			count(1, `SELECT COUNT(*) FROM "oauthClient" WHERE "id"='other-client'`)
			count(2, `SELECT COUNT(*) FROM "oauthClientAssertion"`)
			if dialect == "mysql" {
				write(`ALTER TABLE "oauthConsent" DROP FOREIGN KEY "oauthConsent_clientId_fk"`)
				write(`ALTER TABLE "oauthConsent" ADD CONSTRAINT "wrong_consent_key" FOREIGN KEY ("clientId") REFERENCES "oauthClient" ("clientId") ON DELETE RESTRICT`)
				store, err := OpenWithOptions(ctx, dialect, dsn, profiles, schema.Options{})
				if err == nil {
					store.Close()
					t.Fatal("accepted an incompatible grant deletion rule")
				}
				if !strings.Contains(err.Error(), "incompatible target or delete rule") {
					t.Fatal(err)
				}
			}
		})
	}
}
