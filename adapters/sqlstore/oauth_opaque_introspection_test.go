package sqlstore

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Plain-Auth/plain-auth/schema"
)

func TestOpaqueIntrospectionResourceSnapshot(t *testing.T) {
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
			first, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { first.Close() })
			peer, err := Open(ctx, dialect, dsn)
			must(err)
			t.Cleanup(func() { peer.Close() })
			write := func(q string, args ...any) {
				t.Helper()
				_, err := peer.db.ExecContext(ctx, peer.bind(q), args...)
				must(err)
			}
			for _, id := range []string{"app", "api", "other"} {
				write(`INSERT INTO "oauthClient" ("id","clientId","redirectUris") VALUES (?,?,?)`, id, id, `["https://client.example.test/cb"]`)
			}
			now := time.Now().UTC().Truncate(time.Second)
			issued, until := peer.date(now), peer.date(now.Add(time.Hour))
			write(`INSERT INTO "user" ("id","email","name","emailVerified","createdAt","updatedAt") VALUES ('user','u@example.test','U',?,?,?)`, true, issued, issued)
			write(`INSERT INTO "session" ("id","token","userId","createdAt","updatedAt","expiresAt") VALUES ('sid','cookie','user',?,?,?)`, issued, issued, until)
			write(`UPDATE "oauthClient" SET "subjectType"='pairwise' WHERE "id"='app'`)
			write(`INSERT INTO "oauthAccessToken" ("id","token","clientId","userId","sessionId","scopes","resources","createdAt","expiresAt") VALUES ('grant','Digest','app','user','sid',?,?,?,?)`, `["openid"]`, `["urn:one","urn:two"]`, issued, until)
			const userInfo = "https://host.example.test/api/auth/oauth2/userinfo"
			resource := `INSERT INTO "oauthResource" ("id","identifier","name","customClaims","disabled") VALUES (?,?,?,?,?)`
			write(resource, "1", "urn:one", "One", `{"level":1}`, false)
			write(resource, "2", "urn:two", "Two", `{"level":2,"linked":true}`, true)
			link := `INSERT INTO "oauthClientResource" ("id","clientId","resourceId") VALUES ('link','api','urn:two')`
			write(link)
			check := func(caller string, active bool) {
				t.Helper()
				c, r, known, err := first.InspectOpaqueAccessToken(ctx, caller, "Digest", userInfo)
				must(err)
				if !known || c.ClientID != caller || (r != nil) != active {
					t.Fatalf("unexpected grant state for %q: known=%t active=%t", caller, known, r != nil)
				}
				if r != nil && (r.ClientID != "app" || r.UserID != "user" || r.SubjectType != "pairwise" || !slices.Equal(r.RedirectURIs, []string{"https://client.example.test/cb"})) {
					t.Fatal("incorrect issuing client identity", r)
				}
			}
			check("api", true)
			check("other", false)
			check("app", true)
			_, _, known, err := first.InspectOpaqueAccessToken(ctx, "api", "digest", userInfo)
			must(err)
			if known {
				t.Fatal("matched different digest")
			}
			_, record, _, err := first.InspectOpaqueAccessToken(ctx, "api", "Digest", userInfo)
			must(err)
			if record == nil || string(record.ResourceClaims["level"]) != "2" || record.SessionID != "sid" {
				t.Fatal("claim merge or session mismatch", record)
			}

			// Alternate two committed states: a linked API for an issued grant,
			// or no link and a grant issued to a different application. A reader
			// must never return the second issuer to the API using the first link.
			change := func(linked bool) error {
				tx, err := peer.db.BeginTx(ctx, nil)
				if err != nil {
					return err
				}
				defer tx.Rollback()
				id, changeLink := "other", `DELETE FROM "oauthClientResource" WHERE "id"='link'`
				if linked {
					id, changeLink = "app", link
				}
				if _, err = tx.ExecContext(ctx, peer.bind(`UPDATE "oauthAccessToken" SET "clientId"=? WHERE "id"='grant'`), id); err != nil {
					return err
				}
				if _, err = tx.ExecContext(ctx, peer.bind(changeLink)); err != nil {
					return err
				}
				return tx.Commit()
			}
			done := make(chan error, 1)
			go func() {
				for i := range 40 {
					if err := change(i%2 == 1); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			var inconsistent bool
			var readErr error
			for range 80 {
				_, r, known, err := first.InspectOpaqueAccessToken(ctx, "api", "Digest", userInfo)
				if err != nil {
					readErr = err
					break
				}
				if !known || r != nil && r.ClientID != "app" {
					inconsistent = true
					break
				}
			}
			must(<-done)
			must(readErr)
			if inconsistent {
				t.Fatal("combined a grant and client link from different commits")
			}
			write(`UPDATE "session" SET "expiresAt"=? WHERE "id"='sid'`, issued)
			check("api", false)
			write(`UPDATE "session" SET "expiresAt"=? WHERE "id"='sid'`, until)
			write(`UPDATE "oauthClient" SET "disabled"=TRUE WHERE "id"='app'`)
			check("api", false)
			write(`UPDATE "oauthClient" SET "disabled"=FALSE WHERE "id"='app'`)
			for _, n := range []int{64, 65} {
				list := make([]string, n)
				for i := range list {
					list[i] = "urn:two"
				}
				raw, err := json.Marshal(list)
				must(err)
				write(`UPDATE "oauthAccessToken" SET "resources"=? WHERE "id"='grant'`, string(raw))
				check("api", n == 64)
			}
			for _, target := range []string{userInfo, strings.ToUpper("urn:two")} {
				raw, err := json.Marshal([]string{target})
				must(err)
				write(`UPDATE "oauthAccessToken" SET "resources"=? WHERE "id"='grant'`, string(raw))
				check("api", false)
				check("app", target == userInfo)
			}
			write(`UPDATE "oauthAccessToken" SET "resources"=? WHERE "id"='grant'`, `["urn:one","urn:two"]`)
			write(`DELETE FROM "oauthResource" WHERE "id"='1'`)
			check("api", false)
			check("app", false)
		})
	}
}
