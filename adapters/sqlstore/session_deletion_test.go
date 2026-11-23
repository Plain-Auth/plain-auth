package sqlstore

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth/schema"
)

func TestSessionDeletionRevokesOAuthGrants(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			core, err := Open(ctx, dialect, dsn)
			must(err)
			t.Cleanup(func() { core.Close() })
			now := time.Now().UTC().Truncate(time.Second)
			issued, until := core.date(now), core.date(now.Add(time.Hour))
			prior := now.Add(-time.Hour)
			write := func(q string, args ...any) {
				t.Helper()
				_, err := core.db.ExecContext(ctx, core.bind(q), args...)
				must(err)
			}
			session := func(id string) {
				t.Helper()
				write(`INSERT INTO "session" ("id","userId","token","createdAt","updatedAt","expiresAt") VALUES (?,'owner',?,?,?,?)`, id, id+"-token", issued, issued, until)
			}
			write(`INSERT INTO "user" ("id","email","name","emailVerified","createdAt","updatedAt") VALUES ('owner','owner@example.test','Owner',?,?,?)`, true, issued, issued)
			session("early")
			must(core.DeleteSession(ctx, "early-token"))
			peer, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { peer.Close() })
			write(`INSERT INTO "oauthClient" ("id","clientId","redirectUris") VALUES ('app','app','[]')`)
			session("first")
			session("second")
			session("keep")
			refresh := `INSERT INTO "oauthRefreshToken" ("id","token","clientId","userId","sessionId","scopes","revoked","createdAt","expiresAt") VALUES (?,?,'app','owner',?,?,?,?,?)`
			access := `INSERT INTO "oauthAccessToken" ("id","token","clientId","sessionId","scopes","revoked","createdAt","expiresAt") VALUES (?,?,'app',?,'[]',?,?,?)`
			for _, r := range []struct {
				id      string
				session any
				scopes  string
				prior   any
			}{
				{"online", "first", `[]`, nil}, {"offline", "first", `["read","offline_access"]`, nil},
				{"near", "second", `["OFFLINE_ACCESS","offline_access_extra"]`, nil},
				{"old", "second", `["offline_access"]`, core.date(prior)}, {"unrelated", "keep", `[]`, nil}, {"device", nil, `[]`, nil},
			} {
				write(refresh, r.id, r.id, r.session, r.scopes, r.prior, issued, until)
			}
			write(access, "access", "access", "first", nil, issued, until)
			write(access, "previous", "previous", "first", core.date(prior), issued, until)
			write(access, "machine", "machine", nil, nil, issued, until)
			state := func(table, id, sid string, revoked bool, previous bool) {
				t.Helper()
				var actualSession sql.NullString
				var at sql.NullTime
				q := `SELECT "sessionId","revoked" FROM "` + table + `" WHERE "id"=?`
				must(peer.db.QueryRowContext(ctx, peer.bind(q), id).Scan(&actualSession, &at))
				if actualSession.String != sid || at.Valid != revoked || previous && !at.Time.Equal(prior) {
					t.Fatalf("%s/%s session=%v revoked=%v", table, id, actualSession, at)
				}
			}
			const rt, at = "oauthRefreshToken", "oauthAccessToken"
			// A failed enclosing operation must preserve both the session and its grants.
			tx, err := core.db.BeginTx(ctx, nil)
			must(err)
			n, err := core.deleteSessionsTx(ctx, tx, `"id"=?`, "first")
			must(err)
			if n != 1 {
				t.Fatal("unexpected deletion count", n)
			}
			must(tx.Rollback())
			must(core.DeleteUserSession(ctx, "different-owner", "first-token"))
			must(core.DeleteExpiredSession(ctx, "first-token", now))
			state(at, "access", "first", false, false)
			state(rt, "online", "first", false, false)
			must(core.DeleteOtherSessions(ctx, "owner", "keep-token"))
			must(core.DeleteOtherSessions(ctx, "owner", "keep-token"))
			state(at, "access", "", true, false)
			state(at, "previous", "", true, true)
			state(at, "machine", "", false, false)
			state(rt, "online", "", true, false)
			state(rt, "offline", "", false, false)
			state(rt, "near", "", true, false)
			state(rt, "old", "", true, true)
			state(rt, "unrelated", "keep", false, false)
			state(rt, "device", "", false, false)

			// Exercise both the session and refresh-token parameter batches in one logout.
			bulk, err := core.db.BeginTx(ctx, nil)
			must(err)
			defer bulk.Rollback()
			for i := range 405 {
				id := fmt.Sprintf("bulk-%03d", i)
				_, err := bulk.ExecContext(ctx, core.bind(`INSERT INTO "session" ("id","userId","token","createdAt","updatedAt","expiresAt") VALUES (?,'owner',?,?,?,?)`), id, id, issued, issued, until)
				must(err)
				_, err = bulk.ExecContext(ctx, core.bind(refresh), id, id, "bulk-000", "[]", nil, issued, until)
				must(err)
				_, err = bulk.ExecContext(ctx, core.bind(access), id, id, id, nil, issued, until)
				must(err)
			}
			must(bulk.Commit())
			must(core.DeleteOtherSessions(ctx, "owner", "keep-token"))
			for _, table := range []string{at, rt} {
				var count int
				q := `SELECT COUNT(*) FROM "` + table + `" WHERE "id" LIKE 'bulk-%' AND "sessionId" IS NULL AND "revoked" IS NOT NULL`
				must(peer.db.QueryRowContext(ctx, peer.bind(q)).Scan(&count))
				if count != 405 {
					t.Fatal(table, "revoked bulk grants", count)
				}
			}

			// Both successful orders of a racing insert and logout are safe.
			for i := range 6 {
				id := fmt.Sprintf("race-%d", i)
				session(id)
				start := make(chan struct{})
				done := make(chan error, 1)
				go func() {
					<-start
					_, err := peer.db.ExecContext(ctx, peer.bind(access), id, id, id, nil, issued, until)
					done <- err
				}()
				close(start)
				must(core.DeleteSession(ctx, id+"-token"))
				insertErr := <-done
				if insertErr == nil {
					state(at, id, "", true, false)
				} else {
					var count int
					must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT COUNT(*) FROM "oauthAccessToken" WHERE "id"=?`), id).Scan(&count))
					if count != 0 {
						t.Fatal("failed grant insert left a row", insertErr)
					}
				}
			}
		})
	}
}
