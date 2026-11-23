package sqlstore

import (
	"errors"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestSessionTransferAfterAdminMigration(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			db, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			now := time.Now().UTC().Truncate(time.Millisecond)
			user := auth.User{ID: "transfer-owner", Email: "transfer@example.test", CreatedAt: now, UpdatedAt: now}
			row := auth.StoredSession{Session: auth.Session{ID: "transfer-session", UserID: user.ID, Token: "transfer-original", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			if err = db.CreateUser(ctx, user, "", &row); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"delegated", "banned", "valid"} {
				if err = db.SaveOneTimeToken(ctx, key, row.Session, now, now.Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"admin"})
			if err != nil {
				t.Fatal(err)
			}
			configured, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer configured.Close()
			set := func(q string, args ...any) {
				t.Helper()
				if _, e := configured.db.ExecContext(ctx, configured.bind(q), args...); e != nil {
					t.Fatal(e)
				}
			}
			denied := func(k string) {
				t.Helper()
				if _, err := db.ConsumeOneTimeToken(ctx, k, now); !errors.Is(err, auth.ErrTransferSessionMissing) {
					t.Fatal("rejected session transfer returned an unexpected result", k, err)
				}
				if _, err := db.ConsumeOneTimeToken(ctx, k, now); !errors.Is(err, auth.ErrNotFound) {
					t.Fatal("administrative denial did not consume transfer", k, err)
				}
				if err := db.SaveOneTimeToken(ctx, "new-"+k, row.Session, now, now.Add(time.Minute)); err == nil {
					t.Fatal("restricted session issued a transfer", k)
				}
			}
			set(`UPDATE "session" SET "impersonatedBy"=? WHERE "id"=?`, "administrator", row.ID)
			denied("delegated")
			set(`UPDATE "session" SET "impersonatedBy"=NULL WHERE "id"=?`, row.ID)
			set(`UPDATE "user" SET "banned"=? WHERE "id"=?`, true, user.ID)
			denied("banned")
			set(`UPDATE "user" SET "banned"=? WHERE "id"=?`, false, user.ID)
			result, err := db.ConsumeOneTimeToken(ctx, "valid", now)
			if err != nil || result.Session.ID != row.ID || result.User.ID != user.ID {
				t.Fatal("valid direct owner could not transfer session", err)
			}
		})
	}
}
