package sqlstore

import (
	"database/sql"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth/schema"
)

func TestOrganizationRoleSchemaUpgrade(t *testing.T) {
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
			open := func(profiles ...string) *Store {
				t.Helper()
				store, err := OpenWithOptions(ctx, dialect, dsn, profiles, schema.Options{})
				must(err)
				t.Cleanup(func() { store.Close() })
				return store
			}
			base := open("organization-teams")
			now := time.Now().UTC().Truncate(time.Millisecond)
			for _, id := range []string{"north", "south"} {
				_, err := base.db.ExecContext(ctx, base.bind(`INSERT INTO "organization" ("id","name","slug","createdAt") VALUES (?,?,?,?)`), id, id, id, base.date(now))
				must(err)
			}
			profiles := []string{"organization-teams", "organization-roles"}
			findings, err := CheckSchema(ctx, dialect, dsn, profiles)
			must(err)
			hasMissing := false
			for _, f := range findings {
				if f.Kind == "missing-table" && f.Table == "organizationRole" {
					hasMissing = true
				}
			}
			if !hasMissing {
				t.Fatalf("pre-upgrade check did not report organizationRole: %v", findings)
			}
			installed := open(profiles...)
			insert := func(id, group, grants string) error {
				_, err := installed.db.ExecContext(ctx, installed.bind(`INSERT INTO "organizationRole" ("id","organizationId","role","permission","createdAt") VALUES (?,?,?,?,?)`), id, group, "editor", grants, installed.date(now))
				return err
			}
			must(insert("n", "north", `{"reports":["read"]}`))
			must(insert("s", "south", `{"reports":["publish"]}`))
			if err := insert("unknown", "absent", "{}"); err == nil {
				t.Fatal("a role was inserted without its organization")
			}
			repeat := open(profiles...)
			findings, err = CheckSchema(ctx, dialect, dsn, profiles)
			must(err)
			if len(findings) != 0 {
				t.Fatalf("unexpected schema drift after a repeated upgrade: %v", findings)
			}
			_, err = repeat.db.ExecContext(ctx, repeat.bind(`DELETE FROM "organization" WHERE "id"=?`), "north")
			must(err)
			var rows int
			must(repeat.db.QueryRowContext(ctx, repeat.bind(`SELECT COUNT(*) FROM "organizationRole"`)).Scan(&rows))
			if rows != 1 {
				t.Fatalf("organization deletion left %d role rows", rows)
			}
			var grants string
			var created time.Time
			var updated sql.NullTime
			must(repeat.db.QueryRowContext(ctx, repeat.bind(`SELECT "permission","createdAt","updatedAt" FROM "organizationRole" WHERE "organizationId"=? AND "role"=?`), "south", "editor").Scan(&grants, &created, &updated))
			if grants != `{"reports":["publish"]}` || !created.Equal(now) || updated.Valid {
				t.Fatalf("surviving grant changed: %s, %v, %v", grants, created, updated)
			}
		})
	}
}
