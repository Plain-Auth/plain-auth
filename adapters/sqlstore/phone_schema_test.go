package sqlstore

import (
	"database/sql"
	"testing"

	"github.com/Stonewrit/stonewrit-auth/schema"
)

func TestPhoneNumberProfileMigration(t *testing.T) {
	for _, kind := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(kind, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, kind)
			base, err := Open(ctx, kind, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer base.Close()
			owner, other := testUser("phone-owner"), testUser("phone-other")
			if err := base.CreateUser(ctx, owner, "", nil); err != nil {
				t.Fatal(err)
			}
			if err := base.CreateUser(ctx, other, "", nil); err != nil {
				t.Fatal(err)
			}
			ddl, err := schema.Generate(kind, []string{"phone-number", "username"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, kind, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			var count int
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "user" WHERE "id" IN (?,?) AND "phoneNumber" IS NULL AND "phoneNumberVerified" IS NULL`), owner.ID, other.ID).Scan(&count); err != nil || count != 2 {
				t.Fatal("migration did not retain both unverified users with null phone numbers", count, err)
			}
			const number = "+12025550142"
			set := store.bind(`UPDATE "user" SET "phoneNumber"=?, "phoneNumberVerified"=? WHERE "id"=?`)
			if _, err := store.db.ExecContext(ctx, set, number, true, owner.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.ExecContext(ctx, set, number, false, other.ID); err == nil {
				t.Fatal("database accepted a second owner for the same phone number")
			}
			reopened, err := OpenWithSchema(ctx, kind, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			query := reopened.bind(`SELECT "phoneNumber", "phoneNumberVerified" FROM "user" WHERE "id"=?`)
			var phone sql.NullString
			var verified sql.NullBool
			if err := reopened.db.QueryRowContext(ctx, query, owner.ID).Scan(&phone, &verified); err != nil || !phone.Valid || phone.String != number || !verified.Valid || !verified.Bool {
				t.Fatal("replayed migration lost a verified number", err)
			}
			if _, err := reopened.db.ExecContext(ctx, set, nil, nil, owner.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := reopened.db.ExecContext(ctx, set, number, false, other.ID); err != nil {
				t.Fatal("could not reuse a released number", err)
			}
			if err := reopened.db.QueryRowContext(ctx, query, other.ID).Scan(&phone, &verified); err != nil || !phone.Valid || phone.String != number || !verified.Valid || verified.Bool {
				t.Fatal("stored false verification value was lost", err)
			}
		})
	}
}
