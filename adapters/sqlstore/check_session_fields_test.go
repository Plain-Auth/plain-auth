package sqlstore

import (
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func TestCheckConfiguredSessionSchema(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			s, e := Open(ctx, dialect, dsn)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			now := time.Now().UTC()
			u := auth.User{ID: "field-user", Name: "Field user", Email: "field-user@example.test", CreatedAt: now, UpdatedAt: now}
			initial := auth.StoredSession{Session: auth.Session{ID: "original", UserID: u.ID, Token: "original-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			if e := s.CreateUser(ctx, u, "test", &initial); e != nil {
				t.Fatal(e)
			}
			decl, e := schema.ReadSessionFields(strings.NewReader(`{"country":{"type":"string","column":"country_code","required":true,"default":"O'Brien"},"score":{"type":"number","default":-7},"notified":{"type":"boolean","default":false}}`))
			if e != nil {
				t.Fatal(e)
			}
			check := func(f map[string]schema.SessionField) []SchemaFinding {
				t.Helper()
				list, err := CheckSchemaWithSessionFields(ctx, dialect, dsn, nil, f)
				if err != nil {
					t.Fatal(err)
				}
				return list
			}
			missing := []SchemaFinding{{"missing-column", "session", "country_code"}, {"missing-column", "session", "notified"}, {"missing-column", "session", "score"}}
			if got := check(decl); !slices.Equal(got, missing) {
				t.Fatal("missing physical session columns", got)
			}
			if got := check(decl); !slices.Equal(got, missing) {
				t.Fatal("check mutated a populated target", got)
			}
			for range 2 {
				up, e := OpenWithSessionFields(ctx, dialect, dsn, nil, decl)
				if e != nil {
					t.Fatal(e)
				}
				if e = up.Close(); e != nil {
					t.Fatal(e)
				}
			}
			if got := check(decl); len(got) != 0 {
				t.Fatal("migrated session field check", got)
			}
			var country string
			var score int
			var notified bool
			if e = s.db.QueryRowContext(ctx, s.bind(`SELECT "country_code","score","notified" FROM "session" WHERE "id"=?`), initial.ID).Scan(&country, &score, &notified); e != nil || country != "O'Brien" || score != -7 || notified {
				t.Fatal("original session backfill", country, score, notified, e)
			}
			generated := `ALTER TABLE "session" ADD COLUMN "computedField" INTEGER GENERATED ALWAYS AS (1) VIRTUAL`
			if dialect == "postgres" {
				generated = `ALTER TABLE "session" ADD COLUMN "computedField" INTEGER GENERATED ALWAYS AS (1) STORED`
			}
			if _, err := s.db.ExecContext(ctx, s.bind(generated)); err != nil {
				t.Fatal(err)
			}
			if got := check(map[string]schema.SessionField{"computedField": {Type: auth.FieldNumber}}); !slices.Contains(got, SchemaFinding{"incompatible-column", "session", "computedField"}) {
				t.Fatal("generated column accepted for application writes", got)
			}
			decl["country"] = auth.SessionField{Type: auth.FieldString, Column: "country_code"}
			decl["score"] = auth.SessionField{Type: auth.FieldString, Column: "score"}
			decl["notified"] = auth.SessionField{Type: auth.FieldBoolean, Column: "Notified"}
			want := []SchemaFinding{{"incompatible-column", "session", "country_code"}, {"incompatible-column", "session", "Notified"}, {"incompatible-column", "session", "score"}}
			if got := check(decl); !slices.Equal(got, want) {
				t.Fatal("type, nullability and physical name drift", got)
			}
			if _, err := OpenWithSessionFields(ctx, dialect, dsn, nil, decl); err == nil {
				t.Fatal("incompatible migration changed the existing table")
			}
			if v, _, e := s.Session(ctx, initial.Token); e != nil || v.ID != initial.ID {
				t.Fatal("inspection changed the original login", e)
			}
		})
	}
}
