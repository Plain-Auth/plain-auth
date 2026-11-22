package main

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Plain-Auth/plain-auth/schema"
)

func TestAccountFieldCommands(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			dir := t.TempDir()
			dsn := filepath.Join(dir, "accounts.sqlite")
			driver := "sqlite3"
			if dialect != "sqlite" {
				dsn = fieldCommandTarget(t, dialect)
				driver = map[string]string{"postgres": "pgx", "mysql": "mysql"}[dialect]
			}
			t.Setenv("AUTH_DSN", dsn)
			path := filepath.Join(dir, "accounts.json")
			call := func(verb string) (string, error) {
				return fieldCommand(t, verb, "--dialect", dialect, "--account-fields", path)
			}
			writeFieldConfig(t, path, `{"tenant":{"type":"string","column":"directory_tenant"}}`)
			ddl, err := call("generate")
			if err != nil || strings.Count(ddl, "directory_tenant") != 1 {
				t.Fatalf("account column in generated schema: %v", err)
			}
			if _, err := call("migrate"); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open(driver, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			query := func(q string) string {
				if dialect == "mysql" {
					return strings.ReplaceAll(q, `"`, "`")
				}
				return q
			}
			for _, stmt := range []string{
				`INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES ('owner','Person','person@example.test',false,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
				`INSERT INTO "account" ("id","userId","accountId","providerId","directory_tenant","createdAt","updatedAt") VALUES ('row','owner','subject','org','north',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
			} {
				if _, err := db.ExecContext(t.Context(), query(stmt)); err != nil {
					t.Fatal(err)
				}
			}
			writeFieldConfig(t, path, `{"tenant":{"type":"string","column":"directory_tenant"},"region":{"type":"string","required":true}}`)
			if out, err := call("check"); !errors.Is(err, errSchemaMismatch) || !strings.Contains(out, "region") {
				t.Fatal("missing account column", out, err)
			}
			if _, err := call("migrate"); err == nil {
				t.Fatal("added required column to populated accounts without a backfill")
			}
			writeFieldConfig(t, path, `{"tenant":{"type":"string","column":"directory_tenant"},"region":{"type":"string","required":true,"default":"west"}}`)
			for range 2 {
				if _, err := call("migrate"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := call("check"); err != nil {
				t.Fatal(err)
			}
			var tenant, region string
			if err := db.QueryRowContext(t.Context(), query(`SELECT "directory_tenant","region" FROM "account" WHERE "id"='row'`)).Scan(&tenant, &region); err != nil || tenant != "north" || region != "west" {
				t.Fatal("account after additive migration", tenant, region, err)
			}
			writeFieldConfig(t, path, `{"tenant":{"type":"boolean","column":"directory_tenant"}}`)
			if _, err := call("check"); !errors.Is(err, errSchemaMismatch) {
				t.Fatal("accepted incompatible account column", err)
			}
		})
	}
}

func TestAccountFieldReservedNames(t *testing.T) {
	for _, name := range []string{"id", "userId", "accountId", "providerId", "accessToken", "refreshToken", "idToken", "scope", "scopes", "password", "accessTokenExpiresAt", "refreshTokenExpiresAt", "createdAt", "updatedAt", "prototype", "constructor"} {
		for _, declaration := range []string{`{"` + name + `":{"type":"string"}}`, `{"alias":{"type":"string","column":"` + strings.ToUpper(name) + `"}}`} {
			if _, err := schema.ReadAccountFields(strings.NewReader(declaration)); err == nil {
				t.Fatalf("accepted reserved account field %s", name)
			}
		}
	}
}
