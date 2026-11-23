package main

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Plain-Auth/plain-auth/schema"
)

func TestOrganizationRoleFieldCommands(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			dir := t.TempDir()
			dsn, driver := filepath.Join(dir, "roles.sqlite"), "sqlite3"
			if dialect != "sqlite" {
				dsn = fieldCommandTarget(t, dialect)
				driver = map[string]string{"postgres": "pgx", "mysql": "mysql"}[dialect]
			}
			t.Setenv("AUTH_DSN", dsn)
			file := filepath.Join(dir, "role-fields.json")
			call := func(verb string) (string, error) {
				return fieldCommand(t, verb, "--dialect", dialect, "--plugins", "organization-roles", "--organization-role-fields", file)
			}
			writeFieldConfig(t, file, `{"color":{"type":"string","column":"display_color"}}`)
			ddl, err := call("generate")
			if err != nil || strings.Count(ddl, "display_color") != 1 {
				t.Fatal("role column missing from generated schema", err)
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
					return strings.ReplaceAll(q, "\"", "`")
				}
				return q
			}
			for _, q := range []string{
				`INSERT INTO "organization" ("id","name","slug","createdAt") VALUES ('org','Studio','studio',CURRENT_TIMESTAMP)`,
				`INSERT INTO "organizationRole" ("id","organizationId","role","permission","createdAt","display_color") VALUES ('row','org','desk','{}',CURRENT_TIMESTAMP,'red')`,
			} {
				if _, err := db.ExecContext(t.Context(), query(q)); err != nil {
					t.Fatal(err)
				}
			}
			writeFieldConfig(t, file, `{"color":{"type":"string","column":"display_color"},"rank":{"type":"number","column":"display_rank","required":true}}`)
			if out, err := call("check"); !errors.Is(err, errSchemaMismatch) || !strings.Contains(out, "display_rank") {
				t.Fatal("missing role field was not reported", out, err)
			}
			if _, err := call("migrate"); err == nil {
				t.Fatal("upgraded a populated table without a required backfill")
			}
			writeFieldConfig(t, file, `{"color":{"type":"string","column":"display_color"},"rank":{"type":"number","column":"display_rank","required":true,"default":4}}`)
			for range 2 {
				if _, err := call("migrate"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := call("check"); err != nil {
				t.Fatal(err)
			}
			var color string
			var rank int
			if err := db.QueryRowContext(t.Context(), query(`SELECT "display_color","display_rank" FROM "organizationRole" WHERE "id"='row'`)).Scan(&color, &rank); err != nil || color != "red" || rank != 4 {
				t.Fatal("migration did not preserve and backfill populated role fields", color, rank, err)
			}
			for _, verb := range []string{"check", "migrate", "generate"} {
				if _, err := fieldCommand(t, verb, "--dialect", dialect, "--organization-role-fields", file); err == nil {
					t.Fatal("role field configuration accepted without its schema profile", verb)
				}
			}
		})
	}
	for _, name := range []string{"id", "role", "roleId", "roleName", "organizationId", "permission", "createdAt", "updatedAt", "additionalFields", "constructor", "prototype"} {
		for _, decl := range []string{`{"` + name + `":{"type":"string"}}`, `{"tag":{"type":"string","column":"` + strings.ToUpper(name) + `"}}`} {
			if _, err := schema.ReadRoleFields(strings.NewReader(decl)); err == nil {
				t.Fatal("accepted reserved role field", name)
			}
		}
	}
}
