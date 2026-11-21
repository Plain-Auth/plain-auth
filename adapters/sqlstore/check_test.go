package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/FineStack/frost-auth/schema"
)

func TestReadOnlySchemaCheck(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			base, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer base.Close()
			check := func(profiles ...string) []SchemaFinding {
				t.Helper()
				v, err := CheckSchema(ctx, dialect, dsn, profiles)
				if err != nil {
					t.Fatal(err)
				}
				return v
			}
			if v := check(); len(v) != 0 {
				t.Fatal(v)
			}
			if v := check("device-authorization"); len(v) != 1 || v[0].Kind != "missing-table" || v[0].Table != "deviceCode" {
				t.Fatal("missing table findings", v)
			}
			if v := check("last-login-method"); len(v) != 1 || v[0].Kind != "missing-column" || v[0].Column != "lastLoginMethod" {
				t.Fatal("missing column findings", v)
			}
			sql, err := schema.Generate(dialect, []string{"last-login-method"})
			if err != nil {
				t.Fatal(err)
			}
			full, err := OpenWithSchema(ctx, dialect, dsn, sql)
			if err != nil {
				t.Fatal(err)
			}
			defer full.Close()
			for _, ddl := range []string{
				`ALTER TABLE "user" ADD COLUMN "customOptional" text`,
				`ALTER TABLE "user" ADD COLUMN "customDefault" integer NOT NULL DEFAULT 15`,
				`ALTER TABLE "user" ADD COLUMN "customGenerated" integer GENERATED ALWAYS AS (1) STORED NOT NULL`,
				`ALTER TABLE "user" ADD COLUMN "customRequired" integer NOT NULL`,
				`CREATE TABLE "unmanaged" ("required" integer NOT NULL)`,
				`CREATE VIEW "deviceCode" AS SELECT 1 AS "testViewColumn"`,
			} {
				if _, err := full.db.ExecContext(ctx, full.bind(ddl)); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				v := check("last-login-method")
				if len(v) != 1 || v[0] != (SchemaFinding{Kind: "unexpected-required-column", Table: "user", Column: "customRequired"}) {
					t.Fatal("required extra field or read-only behavior", v)
				}
			}
			// A view's physical columns participate in the name comparison.
			view := check("last-login-method", "device-authorization")
			if !slices.Contains(view, SchemaFinding{Kind: "missing-column", Table: "deviceCode", Column: "id"}) {
				t.Fatal("view columns unavailable", view)
			}
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			if _, err := CheckSchema(cancelled, dialect, dsn, nil); !errors.Is(err, context.Canceled) {
				t.Fatal("ignored cancellation")
			}
		})
	}
}

func TestCheckSchemaSQLiteGeneratedPrimaryKey(t *testing.T) {
	ctx := t.Context()
	dsn := organizationTestDSN(t, "sqlite")
	base, err := Open(ctx, "sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	for _, tc := range []struct {
		columns string
		want    bool
	}{
		{`"number" INTEGER PRIMARY KEY NOT NULL`, false},
		{`"number" INTEGER PRIMARY KEY DESC NOT NULL`, true},
		{`"number" INTEGER NOT NULL, "other" INTEGER NOT NULL, PRIMARY KEY ("number", "other")`, true},
	} {
		if _, err := base.db.ExecContext(ctx, `CREATE TABLE "deviceCode" (`+tc.columns+`)`); err != nil {
			t.Fatal(err)
		}
		found, err := CheckSchema(ctx, "sqlite", dsn, []string{"device-authorization"})
		if err != nil {
			t.Fatal(err)
		}
		if got := slices.Contains(found, SchemaFinding{Kind: "unexpected-required-column", Table: "deviceCode", Column: "number"}); got != tc.want {
			t.Fatalf("rowid generation for %s: %v", tc.columns, found)
		}
		if _, err := base.db.ExecContext(ctx, `DROP TABLE "deviceCode"`); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCheckSchemaConnectionPrivacy(t *testing.T) {
	const secret = "schema-connection-private-marker"
	for _, tc := range []struct{ dialect, dsn string }{
		{"postgres", "postgres://user:" + secret + "@%zz/test"},
		{"mysql", secret + "@invalid-network()/test"},
		{"sqlite", t.TempDir() + "/" + secret},
	} {
		findings, err := CheckSchema(t.Context(), tc.dialect, tc.dsn, nil)
		if findings != nil || err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("%s inspection disclosed a connection detail or returned findings", tc.dialect)
		}
	}
}

func TestCheckSchemaSelectedProfiles(t *testing.T) {
	profiles := slices.DeleteFunc(schema.Profiles(), func(name string) bool { return name == "organization" })
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, profiles)
			if err != nil {
				t.Fatal(err)
			}
			all, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer all.Close()
			findings, err := CheckSchema(ctx, dialect, dsn, profiles)
			if err != nil || len(findings) != 0 {
				t.Fatalf("configured schema had findings: %v, %v", findings, err)
			}
		})
	}
}

func TestCheckSchemaPostgresSearchPath(t *testing.T) {
	ctx := t.Context()
	deployedDSN, shadowDSN := organizationTestDSN(t, "postgres"), organizationTestDSN(t, "postgres")
	deployed, err := Open(ctx, "postgres", deployedDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer deployed.Close()
	shadow, err := sql.Open("pgx", shadowDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer shadow.Close()
	if _, err := shadow.ExecContext(ctx, `CREATE TABLE "user" ()`); err != nil {
		t.Fatal(err)
	}
	var deployedName, shadowName string
	if err := deployed.db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&deployedName); err != nil {
		t.Fatal(err)
	}
	if err := shadow.QueryRowContext(ctx, "SELECT current_schema()").Scan(&shadowName); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path       string
		incomplete bool
	}{
		{shadowName + "," + deployedName, true},
		{deployedName + "," + shadowName, false},
	} {
		cfg, err := pgx.ParseConfig(os.Getenv("AUTH_TEST_POSTGRES_DSN"))
		if err != nil {
			t.Fatal(err)
		}
		cfg.RuntimeParams["search_path"] = tc.path
		key := stdlib.RegisterConnConfig(cfg)
		findings, err := CheckSchema(ctx, "postgres", key, nil)
		stdlib.UnregisterConnConfig(key)
		if err != nil {
			t.Fatal(err)
		}
		if (len(findings) != 0) != tc.incomplete {
			t.Fatalf("schema resolution: %v", findings)
		}
		for _, f := range findings {
			if f.Table != "user" || f.Kind != "missing-column" {
				t.Fatalf("zero-column table or inherited table misreported: %v", f)
			}
		}
	}
}
