package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/schema"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Exercise the command dispatcher against a disposable schema or database, so
// the CLI never alters the base database supplied by the test environment.
func fieldCommandTarget(t *testing.T, dialect string) string {
	t.Helper()
	dsn := os.Getenv("AUTH_TEST_" + strings.ToUpper(dialect) + "_DSN")
	if dsn == "" {
		t.Skip("requires a disposable local " + dialect + " test database")
	}
	name := "fieldcli_" + strings.ToLower(rand.Text()[:12])
	driver, kind := "mysql", "DATABASE"
	if dialect == "postgres" {
		driver, kind = "pgx", "SCHEMA"
	}
	admin, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	if _, err = admin.ExecContext(t.Context(), "CREATE "+kind+" "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		q := "DROP " + kind + " " + name
		if dialect == "postgres" {
			q += " CASCADE"
		}
		if _, e := admin.ExecContext(context.Background(), q); e != nil {
			t.Error(e)
		}
	})
	if dialect == "mysql" {
		config, e := mysql.ParseDSN(dsn)
		if e != nil {
			t.Fatal(e)
		}
		config.DBName = name
		return config.FormatDSN()
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = name
	target := stdlib.RegisterConnConfig(config)
	t.Cleanup(func() { stdlib.UnregisterConnConfig(target) })
	return target
}

func TestSessionFieldCommandsOnServers(t *testing.T) {
	for _, dialect := range []string{"postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := fieldCommandTarget(t, dialect)
			t.Setenv("AUTH_DSN", dsn)
			call := func(cmd string, args ...string) (string, error) {
				t.Helper()
				var out, stderr bytes.Buffer
				opts := append([]string{cmd, "--dialect", dialect}, args...)
				err := run(ctx, opts, &out, &stderr)
				return out.String(), err
			}
			if _, err := call("migrate"); err != nil {
				t.Fatal(err)
			}
			base, err := sqlstore.Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer base.Close()
			now := time.Now().UTC()
			u := auth.User{ID: "owner", Name: "Test", Email: "test@example.test", CreatedAt: now, UpdatedAt: now}
			row := auth.StoredSession{Session: auth.Session{ID: "existing", UserID: u.ID, Token: "fixture-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			if err = base.CreateUser(ctx, u, "test", &row); err != nil {
				t.Fatal(err)
			}
			manifest := filepath.Join(t.TempDir(), "fields.json")
			contents := `{"location":{"type":"string","column":"office_location","required":true,"default":"here"}}`
			write := func(v string) {
				if err := os.WriteFile(manifest, []byte(v), 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(contents)
			flags := []string{"--session-fields", manifest, "--plugins", "api-key"}
			for range 2 {
				out, err := call("check", append(flags, "--json")...)
				if !errors.Is(err, errSchemaMismatch) || !strings.Contains(out, `"kind":"missing-column","table":"session","column":"office_location"`) {
					t.Fatal("read-only CLI preflight", out, err)
				}
			}
			for range 2 {
				if _, err := call("migrate", append(flags, "--api-key-ledger")...); err != nil {
					t.Fatal(err)
				}
			}
			out, err := call("check", append(flags, "--json")...)
			if err != nil || out != "[]\n" {
				t.Fatal("ready schema reported drift", out, err)
			}
			fields, err := schema.ReadSessionFields(strings.NewReader(contents))
			if err != nil {
				t.Fatal(err)
			}
			record, err := base.ReadSessionFields(ctx, []auth.Session{row.Session}, fields)
			if err != nil || record[row.Token]["location"] != "here" {
				t.Fatal("old row lost its default", err)
			}
			write(`{"location":{"type":"boolean","column":"office_location","required":true}}`)
			out, err = call("check", append(flags, "--json")...)
			if !errors.Is(err, errSchemaMismatch) || !strings.Contains(out, "incompatible-column") {
				t.Fatal("drift was not reported", out, err)
			}
			if _, err := call("migrate", flags...); err == nil {
				t.Fatal("migration rewrote an incompatible field")
			}
		})
	}
}
