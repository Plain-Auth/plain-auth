package main

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionFieldCommands(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	path := filepath.Join(dir, "session columns.json")
	file := func(text string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fields := `{"region":{"type":"string","column":"region_code","required":true,"default":"west"},"attempts":{"type":"number","default":2}}`
	file(fields)
	command := func(args ...string) (string, error) {
		t.Helper()
		var out, stderr bytes.Buffer
		err := run(ctx, args, &out, &stderr)
		return out.String(), err
	}
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		out, err := command("generate", "--dialect", dialect, "--plugins", "admin", "--session-fields", path)
		if err != nil || !strings.Contains(out, "region_code") || !strings.Contains(out, "impersonatedBy") || !strings.Contains(out, "attempts") {
			t.Fatal("generated schema missing fields or plugin", dialect, err)
		}
	}
	dsn := filepath.Join(dir, "new.db")
	t.Setenv("AUTH_DSN", dsn)
	check := func() (string, error) {
		return command("check", "schema", "--dialect", "sqlite", "--plugins", "admin", "--session-fields", path, "--json")
	}
	if _, err := check(); err == nil {
		t.Fatal("check created the SQLite target")
	}
	if _, err := os.Stat(dsn); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only check changed the target", err)
	}
	if _, err := command("migrate", "--dialect", "sqlite"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`INSERT INTO user(id,name,email,emailVerified,createdAt,updatedAt) VALUES ('u','Fixture','fixture@example.test',0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP); INSERT INTO session(id,userId,token,createdAt,updatedAt,expiresAt) VALUES ('s','u','local',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	out, err := check()
	if !errors.Is(err, errSchemaMismatch) || !strings.Contains(out, `"column":"region_code"`) {
		t.Fatal("missing field not reported", out, err)
	}
	for range 2 {
		if _, err := command("migrate", "--dialect", "sqlite", "--plugins", "admin", "--session-fields", path); err != nil {
			t.Fatal(err)
		}
	}
	out, err = check()
	if err != nil || out != "[]\n" {
		t.Fatal("configured check", out, err)
	}
	var region string
	var count int
	if err = db.QueryRow(`SELECT region_code,attempts FROM session WHERE id='s'`).Scan(&region, &count); err != nil || region != "west" || count != 2 {
		t.Fatal("existing session not upgraded", region, count, err)
	}
	file(`{"region":{"type":"number","column":"region_code","required":true}}`)
	out, err = check()
	if !errors.Is(err, errSchemaMismatch) || !strings.Contains(out, `"kind":"incompatible-column"`) {
		t.Fatal("wrong type not reported", out, err)
	}
	file(`{"region":{"type":"string","required":"yes"}}`)
	for _, verb := range []string{"generate", "check", "migrate"} {
		if out, err := command(verb, "--dialect", "sqlite", "--session-fields", path); err == nil || out != "" || verb == "check" && failureCode([]string{"check"}, err) != 2 {
			t.Fatal("malformed field file not rejected", verb, out, err)
		}
	}
	if _, err := command("generate", "--dialect", "sqlite", "--session-fields", ""); err == nil {
		t.Fatal("empty field filename accepted")
	}
}
