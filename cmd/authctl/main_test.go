package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommands(t *testing.T) {
	var out bytes.Buffer
	runCommand := func(args ...string) error { out.Reset(); return run(context.Background(), args, &out, io.Discard) }
	if err := runCommand("secret"); err != nil {
		t.Fatal(err)
	}
	raw, ok := strings.CutPrefix(strings.TrimSpace(out.String()), "AUTH_SECRET=")
	if !ok {
		t.Fatal("missing env assignment")
	}
	secret, err := hex.DecodeString(raw)
	if err != nil || len(secret) != 32 {
		t.Fatal("secret length or format")
	}
	for _, dialect := range []string{"postgres", "mysql", "sqlite"} {
		if err := runCommand("generate", "--dialect", dialect); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.ToUpper(out.String()), "CREATE TABLE") {
			t.Fatal("missing table DDL")
		}
	}
	t.Setenv("AUTH_DSN", filepath.Join(t.TempDir(), "auth.db"))
	for range 2 {
		if err := runCommand("migrate", "--dialect", "sqlite"); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := runCommand("migrate", "--dialect", "sqlite", "--plugins", "organization-teams,two-factor"); err != nil {
			t.Fatal(err)
		}
	}
	if err := runCommand("generate", "--dialect", "mysql", "--plugins", "unknown"); err == nil {
		t.Fatal("accepted unknown schema profile")
	}
	if err := runCommand("generate", "--dialect", "invalid"); err == nil {
		t.Fatal("accepted unsupported dialect")
	}
	for _, verb := range []string{"generate", "migrate", "check"} {
		if err := runCommand(verb); err == nil {
			t.Fatal(verb, "ran without --dialect")
		}
	}
	t.Setenv("AUTH_DSN", "")
	if err := runCommand("migrate", "--dialect", "sqlite"); err == nil {
		t.Fatal("accepted missing DSN")
	}
}

func TestPrepareAPIKeyLedgerCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.db")
	t.Setenv("AUTH_DSN", path)
	args := []string{"migrate", "--dialect", "sqlite", "--api-key-ledger"}
	for range 2 {
		if err := run(t.Context(), args, io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var markers int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM plainauth_api_key_digest WHERE digest = ?", []byte{1}).Scan(&markers); err != nil || markers != 1 {
		t.Fatalf("expected one completed backfill, got %d: %v", markers, err)
	}
}

func TestPolarSchemaCommands(t *testing.T) {
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "billing.sqlite")
	t.Setenv("AUTH_DSN", dbPath)
	var out, diagnostics bytes.Buffer
	command := func(args ...string) error {
		out.Reset()
		diagnostics.Reset()
		return run(ctx, args, &out, &diagnostics)
	}
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		if err := command("generate", "--dialect", dialect, "--plugins", "polar"); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "plainauth_polar_checkout") || !strings.Contains(out.String(), "plainauth_polar_delivery") {
			t.Fatal("missing Polar tables for", dialect)
		}
		if err := command("generate", "--dialect", dialect); err != nil || strings.Contains(out.String(), "plainauth_polar_") {
			t.Fatal("ordinary installation selected billing tables", dialect, err)
		}
	}
	if err := command("migrate", "--dialect", "sqlite"); err != nil {
		t.Fatal(err)
	}
	if err := command("check", "schema", "--dialect", "sqlite", "--plugins", "polar", "--json"); err == nil || !strings.Contains(out.String(), "plainauth_polar_delivery") {
		t.Fatal("pending billing setup not reported", err, out.String())
	}
	for range 2 {
		if err := command("migrate", "--dialect", "sqlite", "--plugins", "sso,polar"); err != nil {
			t.Fatal(err)
		}
	}
	if err := command("check", "schema", "--dialect", "sqlite", "--plugins", "sso,polar", "--json"); err != nil || strings.TrimSpace(out.String()) != "[]" {
		t.Fatalf("billing schema check: %v %q", err, out.String())
	}
}
