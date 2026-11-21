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
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM stonewrit_api_key_digest WHERE digest = ?", []byte{1}).Scan(&markers); err != nil || markers != 1 {
		t.Fatalf("expected one completed backfill, got %d: %v", markers, err)
	}
}
