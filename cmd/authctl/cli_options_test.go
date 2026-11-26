package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	"github.com/Plain-Org/plain-auth/schema"
)

// -c and --cwd run init, migrate, check, generate and create-admin in another
// directory: relative files and a relative SQLite AUTH_DSN resolve there, and
// a missing directory fails before anything is written.
func TestWorkingDirectoryOption(t *testing.T) {
	outside, project := t.TempDir(), t.TempDir()
	t.Setenv("AUTH_DSN", "app.db")
	in := func(args ...string) error {
		t.Helper()
		t.Chdir(outside)
		return run(context.Background(), args, io.Discard, io.Discard)
	}
	for _, step := range [][]string{
		{"init", "-c", project},
		{"migrate", "--dialect", "sqlite", "--plugins", "admin", "--cwd", project},
		{"check", "--dialect", "sqlite", "--plugins", "admin", "-c", project},
		{"generate", "--dialect", "sqlite", "--cwd", project, "--output", "schema.sql"},
	} {
		if err := in(step...); err != nil {
			t.Fatal(step[0], "failed:", err)
		}
	}
	t.Chdir(outside)
	var out bytes.Buffer
	if err := createAdmin(context.Background(), []string{"--dialect", "sqlite", "--name", "Ops", "--email", "ops@example.test", "--password-stdin", "-c", project}, strings.NewReader("correct horse battery staple\n"), &out, io.Discard); err != nil {
		t.Fatal("create-admin failed:", err)
	}
	for _, name := range []string{".env", "app.db", "schema.sql"} {
		if _, err := os.Stat(filepath.Join(project, name)); err != nil {
			t.Fatal("a command ignored the working directory:", name)
		}
		if _, err := os.Stat(filepath.Join(outside, name)); err == nil {
			t.Fatal("a command wrote outside the working directory:", name)
		}
	}
	missing := filepath.Join(outside, "missing")
	if err := in("generate", "--dialect", "sqlite", "-c", missing, "--output", "schema.sql"); err == nil || !strings.Contains(err.Error(), "working directory") {
		t.Fatal("a missing working directory was accepted:", err)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatal("a failed run wrote files")
	}
}

// generate --output writes the schema to a file, creating its parents, or to
// a timestamped file inside a directory; an existing file is replaced only
// with -y or --yes, and a failed generation writes nothing. migrate accepts
// -y and --yes.
func TestGenerateOutputFile(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	generate := func(args ...string) error {
		out.Reset()
		return run(context.Background(), append([]string{"generate", "--dialect", "sqlite"}, args...), &out, io.Discard)
	}
	want, err := schema.Generate("sqlite", nil)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "nested", "parts", "schema.sql")
	if err := generate("--output", target); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(target); string(got) != want || out.String() != "Wrote the auth schema to "+target+".\n" {
		t.Fatal("the schema file or the notice is wrong:", out.String())
	}
	if err := os.WriteFile(target, []byte("kept"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := generate("--output", target); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatal("an existing file was replaced without --yes:", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "kept" {
		t.Fatal("a refused run changed the file")
	}
	for _, flag := range []string{"-y", "--yes"} {
		if err := os.WriteFile(target, []byte("kept"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := generate("--output", target, flag); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(target); string(got) != want {
			t.Fatal(flag, "did not replace the file")
		}
	}
	folder := filepath.Join(dir, "migrations")
	if err := os.Mkdir(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := generate("--output", folder); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(folder, "*.sql"))
	if len(files) != 1 || len(filepath.Base(files[0])) != len("2006-01-02T15-04-05.000Z.sql") {
		t.Fatal("a directory output did not get one timestamped file:", files)
	}
	if got, _ := os.ReadFile(files[0]); string(got) != want {
		t.Fatal("the timestamped file has the wrong schema")
	}
	// A path ending in a separator names a directory, created if missing.
	fresh := filepath.Join(dir, "fresh") + string(os.PathSeparator)
	if err := generate("--output", fresh); err != nil {
		t.Fatal(err)
	}
	if files, _ := filepath.Glob(filepath.Join(fresh, "*.sql")); len(files) != 1 {
		t.Fatal("a new directory output did not get one timestamped file:", files)
	}
	failed := filepath.Join(dir, "failed.sql")
	if err := run(context.Background(), []string{"generate", "--dialect", "oracle", "--output", failed}, io.Discard, io.Discard); err == nil {
		t.Fatal("an unsupported dialect was accepted")
	}
	if _, err := os.Stat(failed); err == nil {
		t.Fatal("a failed generation wrote a file")
	}
	t.Setenv("AUTH_DSN", filepath.Join(dir, "auth.db"))
	for _, flag := range []string{"-y", "--yes"} {
		if err := run(context.Background(), []string{"migrate", "--dialect", "sqlite", flag}, io.Discard, io.Discard); err != nil {
			t.Fatal("migrate refused", flag, err)
		}
	}
}

// info reports authctl, the Go runtime, the platform, the SQL drivers and
// the schema profiles as text or, with -j or --json, as JSON.
func TestInfoCommand(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"info"}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"authctl ", "Go " + runtime.Version() + " (" + runtime.GOOS + "/" + runtime.GOARCH, "sqlite (github.com/mattn/go-sqlite3 v", "postgres (github.com/jackc/pgx/v5 v", "mysql (github.com/go-sql-driver/mysql v", "Schema profiles: " + strings.Join(schema.Profiles(), ", ")} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("info lacks %q:\n%s", want, out.String())
		}
	}
	for _, flag := range []string{"-j", "--json"} {
		out.Reset()
		if err := run(context.Background(), []string{"info", flag}, &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		var r infoReport
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatal(flag, "did not print JSON:", err)
		}
		if r.Go.Version != runtime.Version() || r.System.Platform != runtime.GOOS || r.System.Arch != runtime.GOARCH || r.System.CPUCount != runtime.NumCPU() || r.Authctl.Version == "" || len(r.Databases) != 3 || !slices.Equal(r.SchemaProfiles, schema.Profiles()) {
			t.Fatalf("the JSON report is wrong: %+v", r)
		}
		for _, d := range r.Databases {
			if d.Version == "unknown" || !strings.HasPrefix(d.Version, "v") {
				t.Fatalf("no version for %s", d.Driver)
			}
		}
	}
	if err := run(context.Background(), []string{"info", "extra"}, io.Discard, io.Discard); err == nil {
		t.Fatal("info accepted a positional argument")
	}
}

// A replaced module keeps its own path in the report, with the replacement's
// version, or development for a directory.
func TestInfoReplacedModules(t *testing.T) {
	r := collectInfo(&debug.BuildInfo{Main: debug.Module{Path: "example.com/host"}, Deps: []*debug.Module{
		{Path: modulePath, Version: "v1.0.0", Replace: &debug.Module{Path: "example.com/fork", Version: "v1.0.1-fork"}},
		{Path: "github.com/mattn/go-sqlite3", Version: "v1.14.0", Replace: &debug.Module{Path: "example.com/sqlite3", Version: "v1.14.99"}},
		{Path: "github.com/jackc/pgx/v5", Version: "v5.0.0", Replace: &debug.Module{Path: "../pgx"}},
		{Path: "github.com/go-sql-driver/mysql", Version: "v1.9.0"},
	}})
	got := map[string]string{}
	for _, d := range r.Databases {
		got[d.Driver] = d.Version
	}
	if r.Authctl.Version != "v1.0.1-fork" || got["github.com/mattn/go-sqlite3"] != "v1.14.99" || got["github.com/jackc/pgx/v5"] != "(devel)" || got["github.com/go-sql-driver/mysql"] != "v1.9.0" {
		t.Fatalf("replaced modules were reported as %s and %v", r.Authctl.Version, got)
	}
	if collectInfo(nil).Authctl.Version != "development" {
		t.Fatal("a build without build information did not report development")
	}
}

// -c and --copy hand exactly the printed report to the platform clipboard
// command and say on standard error whether that worked; a failing clipboard
// still prints the report and exits successfully.
func TestInfoCopy(t *testing.T) {
	name := map[string]string{"darwin": "pbcopy", "linux": "xclip"}[runtime.GOOS]
	if name == "" {
		t.Skip("the clipboard command is not a shell script here")
	}
	bin, copied := t.TempDir(), filepath.Join(t.TempDir(), "clipboard")
	t.Setenv("PATH", bin)
	tool := filepath.Join(bin, name)
	for _, tc := range []struct {
		flag, script, notice string
	}{
		{"-c", "#!/bin/sh\n/bin/cat > " + copied + "\n", "Copied to clipboard\n"},
		{"--copy", "#!/bin/sh\n/bin/cat > " + copied + "\n", "Copied to clipboard\n"},
		{"--copy", "#!/bin/sh\nexit 1\n", "Could not copy to clipboard\n"},
	} {
		if err := os.WriteFile(tool, []byte(tc.script), 0o755); err != nil {
			t.Fatal(err)
		}
		os.Remove(copied)
		var out, errOut bytes.Buffer
		if err := run(context.Background(), []string{"info", "--json", tc.flag}, &out, &errOut); err != nil {
			t.Fatal(err)
		}
		if errOut.String() != tc.notice || !json.Valid(out.Bytes()) {
			t.Fatalf("%s gave %q", tc.flag, errOut.String())
		}
		if got, err := os.ReadFile(copied); tc.notice == "Copied to clipboard\n" && (err != nil || !bytes.Equal(got, out.Bytes())) {
			t.Fatal("the clipboard did not receive the printed report")
		}
	}
}
