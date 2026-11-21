package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCheckSchemaCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	dsn := filepath.Join(t.TempDir(), "auth.db")
	t.Setenv("AUTH_DSN", dsn)
	check := []string{"check", "schema", "--dialect", "sqlite", "--json"}
	err := run(t.Context(), check, &stdout, &stderr)
	if err == nil || failureCode(check, err) != 2 || strings.Contains(err.Error(), dsn) {
		t.Fatal("unexpected database failure output", err)
	}
	if _, err := os.Stat(dsn); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("check created a missing database", err)
	}
	if err := run(t.Context(), []string{"migrate", "--dialect", "sqlite"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := run(t.Context(), check, &stdout, &stderr); err != nil || stdout.String() != "[]\n" {
		t.Fatal("invalid success report", err, stdout.String())
	}
	stdout.Reset()
	args := []string{"check", "--dialect", "sqlite", "--plugins", "last-login-method"}
	err = run(t.Context(), args, &stdout, &stderr)
	if !errors.Is(err, errSchemaMismatch) || failureCode(args, err) != 1 || !strings.Contains(stdout.String(), "missing-column user.lastLoginMethod") {
		t.Fatal("invalid mismatch report", err, stdout.String())
	}
}

// Exercise main's real stdout, stderr and exit status in a separate process.
func TestCheckSchemaProcess(t *testing.T) {
	if os.Getenv("AUTHCTL_CHECK_TEST_CHILD") == "1" {
		separator := slices.Index(os.Args, "--")
		os.Args = append([]string{"authctl"}, os.Args[separator+1:]...)
		main()
		os.Exit(0)
	}
	const secret = "check-private-marker"
	dsn := filepath.Join(t.TempDir(), secret+" #1?%.sqlite")
	command := func(target string, wantCode int, args ...string) (string, string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), os.Args[0], append([]string{"-test.run=^TestCheckSchemaProcess$", "--"}, args...)...)
		cmd.Env = append(os.Environ(), "AUTHCTL_CHECK_TEST_CHILD=1", "AUTH_DSN="+target, "GORACE=atexit_sleep_ms=0")
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		err := cmd.Run()
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal(err)
			}
		}
		if strings.Contains(out.String()+stderr.String(), secret) {
			t.Fatal("process output exposed a connection detail")
		}
		if code := cmd.ProcessState.ExitCode(); code != wantCode {
			t.Fatalf("expected status %d, got %d: %s %s", wantCode, code, out.String(), stderr.String())
		}
		return out.String(), stderr.String()
	}
	for _, tc := range []struct{ dialect, target string }{
		{"sqlite", dsn},
		{"sqlite", ":memory:"},
		{"postgres", "postgres://user:" + secret + "@%zz/db"},
		{"mysql", secret + "@invalid-network()/test"},
	} {
		out, stderr := command(tc.target, 2, "check", "schema", "--dialect", tc.dialect, "--json")
		if out != "" || stderr == "" {
			t.Fatal("unreadable target did not produce an isolated diagnostic")
		}
	}
	if _, err := os.Stat(dsn); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inspection changed the missing SQLite file", err)
	}
	command(dsn, 2, "check", "--dialect", "sqlite", "--plugins", "unknown")
	command("", 2, "check", "--dialect", "sqlite")
	command(dsn, 2, "check", "--dialect", "sqlite", "unexpected")
	command(dsn, 0, "check", "schema", "--help")
	command(dsn, 0, "migrate", "--dialect", "sqlite")
	out, stderr := command(dsn, 0, "check", "schema", "--dialect", "sqlite", "--json")
	if out != "[]\n" || stderr != "" {
		t.Fatalf("successful JSON check: %q, %q", out, stderr)
	}
	out, stderr = command(dsn, 1, "check", "--dialect", "sqlite", "--plugins", "last-login-method", "--json")
	if out != "[{\"kind\":\"missing-column\",\"table\":\"user\",\"column\":\"lastLoginMethod\"}]\n" || stderr == "" {
		t.Fatalf("drift JSON check: %q, %q", out, stderr)
	}
	command(dsn, 0, "migrate", "--dialect", "sqlite", "--plugins", "last-login-method")
	out, stderr = command(dsn, 0, "check", "--dialect", "sqlite", "--plugins", "last-login-method")
	if out != "Schema check passed.\n" || stderr != "" {
		t.Fatalf("successful text check: %q, %q", out, stderr)
	}
}
