package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/sqlstore"
	"github.com/Plain-Auth/plain-auth/plugins/siwe"
	"github.com/Plain-Auth/plain-auth/schema"
)

const walletSchemaFile = `{"table":"wallet_address","userId":"user_id","address":"wallet_address","chainId":"chain_id","isPrimary":"is_primary","createdAt":"created_at"}`

// The PostgreSQL test helper registers its connection settings inside this
// process. Give the CLI child the same isolated search path over a real DSN.
func walletCLITarget(t *testing.T, dialect string) (string, string) {
	t.Helper()
	if dialect == "sqlite" {
		p := filepath.Join(t.TempDir(), "wallet.sqlite")
		return p, p
	}
	target := fieldCommandTarget(t, dialect)
	if dialect != "postgres" {
		return target, target
	}
	db, err := sql.Open("pgx", target)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var name string
	if err := db.QueryRowContext(t.Context(), "SELECT current_schema()").Scan(&name); err != nil || !strings.HasPrefix(name, "fieldcli_") {
		t.Fatal("isolated PostgreSQL schema unavailable", err)
	}
	base := os.Getenv("AUTH_TEST_POSTGRES_DSN")
	if strings.HasPrefix(base, "postgres://") || strings.HasPrefix(base, "postgresql://") {
		u, err := url.Parse(base)
		if err != nil {
			t.Fatal("invalid PostgreSQL test URL")
		}
		q := u.Query()
		q.Set("search_path", name)
		u.RawQuery = q.Encode()
		return target, u.String()
	}
	return target, base + " search_path=" + name
}

func TestWalletSchemaCLI(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			target, childDSN := walletCLITarget(t, dialect)
			dir := t.TempDir()
			declaration := filepath.Join(dir, "wallet layout.json")
			userFile := filepath.Join(dir, "users.json")
			sessions := filepath.Join(dir, "sessions.json")
			writeFieldConfig(t, declaration, walletSchemaFile)
			writeFieldConfig(t, userFile, userConfig)
			writeFieldConfig(t, sessions, sessionConfig)
			runChild := func(want int, args ...string) (string, string) {
				t.Helper()
				cmd := exec.CommandContext(t.Context(), os.Args[0], append([]string{"-test.run=^TestCheckSchemaProcess$", "--"}, args...)...)
				cmd.Env = append(os.Environ(), "AUTHCTL_CHECK_TEST_CHILD=1", "AUTH_DSN="+childDSN, "GORACE=atexit_sleep_ms=0")
				var out, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &out, &stderr
				err := cmd.Run()
				if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != want {
					t.Fatalf("wallet command exited unexpectedly (%v), output %q, diagnostic %q", err, out.String(), stderr.String())
				}
				return out.String(), stderr.String()
			}
			flags := []string{"--dialect", dialect, "--plugins", "siwe,api-key", "--user-fields", userFile, "--session-fields", sessions, "--wallet-schema", declaration}
			call := func(want int, verb string, more ...string) (string, string) {
				t.Helper()
				args := []string{verb}
				args = append(args, flags...)
				return runChild(want, append(args, more...)...)
			}
			for _, invalid := range []string{`null`, `{"table":"one","table":"two"}`, `{"Table":"wallet"}`, `{"createdAt":"id"}`, `{"table":"user"}`, `{"userId":[]}`, `{"address":""}`, `{} {}`} {
				writeFieldConfig(t, declaration, invalid)
				for _, verb := range []string{"generate", "migrate", "check"} {
					code := 1
					if verb == "check" {
						code = 2
					}
					out, msg := call(code, verb)
					if out != "" || !strings.Contains(msg, "wallet schema") {
						t.Fatalf("invalid wallet description was not rejected by %s", verb)
					}
				}
			}
			writeFieldConfig(t, declaration, walletSchemaFile)
			out, diagnostic := runChild(1, "generate", "--dialect", dialect, "--wallet-schema", declaration)
			if out != "" || !strings.Contains(diagnostic, "siwe profile") {
				t.Fatal("missing plugin selector was accepted")
			}
			wallet, err := schema.ReadWalletSchema(strings.NewReader(walletSchemaFile))
			if err != nil {
				t.Fatal(err)
			}
			uf, err := schema.ReadUserFields(strings.NewReader(userConfig))
			if err != nil {
				t.Fatal(err)
			}
			sf, err := schema.ReadSessionFields(strings.NewReader(sessionConfig))
			if err != nil {
				t.Fatal(err)
			}
			opts := schema.Options{Wallet: wallet, AdditionalFields: schema.AdditionalFields{User: uf, Session: sf}}
			expected, err := schema.GenerateWithOptions(dialect, []string{"siwe", "api-key"}, opts)
			if err != nil {
				t.Fatal(err)
			}
			if out, msg := call(0, "generate"); out != expected || msg != "" {
				t.Fatal("wallet CLI generated different SQL than the configured public API")
			}
			runChild(0, "migrate", "--dialect", dialect)
			out, _ = call(1, "check", "--json")
			var findings []sqlstore.SchemaFinding
			if err := json.Unmarshal([]byte(out), &findings); err != nil {
				t.Fatal(err)
			}
			var mapped bool
			for _, f := range findings {
				if f.Table == "walletAddress" {
					t.Fatal("check reported canonical wallet table for a custom schema")
				}
				if f.Kind == "missing-table" && f.Table == "wallet_address" {
					mapped = true
				}
			}
			if !mapped {
				t.Fatal("read-only check missed mapped wallet table")
			}
			call(0, "migrate", "--api-key-ledger")
			store, err := sqlstore.OpenWithOptions(t.Context(), dialect, target, []string{"siwe", "api-key"}, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			// Insert real profile/session fields through the typed runtime, then
			// repeat the process migration against the populated database.
			instance, err := auth.New(auth.Options{Store: store, BaseURL: "http://app.localhost", Secret: strings.Repeat("z", 36), EmailAndPassword: true, UserAdditionalFields: uf, SessionAdditionalFields: sf})
			if err != nil {
				t.Fatal(err)
			}
			result, err := instance.SignUpEmail(t.Context(), auth.SignUpInput{Name: "Account", Email: "cli@wallet.test", Password: "a-local-credential", AdditionalFields: map[string]any{"locale": "fr"}}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			const address = "0x1111111111111111111111111111111111111111"
			row := auth.StoredSession{Session: auth.Session{ID: "fixture-login", UserID: "fixture-wallet", Token: "fixture-cookie-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			reg, err := store.FinishWalletLogin(t.Context(), siwe.Login{Address: address, Email: "wallet@example.test", CandidateID: row.UserID, AllowSignUp: true, ChainID: 1}, row)
			if err != nil {
				t.Fatal(err)
			}
			call(0, "migrate", "--api-key-ledger")
			if owner, err := store.WalletOwner(t.Context(), address); err != nil || owner != reg.ID {
				t.Fatal("repeated CLI migration lost mapped wallet ownership", owner, err)
			}
			if out, msg := runChild(0, append([]string{"check", "schema", "--json"}, flags...)...); out != "[]\n" || msg != "" {
				t.Fatal("mapped schema drift after repeated migration", out, msg)
			}
			if out, msg := call(0, "check"); out != "Schema check passed.\n" || msg != "" {
				t.Fatal("plain schema check failed", out, msg)
			}
			_, profile, err := store.Session(t.Context(), result.Token)
			if err != nil || profile.ID != result.User.ID {
				t.Fatal("populated session lost", err)
			}
			values, err := store.ReadUserFields(t.Context(), profile.ID, uf)
			if err != nil || values["preferred_locale"] != "fr" {
				t.Fatal("populated profile lost", err)
			}
			driver := map[string]string{"sqlite": "sqlite3", "postgres": "pgx", "mysql": "mysql"}[dialect]
			db, err := sql.Open(driver, target)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var markers int
			if err := db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM plainauth_api_key_digest").Scan(&markers); err != nil || markers != 1 {
				t.Fatal("combined API key ledger migration did not finish", markers, err)
			}
		})
	}
}
