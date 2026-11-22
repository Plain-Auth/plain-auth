package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/sqlstore"
	"github.com/Plain-Auth/plain-auth/schema"
)

const userConfig = `{"locale":{"type":"string","required":true,"column":"preferred_locale","default":""},"accountClass":{"type":"string","default":"standard","serverOnly":true}}`
const sessionConfig = `{"locale":{"type":"boolean","column":"preferred_locale","default":false}}`
const upgradeConfig = `{"locale":{"type":"string","required":true,"column":"preferred_locale","default":""},"accountClass":{"type":"string","default":"standard","serverOnly":true},"quota":{"type":"number","required":true,"default":0},"flag":{"type":"boolean","required":true,"default":false},"memo":{"type":"string","default":null},"internalNote":{"type":"string","hidden":true}}`

func writeFieldConfig(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}
func fieldCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, stderr bytes.Buffer
	err := run(t.Context(), args, &out, &stderr)
	return out.String(), err
}

func TestUserFieldCommandsValidateBeforeConnecting(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "absent.db")
	t.Setenv("AUTH_DSN", target)
	path := filepath.Join(dir, "user fields.json")
	for _, input := range []string{`{"profile":{"type":"number","default":false}}`, `{"profile":{"type":"string","column":"EMAIL"}}`} {
		writeFieldConfig(t, path, input)
		for _, verb := range []string{"generate", "check", "migrate"} {
			out, err := fieldCommand(t, verb, "--dialect", "sqlite", "--user-fields", path)
			if err == nil || out != "" || !strings.Contains(err.Error(), "user fields") {
				t.Fatal(verb, out, err)
			}
			if verb == "check" && failureCode([]string{"check"}, err) != 2 {
				t.Fatal("invalid schema file exit status", err)
			}
		}
	}
	for _, file := range []string{"", filepath.Join(dir, "missing.json")} {
		if _, err := fieldCommand(t, "generate", "--dialect", "sqlite", "--user-fields", file); err == nil {
			t.Fatal("missing user file accepted", file)
		}
	}
	writeFieldConfig(t, path, userConfig)
	if out, err := fieldCommand(t, "check", "schema", "--dialect", "sqlite", "--user-fields", path, "--json"); err == nil || out != "" {
		t.Fatal("check of absent SQLite file", out, err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("command created absent target", err)
	}
}

func TestUserFieldCommandsAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dir := t.TempDir()
			dsn := filepath.Join(dir, "app.db")
			if dialect != "sqlite" {
				dsn = fieldCommandTarget(t, dialect)
			}
			t.Setenv("AUTH_DSN", dsn)
			users, sessions := filepath.Join(dir, "profile.json"), filepath.Join(dir, "sessions.json")
			writeFieldConfig(t, users, userConfig)
			writeFieldConfig(t, sessions, sessionConfig)
			flags := []string{"--dialect", dialect, "--plugins", "admin", "--user-fields", users, "--session-fields", sessions}
			call := func(verb string) (string, error) { return fieldCommand(t, append([]string{verb}, flags...)...) }
			check := func(want []sqlstore.SchemaFinding) {
				t.Helper()
				args := append([]string{"check", "schema", "--json"}, flags...)
				out, err := fieldCommand(t, args...)
				if len(want) == 0 {
					if err != nil || out != "[]\n" {
						t.Fatal("clean schema", out, err)
					}
					return
				}
				var got []sqlstore.SchemaFinding
				if !errors.Is(err, errSchemaMismatch) || failureCode(args, err) != 1 || json.Unmarshal([]byte(out), &got) != nil || !reflect.DeepEqual(got, want) {
					t.Fatal("schema findings", out, err)
				}
			}
			config, err := schema.ReadUserFields(strings.NewReader(userConfig))
			if err != nil {
				t.Fatal(err)
			}
			sessionFields, err := schema.ReadSessionFields(strings.NewReader(sessionConfig))
			if err != nil {
				t.Fatal(err)
			}
			expected, err := schema.GenerateWithAdditionalFields(dialect, []string{"admin"}, schema.AdditionalFields{User: config, Session: sessionFields})
			if err != nil {
				t.Fatal(err)
			}
			generated, err := call("generate")
			if err != nil || generated != expected {
				t.Fatal("generated combined schema", err)
			}
			if _, err = call("migrate"); err != nil {
				t.Fatal(err)
			}
			check(nil)
			store, err := sqlstore.Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			opts := plainauth.Options{BaseURL: "http://app.localhost", Secret: strings.Repeat("s", 40), EmailAndPassword: true, Store: store, UserAdditionalFields: config, SessionAdditionalFields: sessionFields}
			a, err := plainauth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			signup, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: "Owner", Email: "owner@profile.test", Password: "profile test password"}, plainauth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			if v, ok := signup.User.AdditionalField("locale"); !ok || v != "" {
				t.Fatal("fresh empty string default", v, ok)
			}
			session, _, err := store.Session(ctx, signup.Token)
			if err != nil {
				t.Fatal(err)
			}
			attrs, err := store.ReadSessionFields(ctx, []plainauth.Session{session.Session}, sessionFields)
			if err != nil || attrs[signup.Token]["locale"] != false {
				t.Fatal("session file used wrong namespace", attrs, err)
			}
			required := strings.TrimSuffix(upgradeConfig, "}") + `,"unknownValue":{"type":"string","required":true}}`
			writeFieldConfig(t, users, required)
			if _, err = call("migrate"); err == nil {
				t.Fatal("missing required backfill accepted")
			}
			writeFieldConfig(t, users, upgradeConfig)
			missing := []sqlstore.SchemaFinding{{Kind: "missing-column", Table: "user", Column: "flag"}, {Kind: "missing-column", Table: "user", Column: "internalNote"}, {Kind: "missing-column", Table: "user", Column: "memo"}, {Kind: "missing-column", Table: "user", Column: "quota"}}
			check(missing)
			check(missing)
			for range 2 {
				if _, err = call("migrate"); err != nil {
					t.Fatal(err)
				}
			}
			check(nil)
			upgraded, err := schema.ReadUserFields(strings.NewReader(upgradeConfig))
			if err != nil {
				t.Fatal(err)
			}
			physical, err := store.ReadUserFields(ctx, signup.User.ID, upgraded)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]any{"preferred_locale": "", "accountClass": "standard", "quota": int64(0), "flag": false, "memo": nil}
			if !reflect.DeepEqual(physical, want) {
				t.Fatalf("populated account backfill: %#v", physical)
			}
			writeFieldConfig(t, users, strings.Replace(upgradeConfig, `"type":"number","required":true,"default":0`, `"type":"string","required":true,"default":""`, 1))
			check([]sqlstore.SchemaFinding{{Kind: "incompatible-column", Table: "user", Column: "quota"}})
			if _, err = call("migrate"); err == nil {
				t.Fatal("incompatible existing user column changed")
			}
			addGeneratedUserColumn(t, dialect, dsn)
			writeFieldConfig(t, users, strings.TrimSuffix(upgradeConfig, "}")+`,"computedQuota":{"type":"number"}}`)
			check([]sqlstore.SchemaFinding{{Kind: "incompatible-column", Table: "user", Column: "computedQuota"}})
			if _, err = call("migrate"); err == nil {
				t.Fatal("generated user column accepted as writable")
			}
		})
	}
}

func addGeneratedUserColumn(t *testing.T, dialect, dsn string) {
	t.Helper()
	driver, q := "sqlite3", `ALTER TABLE "user" ADD COLUMN "computedQuota" INTEGER GENERATED ALWAYS AS (1) VIRTUAL`
	switch dialect {
	case "postgres":
		driver = "pgx"
		q = strings.Replace(q, "VIRTUAL", "STORED", 1)
	case "mysql":
		driver = "mysql"
		q = strings.ReplaceAll(q, `"`, "`")
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.ExecContext(t.Context(), q); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateDateFieldDDL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dates.json")
	writeFieldConfig(t, path, `{"deadline":{"type":"date","column":"review_at","required":true,"default":"2026-04-03T10:00:00Z"}}`)
	for dialect, kind := range map[string]string{"sqlite": "date", "postgres": "timestamptz", "mysql": "timestamp(3)"} {
		out, err := fieldCommand(t, "generate", "--dialect", dialect, "--user-fields", path, "--session-fields", path)
		if err != nil {
			t.Fatal(err)
		}
		sql := strings.ReplaceAll(out, "`", "\"")
		if strings.Count(sql, `"review_at" `+kind+" not null") != 2 {
			t.Fatalf("%s did not generate both date columns", dialect)
		}
	}
	writeFieldConfig(t, path, `{"deadline":{"type":"date","default":"2025-02-29T01:00:00Z"}}`)
	if out, err := fieldCommand(t, "generate", "--dialect", "sqlite", "--user-fields", path); err == nil || out != "" {
		t.Fatal("invalid timestamp default produced SQL")
	}
}
