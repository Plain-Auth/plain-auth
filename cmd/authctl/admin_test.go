package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestCreateAdminCommand(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "application.db")
	t.Setenv("AUTH_DSN", path)
	args := []string{"--dialect", "sqlite", "--email", "ops@example.test", "--name", "Operations", "--password-stdin"}
	const password = "example-managed-secret-phrase-012"
	var out, diagnostics bytes.Buffer
	call := func(pwd string) error {
		out.Reset()
		diagnostics.Reset()
		return createAdmin(ctx, args, strings.NewReader(pwd), &out, &diagnostics)
	}
	if err := call(password); err == nil {
		t.Fatal("missing schema allowed")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("bootstrap created a database at the wrong target", err)
	}
	ddl, err := schema.Generate("sqlite", []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlstore.OpenWithSchema(ctx, "sqlite", path, ddl)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, invalid := range []string{"short", "first-line\nsecond-line", "                    ", strings.Repeat("a", 520)} {
		if err := call(invalid); err == nil {
			t.Fatal("invalid initial credential accepted")
		}
	}
	if err := call(password + "\r\n"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "Admin user created successfully.\nUser ID: ") || !strings.HasSuffix(out.String(), "\nEmail: ops@example.test\nRole: admin\n") || strings.Contains(out.String()+diagnostics.String(), password) {
		t.Fatal("unexpected command output", out.String())
	}
	if err := call(password); err == nil || !strings.Contains(err.Error(), "--force or --yes") {
		t.Fatal("a populated database was not refused", err)
	}
	args = append(args, "--yes")
	if err := call(password); !errors.Is(err, authn.ErrAdminExists) {
		t.Fatal("bootstrap unexpectedly repeated", err)
	}
	for _, flag := range []string{"--password", "-password=" + password, "--password=" + password} {
		err := createAdmin(ctx, []string{"--dialect", "sqlite", "--email", "x@example.test", flag}, strings.NewReader(""), &out, &diagnostics)
		if err == nil || !strings.Contains(err.Error(), "--password-stdin") || strings.Contains(err.Error(), password) {
			t.Fatal("a password argument was accepted or echoed", err)
		}
	}
	p, err := authn.NewAdmin(authn.AdminOptions{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := authn.New(authn.Options{Store: store, BaseURL: "http://localhost", Secret: strings.Repeat("t", 32), EmailAndPassword: true, Plugins: []authn.Plugin{p}})
	if err != nil {
		t.Fatal(err)
	}
	login, err := service.SignInEmail(ctx, authn.SignInInput{Email: "ops@example.test", Password: password}, authn.RequestMeta{})
	if err != nil || login.User.Role != "admin" || login.User.Name != "Operations" || !login.User.EmailVerified {
		t.Fatal("provisioned administrator login", err)
	}
	h := http.Header{}
	h.Set("Cookie", service.SessionCookie(login.Token, true).Name+"="+service.SessionCookie(login.Token, true).Value)
	res, err := service.Admin(ctx, h, authn.AdminRequest{Operation: "list-users"})
	if err != nil || res.Page.Total != 1 {
		t.Fatal("provisioned administrator cannot operate", err)
	}
	if _, err := service.Admin(ctx, http.Header{}, authn.AdminRequest{Operation: "create-user", Email: "x@example.test", Name: "No credentials"}); err == nil {
		t.Fatal("unauthenticated native administrative action accepted")
	}
}

// create-admin defaults to the name Admin, the admin role and a verified
// email; --name, --role, --no-email-verified and --data set them, the image
// and declared user fields. A database with users needs --force or --yes, an
// account already holding a requested role or the email is refused, and
// malformed --data writes nothing, on SQLite, PostgreSQL and MySQL.
func TestCreateAdminOptionsAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := filepath.Join(t.TempDir(), "admin.db")
			if dialect != "sqlite" {
				dsn = fieldCommandTarget(t, dialect)
			}
			t.Setenv("AUTH_DSN", dsn)
			fields := filepath.Join(t.TempDir(), "user.json")
			writeFieldConfig(t, fields, userConfig)
			if _, err := fieldCommand(t, "migrate", "--dialect", dialect, "--plugins", "admin", "--user-fields", fields); err != nil {
				t.Fatal(err)
			}
			const password = "administrator test password 42"
			create := func(args ...string) (string, error) {
				var out bytes.Buffer
				err := createAdmin(ctx, append([]string{"--dialect", dialect, "--password-stdin", "--user-fields", fields}, args...), strings.NewReader(password), &out, io.Discard)
				return out.String(), err
			}
			store, err := sqlstore.Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			count := func() int {
				t.Helper()
				n, err := store.CountUsers(ctx)
				if err != nil {
					t.Fatal(err)
				}
				return n
			}
			config, err := schema.ReadUserFields(strings.NewReader(userConfig))
			if err != nil {
				t.Fatal(err)
			}
			admin, err := authn.NewAdmin(authn.AdminOptions{})
			if err != nil {
				t.Fatal(err)
			}
			service, err := authn.New(authn.Options{Store: store, BaseURL: "http://localhost", Secret: strings.Repeat("t", 32), EmailAndPassword: true, Plugins: []authn.Plugin{admin}, UserAdditionalFields: config})
			if err != nil {
				t.Fatal(err)
			}
			signIn := func(email string) (authn.User, map[string]any) {
				t.Helper()
				login, err := service.SignInEmail(ctx, authn.SignInInput{Email: email, Password: password}, authn.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				physical, err := store.ReadUserFields(ctx, login.User.ID, config)
				if err != nil {
					t.Fatal(err)
				}
				return login.User, physical
			}
			for _, bad := range []struct{ data, want string }{
				{`{`, "valid JSON"}, {`[]`, "JSON object"}, {`null`, "JSON object"}, {`{"a":1} {}`, "valid JSON"}, {`{"image":3}`, "image"}, {`{"undeclared":1}`, "undeclared"},
			} {
				if _, err := create("--email", "bad@example.test", "--data", bad.data); err == nil || !strings.Contains(err.Error(), bad.want) {
					t.Fatalf("--data %s gave %v", bad.data, err)
				}
			}
			if count() != 0 {
				t.Fatal("malformed --data wrote a user")
			}
			out, err := create("--email", "first@example.test")
			if err != nil || !strings.HasSuffix(out, "\nEmail: first@example.test\nRole: admin\n") {
				t.Fatal("the default administrator was not created:", out, err)
			}
			user, physical := signIn("first@example.test")
			if user.Name != "Admin" || user.Role != "admin" || !user.EmailVerified || user.Image != nil || physical["preferred_locale"] != "" || physical["accountClass"] != "standard" {
				t.Fatalf("the defaults are wrong: %+v %v", user, physical)
			}
			if _, err := create("--email", "second@example.test", "--role", "support"); err == nil || !strings.Contains(err.Error(), "--force or --yes") || count() != 1 {
				t.Fatal("a populated database was not refused:", err)
			}
			if _, err := create("--force", "--email", "second@example.test", "--role", "admin,support"); !errors.Is(err, authn.ErrAdminExists) || count() != 1 {
				t.Fatal("a held role was granted again:", err)
			}
			out, err = create("--force", "--email", "second@example.test", "--name", "Support", "--role", "support, auditor", "--no-email-verified",
				"--data", `{"image":"https://cdn.example/a.png","locale":"fr","accountClass":"staff","emailVerified":true,"role":"user","name":"x","email":"other@example.test"}`)
			if err != nil || !strings.HasSuffix(out, "\nRole: support,auditor\n") {
				t.Fatal("the configured administrator was not created:", out, err)
			}
			user, physical = signIn("second@example.test")
			if user.Name != "Support" || user.Role != "support,auditor" || user.EmailVerified || user.Image == nil || *user.Image != "https://cdn.example/a.png" || physical["preferred_locale"] != "fr" || physical["accountClass"] != "staff" {
				t.Fatalf("the options were not applied: %+v %v", user, physical)
			}
			if _, err := store.FindAccountUser(ctx, "other@example.test"); err == nil {
				t.Fatal("an email key in --data created an account")
			}
			if _, err := create("--yes", "--email", "second@example.test", "--role", "viewer"); err == nil || !strings.Contains(err.Error(), "already uses that email") {
				t.Fatal("an existing email was accepted:", err)
			}
			if _, err := create("-y", "--email", "third@example.test", "--role", "auditor"); !errors.Is(err, authn.ErrAdminExists) || count() != 2 {
				t.Fatal("a held role was granted again:", err)
			}
			for i, flag := range []string{"-y", "--yes"} {
				email, role := fmt.Sprintf("yes%d@example.test", i), fmt.Sprintf("viewer%d", i)
				if out, err := create(flag, "--email", email, "--role", role); err != nil || !strings.HasSuffix(out, "\nEmail: "+email+"\nRole: "+role+"\n") || count() != 3+i {
					t.Fatal(flag, "did not create the administrator:", out, err)
				}
			}
			// Roles compare exactly, also where the database folds case.
			if _, err := create("--force", "--email", "case@example.test", "--role", "Admin"); err != nil {
				t.Fatal("a role differing only in case was refused:", err)
			}
			if _, err := create("--force", "--email", "again@example.test", "--role", "admin"); !errors.Is(err, authn.ErrAdminExists) {
				t.Fatal("a held role was granted again beside a case variant:", err)
			}
		})
	}
}
