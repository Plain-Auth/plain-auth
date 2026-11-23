package main

import (
	"bytes"
	"errors"
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
	if !strings.Contains(out.String(), "ops@example.test") || strings.Contains(out.String()+diagnostics.String(), password) {
		t.Fatal("unexpected command output")
	}
	if err := call(password); !errors.Is(err, authn.ErrAdminExists) {
		t.Fatal("bootstrap unexpectedly repeated", err)
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
	if err != nil || login.User.Role != "admin" {
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
