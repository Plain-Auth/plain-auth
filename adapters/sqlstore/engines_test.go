package sqlstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	betterauth "github.com/nabuhadba/go-better-auth"
)

// Network database tests need a database dedicated to testing. They delete
// only the randomly named users they create, and can run against existing data.
func TestEngineContract(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			dsn := filepath.Join(t.TempDir(), "contract.db")
			if dialect != "sqlite" {
				key := "BETTERAUTH_TEST_" + strings.ToUpper(dialect) + "_DSN"
				dsn = os.Getenv(key)
				if dsn == "" {
					t.Skipf("set %s to run the %s database contract", key, dialect)
				}
			}
			ctx := context.Background()
			store, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			id := make([]byte, 8)
			if _, err := rand.Read(id); err != nil {
				t.Fatal(err)
			}
			prefix := "t-" + hex.EncodeToString(id)
			u := testUser(prefix)
			// Database timestamps in PostgreSQL and MySQL match the JavaScript date value at millisecond precision.
			u.CreatedAt = u.CreatedAt.Truncate(time.Millisecond)
			u.UpdatedAt = u.UpdatedAt.Truncate(time.Millisecond)
			session := testSession(u, prefix+"-initial")
			if err := store.CreateUser(ctx, u, "hash", &session); err != nil {
				t.Fatal(err)
			}
			removeUser := func(id string) {
				_, err := store.db.ExecContext(ctx, store.bind("DELETE FROM \"user\" WHERE \"id\"=?"), id)
				if err != nil {
					t.Error(err)
				}
			}
			defer removeUser(u.ID)
			x, hash, err := store.Credential(ctx, strings.ToUpper(u.Email))
			if err != nil || x.ID != u.ID || hash != "hash" || !x.CreatedAt.Equal(u.CreatedAt) {
				t.Fatalf("credential round trip %#v, %q, %v", x, hash, err)
			}
			dup := testUser(prefix + "-duplicate")
			dup.Email = strings.ToUpper(u.Email)
			if err := store.CreateUser(ctx, dup, "hash", nil); !errors.Is(err, betterauth.ErrEmailTaken) {
				t.Fatalf("case-insensitive duplicate: %v", err)
			}
			dup.Email = dup.ID + "@example.org"
			bad := testSession(dup, dup.ID+"-initial")
			bad.Token = session.Token
			if err := store.CreateUser(ctx, dup, "hash", &bad); err == nil {
				t.Fatal("expected session digest collision")
			}
			if _, _, err := store.Credential(ctx, dup.Email); !errors.Is(err, betterauth.ErrNotFound) {
				t.Fatalf("partial registration after failed session insert: %v", err)
			}
			// Simulate an application starting again against a populated schema.
			reopened, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			ss, owner, err := reopened.Session(ctx, session.Token)
			if err != nil || owner.ID != u.ID || ss.Token != session.Token || !ss.ExpiresAt.Equal(session.ExpiresAt) {
				t.Fatalf("persisted session %#v, %#v, %v", ss, owner, err)
			}
			// Exercise the public HTTP API with this engine's connection pool.
			auth, err := betterauth.New(betterauth.Options{
				Store: reopened, EmailAndPassword: true, Secret: strings.Repeat("s", 32), BaseURL: "http://example.org",
			})
			if err != nil {
				t.Fatal(err)
			}
			request := func(method, route, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
				t.Helper()
				req := httptest.NewRequest(method, "http://example.org/api/auth/"+route, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", "http://example.org")
				if cookie != nil {
					req.AddCookie(cookie)
				}
				res := httptest.NewRecorder()
				auth.ServeHTTP(res, req)
				if res.Code != http.StatusOK {
					t.Fatalf("%s %s: %d %s", method, route, res.Code, res.Body.String())
				}
				return res
			}
			email := prefix + "-http@example.org"
			body := fmt.Sprintf(`{"name":"Test User","email":%q,"password":"test-password-123"}`, email)
			registration := request(http.MethodPost, "sign-up/email", body, nil)
			var account betterauth.AuthResult
			if err := json.Unmarshal(registration.Body.Bytes(), &account); err != nil || account.User.ID == "" {
				t.Fatalf("registration response: %v, %s", err, registration.Body.String())
			}
			defer removeUser(account.User.ID)
			sessionCookie := func(res *httptest.ResponseRecorder) *http.Cookie {
				t.Helper()
				for _, cookie := range res.Result().Cookies() {
					if cookie.Name == "better-auth.session_token" {
						return cookie
					}
				}
				t.Fatal("missing session cookie")
				return nil
			}
			firstCookie := sessionCookie(registration)
			loginBody := fmt.Sprintf(`{"email":%q,"password":"test-password-123"}`, email)
			current := sessionCookie(request(http.MethodPost, "sign-in/email", loginBody, nil))
			active := request(http.MethodGet, "get-session", "", current)
			if !bytes.Contains(active.Body.Bytes(), []byte(account.User.ID)) {
				t.Fatalf("session owner mismatch: %s", active.Body.String())
			}
			request(http.MethodPost, "revoke-other-sessions", "{}", current)
			old := request(http.MethodGet, "get-session", "", firstCookie)
			if strings.TrimSpace(old.Body.String()) != "null" {
				t.Fatalf("first session survived revocation: %s", old.Body.String())
			}
			request(http.MethodPost, "sign-out", "{}", current)
			out := request(http.MethodGet, "get-session", "", current)
			if strings.TrimSpace(out.Body.String()) != "null" {
				t.Fatalf("signed-out session survived: %s", out.Body.String())
			}
		})
	}
}
