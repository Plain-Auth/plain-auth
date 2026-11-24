package sqlstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	plainauth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/internal/kvtest"
	"github.com/Plain-Org/plain-auth/schema"
)

const mirrorPassword = "a mirrored test password"

type mirrorReplica struct {
	t    *testing.T
	node *plainauth.Auth
}

func (r mirrorReplica) call(method, path, body, cookie string) (int, map[string]any, string) {
	r.t.Helper()
	req := httptest.NewRequest(method, "https://auth.example/api/auth"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://auth.example")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	w := httptest.NewRecorder()
	r.node.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	session := ""
	for _, c := range w.Result().Cookies() {
		if strings.HasSuffix(c.Name, "session_token") && c.Value != "" {
			session = c.Name + "=" + c.Value
		}
	}
	return w.Code, out, session
}

// sessionUser returns the signed-in user's name, or "" for no session.
func (r mirrorReplica) sessionUser(cookie string) string {
	r.t.Helper()
	status, out, _ := r.call("GET", "/get-session", "", cookie)
	if status != 200 {
		r.t.Fatalf("get-session answered %d %v", status, out)
	}
	user, _ := out["user"].(map[string]any)
	name, _ := user["name"].(string)
	return name
}

func openMirrorStore(t *testing.T, dialect string, profiles ...string) *Store {
	t.Helper()
	ddl, err := schema.Generate(dialect, profiles)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenWithSchema(t.Context(), dialect, organizationTestDSN(t, dialect), ddl)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func mirrorReplicas(t *testing.T, store *Store, storage plainauth.SecondaryStorage, plugins ...plainauth.Plugin) (mirrorReplica, mirrorReplica) {
	t.Helper()
	newNode := func() mirrorReplica {
		node, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example", EmailAndPassword: true,
			RateLimit: new(bool), DeleteUserEnabled: true, SecondaryStorage: storage, StoreSessionInDatabase: true, Plugins: plugins})
		if err != nil {
			t.Fatal(err)
		}
		return mirrorReplica{t, node}
	}
	return newNode(), newNode()
}

func (s *Store) sessionTokens(t *testing.T, email string) []string {
	t.Helper()
	rows, err := s.db.QueryContext(t.Context(), s.bind(`SELECT s."token" FROM "session" s JOIN "user" u ON u."id"=s."userId" WHERE u."email"=? ORDER BY s."token"`), email)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := scanStrings(rows)
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

// Sessions are copied into SecondaryStorage when issued, served from it on
// another replica, copied back after a flush, and deleted before every
// revocation and user change commits.
func TestSecondaryStorageSessions(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store := openMirrorStore(t, dialect)
			storage := kvtest.New()
			a, b := mirrorReplicas(t, store, storage)
			const email = "mirror@example.org"
			status, out, cookie := a.call("POST", "/sign-up/email", `{"name":"Person","email":"`+email+`","password":"`+mirrorPassword+`"}`, "")
			if status != 200 || cookie == "" {
				t.Fatal("sign-up", status, out)
			}
			tokens := store.sessionTokens(t, email)
			if len(tokens) != 1 {
				t.Fatal("sessions", tokens)
			}
			token := tokens[0]
			raw, ttl, ok := storage.Lookup(token)
			if !ok || ttl < 6*24*time.Hour || ttl > 7*24*time.Hour {
				t.Fatalf("the session copy was %v with %v", ok, ttl)
			}
			var entry struct {
				Session struct{ Token, UserID string } `json:"session"`
				User    struct{ Email, Name string }   `json:"user"`
			}
			if json.Unmarshal([]byte(raw), &entry) != nil || entry.Session.Token != token || entry.User.Email != email || entry.User.Name != "Person" {
				t.Fatalf("the session copy was %s", raw)
			}
			// Another replica reads the copy: a rename made behind the
			// store's back shows only after a flush.
			if _, err := store.db.ExecContext(t.Context(), store.bind(`UPDATE "user" SET "name"=? WHERE "email"=?`), "Behind", email); err != nil {
				t.Fatal(err)
			}
			if got := b.sessionUser(cookie); got != "Person" {
				t.Fatal("the replica did not read the copy:", got)
			}
			storage.Clear()
			if got := b.sessionUser(cookie); got != "Behind" {
				t.Fatal("the replica did not fall back to the database:", got)
			}
			if _, _, ok := storage.Lookup(token); !ok {
				t.Fatal("the read did not copy the session back")
			}
			// A user change deletes the copy before it commits.
			if status, out, _ := a.call("POST", "/update-user", `{"name":"Updated"}`, cookie); status != 200 {
				t.Fatal("update-user", status, out)
			}
			if got := b.sessionUser(cookie); got != "Updated" {
				t.Fatal("the replica read a stale copy after update-user:", got)
			}
			// A user change whose copies cannot be deleted rolls back.
			storage.Fail("delete", errors.New("storage is down"))
			if status, _, _ := a.call("POST", "/update-user", `{"name":"Lost"}`, cookie); status != 500 {
				t.Fatal("update-user with a failing storage answered", status)
			}
			storage.Fail("delete", nil)
			var stored string
			if err := store.db.QueryRowContext(t.Context(), store.bind(`SELECT "name" FROM "user" WHERE "email"=?`), email).Scan(&stored); err != nil || stored != "Updated" {
				t.Fatal("a failed update-user changed the user:", stored, err)
			}
			// A copy that fails to write is deleted again, in case the
			// write still lands later.
			storage.Clear()
			storage.Fail("set", errors.New("storage timed out"))
			if got := b.sessionUser(cookie); got != "Updated" {
				t.Fatal("a failed copy write broke the read:", got)
			}
			storage.Fail("set", nil)
			ops := storage.Ops()
			if len(ops) < 2 || ops[len(ops)-2] != "set "+token || ops[len(ops)-1] != "delete "+token {
				t.Fatal("a failed copy write was not deleted:", ops[max(0, len(ops)-3):])
			}
			// A revocation whose copy cannot be deleted fails and keeps the session.
			storage.Fail("delete", errors.New("storage is down"))
			if status, _, _ := a.call("POST", "/sign-out", `{}`, cookie); status != 500 {
				t.Fatal("sign-out with a failing storage answered", status)
			}
			storage.Fail("delete", nil)
			if got := b.sessionUser(cookie); got != "Updated" {
				t.Fatal("a failed revocation ended the session:", got)
			}
			// Each revocation path removes the copy, and the other replica
			// then sees no session.
			_, _, second := a.call("POST", "/sign-in/email", `{"email":"`+email+`","password":"`+mirrorPassword+`"}`, "")
			_, _, third := a.call("POST", "/sign-in/email", `{"email":"`+email+`","password":"`+mirrorPassword+`"}`, "")
			if status, out, _ := a.call("POST", "/revoke-other-sessions", `{}`, third); status != 200 {
				t.Fatal("revoke-other-sessions", status, out)
			}
			for _, revoked := range []string{cookie, second} {
				if got := b.sessionUser(revoked); got != "" {
					t.Fatal("a revoked session was still served:", got)
				}
			}
			if status, _, _ := a.call("POST", "/sign-out", `{}`, third); status != 200 {
				t.Fatal("sign-out failed")
			}
			if got := b.sessionUser(third); got != "" || len(storage.Keys()) != 0 {
				t.Fatalf("after sign-out the replica served %q and the storage held %v", got, storage.Keys())
			}
			// A copy whose row is already gone, as a late write could leave,
			// is removed by signing out again.
			if err := storage.Set(t.Context(), token, raw, time.Hour); err != nil {
				t.Fatal(err)
			}
			a.call("POST", "/sign-out", `{}`, cookie)
			if _, _, ok := storage.Lookup(token); ok {
				t.Fatal("sign-out kept a copy whose session was gone")
			}
			_, _, last := a.call("POST", "/sign-in/email", `{"email":"`+email+`","password":"`+mirrorPassword+`"}`, "")
			if status, out, _ := a.call("POST", "/delete-user", `{"password":"`+mirrorPassword+`"}`, last); status != 200 {
				t.Fatal("delete-user", status, out)
			}
			if got := b.sessionUser(last); got != "" || len(storage.Keys()) != 0 {
				t.Fatalf("after delete-user the replica served %q and the storage held %v", got, storage.Keys())
			}
		})
	}
}

// An impersonated session is never copied, since its validity depends on
// the admin's own session, and a ban deletes the banned user's copies.
func TestSecondaryStorageAdminSessions(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store := openMirrorStore(t, dialect, "admin")
			storage := kvtest.New()
			admin, err := plainauth.NewAdmin(plainauth.AdminOptions{})
			if err != nil {
				t.Fatal(err)
			}
			a, b := mirrorReplicas(t, store, storage, admin)
			if _, err := a.node.BootstrapAdmin(t.Context(), "Root", "root@example.org", mirrorPassword); err != nil {
				t.Fatal(err)
			}
			_, _, root := a.call("POST", "/sign-in/email", `{"email":"root@example.org","password":"`+mirrorPassword+`"}`, "")
			status, created, userCookie := a.call("POST", "/sign-up/email", `{"name":"Member","email":"member@example.org","password":"`+mirrorPassword+`"}`, "")
			if status != 200 || root == "" {
				t.Fatal("setup", status, created)
			}
			user, _ := created["user"].(map[string]any)
			id, _ := user["id"].(string)
			before := len(storage.Keys())
			status, out, impersonated := a.call("POST", "/admin/impersonate-user", `{"userId":"`+id+`"}`, root)
			if status != 200 || impersonated == "" {
				t.Fatal("impersonate-user", status, out)
			}
			if got := b.sessionUser(impersonated); got != "Member" || len(storage.Keys()) != before {
				t.Fatalf("the impersonated session read %q and the storage held %d keys, want %d", got, len(storage.Keys()), before)
			}
			if status, out, _ := a.call("POST", "/admin/ban-user", `{"userId":"`+id+`"}`, root); status != 200 {
				t.Fatal("ban-user", status, out)
			}
			if got := b.sessionUser(userCookie); got != "" {
				t.Fatal("a banned user's session was still served:", got)
			}
			for _, token := range store.sessionTokens(t, "member@example.org") {
				if _, _, ok := storage.Lookup(token); ok {
					t.Fatal("a banned user's session copy survived")
				}
			}
		})
	}
}

// New refuses a SecondaryStorage it cannot use for sessions.
func TestSecondaryStorageConfiguration(t *testing.T) {
	store := openMirrorStore(t, "sqlite")
	storage := kvtest.New()
	secret := strings.Repeat("s", 32)
	for name, opts := range map[string]plainauth.Options{
		"without StoreSessionInDatabase": {Store: store, SecondaryStorage: storage},
		"StoreSessionInDatabase alone":   {Store: store, StoreSessionInDatabase: true},
		"store without a mirror":         {Store: memory.New(), SecondaryStorage: storage, StoreSessionInDatabase: true},
	} {
		opts.Secret, opts.BaseURL = secret, "https://auth.example"
		if _, err := plainauth.New(opts); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	opts := plainauth.Options{Store: store, Secret: secret, BaseURL: "https://auth.example", SecondaryStorage: storage, StoreSessionInDatabase: true}
	if _, err := plainauth.New(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := plainauth.New(opts); err != nil {
		t.Fatal("the same storage could not be attached again:", err)
	}
	opts.SecondaryStorage = kvtest.New()
	if _, err := plainauth.New(opts); err == nil {
		t.Fatal("a second storage was attached to the same store")
	}
}

// Concurrent reads, renames and a revocation leave no copy that disagrees
// with the database, and no copy of a revoked session.
func TestSecondaryStorageConcurrency(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store := openMirrorStore(t, dialect)
			storage := kvtest.New()
			a, b := mirrorReplicas(t, store, storage)
			const email = "busy@example.org"
			_, _, cookie := a.call("POST", "/sign-up/email", `{"name":"Start","email":"`+email+`","password":"`+mirrorPassword+`"}`, "")
			var wg sync.WaitGroup
			for i := range 4 {
				wg.Go(func() {
					for j := range 5 {
						a.call("POST", "/update-user", fmt.Sprintf(`{"name":"Name %d-%d"}`, i, j), cookie)
					}
				})
				wg.Go(func() {
					for range 10 {
						b.call("GET", "/get-session", "", cookie)
						storage.Clear()
					}
				})
			}
			wg.Wait()
			b.sessionUser(cookie)
			var name string
			if err := store.db.QueryRowContext(t.Context(), store.bind(`SELECT "name" FROM "user" WHERE "email"=?`), email).Scan(&name); err != nil {
				t.Fatal(err)
			}
			if got := b.sessionUser(cookie); got != name {
				t.Fatalf("the copy said %q, the database %q", got, name)
			}
			wg.Go(func() { a.call("POST", "/revoke-sessions", `{}`, cookie) })
			for range 3 {
				wg.Go(func() { b.call("GET", "/get-session", "", cookie) })
			}
			wg.Wait()
			if got := b.sessionUser(cookie); got != "" || len(storage.Keys()) != 0 {
				t.Fatalf("after revoke-sessions the replica served %q and the storage held %v", got, storage.Keys())
			}
		})
	}
}
