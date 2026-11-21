package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"testing"
	"time"

	authn "github.com/nabuhadba/go-better-auth"
)

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(context.Background(), "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func testUser(id string) authn.User {
	created := time.Date(2024, time.January, 1, 12, 30, 10, 123000000, time.UTC)
	return authn.User{
		ID: id, Email: id + "@example.org", Name: id, CreatedAt: created, UpdatedAt: created.Add(time.Minute),
	}
}

func testSession(u authn.User, id string) authn.StoredSession {
	return authn.StoredSession{
		Session: authn.Session{
			ID: id, Token: "token-" + id, UserID: u.ID, IPAddress: "127.0.0.1", UserAgent: "test client",
			CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt, ExpiresAt: u.CreatedAt.Add(24 * time.Hour),
		},
	}
}

func TestFailedSchemaInitializationIsAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.db")
	existing, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer existing.Close()
	// An incompatible table prevents the new session index from being created.
	if _, err := existing.Exec("CREATE TABLE session(id TEXT PRIMARY KEY); INSERT INTO session (id) VALUES ('legacy')"); err != nil {
		t.Fatal(err)
	}
	store, err := Open(context.Background(), "sqlite", path)
	if err == nil {
		store.Close()
		t.Fatal("opening incompatible session schema succeeded")
	}
	var count int
	err = existing.QueryRow("SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'user'").Scan(&count)
	if err != nil || count != 0 {
		t.Fatalf("new table persisted after initialization failed: %d, %v", count, err)
	}
}

func TestMissingIndexIsRestored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	s := openTestStore(t, path)
	if _, err := s.db.Exec(`DROP INDEX "session_userId_idx"`); err != nil {
		t.Fatal(err)
	}
	reopened := openTestStore(t, path)
	var count int
	if err := reopened.db.QueryRow("SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND name='session_userId_idx'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("index count %d, %v", count, err)
	}
}

func TestReopenCredentialAndSession(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "users #1?.sqlite")
	s := openTestStore(t, path)
	u := testUser("alice")
	image := "https://example.org/avatar"
	u.Image, u.EmailVerified = &image, true
	ss := testSession(u, "first")
	ss.Token = "private-raw-session-bearer"
	if err := s.CreateUser(ctx, u, "password-digest", &ss); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(ss.Token)) {
		t.Fatal("canonical opaque session token missing from database")
	}
	s = openTestStore(t, path)
	user, hash, err := s.Credential(ctx, "ALICE@example.org")
	if err != nil || !reflect.DeepEqual(user, u) || hash != "password-digest" {
		t.Fatalf("credential after restart: %#v, %q, %v", user, hash, err)
	}
	stored, owner, err := s.Session(ctx, ss.Token)

	if err != nil || !reflect.DeepEqual(ss, stored) || !reflect.DeepEqual(u, owner) {
		t.Fatalf("stored session with expiry after restart: %#v, %#v, %v", stored, owner, err)
	}
	if err := s.DeleteSession(ctx, ss.Token); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Session(ctx, ss.Token); !errors.Is(err, authn.ErrNotFound) {
		t.Fatalf("revoked session: %v", err)
	}
}

func TestCreateUserRollsBackOnSessionFailure(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, ":memory:")
	one := testUser("one")
	first := testSession(one, "original")
	if err := s.CreateUser(ctx, one, "hash", &first); err != nil {
		t.Fatal(err)
	}
	two := testUser("two")
	second := testSession(two, "second")
	second.Token = first.Token
	if err := s.CreateUser(ctx, two, "hash", &second); err == nil {
		t.Fatal("duplicate session token unexpectedly succeeded")
	}
	if _, _, err := s.Credential(ctx, two.Email); !errors.Is(err, authn.ErrNotFound) {
		t.Fatalf("user persisted after failed session insert: %v", err)
	}
	if err := s.CreateSession(ctx, testSession(two, "orphan")); err == nil {
		t.Fatal("created orphaned session")
	}
	if err := s.CreateUser(ctx, two, "hash", &first); err == nil {
		t.Fatal("accepted initial session for a different user")
	}
	if err := s.CreateUser(ctx, two, "hash", nil); err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
}

func TestConcurrentRegistrationWithTwoStores(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "auth.db")
	stores := []*Store{openTestStore(t, path), openTestStore(t, path)}
	const attempts = 20
	errs := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			u := testUser(fmt.Sprintf("u-%d", i))
			u.Email = "same@example.org"
			if i%2 == 0 {
				u.Email = "SAME@example.org"
			}
			session := testSession(u, u.ID)
			errs <- stores[i%len(stores)].CreateUser(ctx, u, "hash", &session)
		}(i)
	}
	var created, duplicate int
	for i := 0; i < attempts; i++ {
		switch err := <-errs; {
		case err == nil:
			created++
		case errors.Is(err, authn.ErrEmailTaken):
			duplicate++
		default:
			t.Errorf("registration failed: %v", err)
		}
	}
	if created != 1 || duplicate != attempts-1 {
		t.Fatalf("created %d, duplicate %d", created, duplicate)
	}
	for _, table := range []string{`"user"`, `"account"`, `"session"`} {
		var count int
		if err := stores[0].db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 1 {
			t.Errorf("%s row count %d, error %v", table, count, err)
		}
	}
}

func TestUserScopedRevocation(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, ":memory:")
	one, two := testUser("one"), testUser("two")
	first, second, other := testSession(one, "first"), testSession(one, "second"), testSession(two, "other")
	second.CreatedAt = second.CreatedAt.Add(time.Minute)
	if err := s.CreateUser(ctx, one, "hash", &first); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, two, "hash", &other); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, second); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListSessions(ctx, one.ID)
	if err != nil || !reflect.DeepEqual(got, []authn.StoredSession{second, first}) {
		t.Fatalf("listed sessions: %#v, %v", got, err)
	}
	if err := s.DeleteUserSession(ctx, one.ID, other.Token); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteOtherSessions(ctx, one.ID, second.Token); err != nil {
		t.Fatal(err)
	}
	for _, kept := range []authn.StoredSession{second, other} {
		if _, _, err := s.Session(ctx, kept.Token); err != nil {
			t.Fatalf("retained session %q: %v", kept.ID, err)
		}
	}
	if _, _, err := s.Session(ctx, first.Token); !errors.Is(err, authn.ErrNotFound) {
		t.Fatalf("first session: %v", err)
	}
	if err := s.DeleteUserSession(ctx, one.ID, second.Token); err != nil {
		t.Fatal(err)
	}
	got, err = s.ListSessions(ctx, one.ID)
	if err != nil || len(got) != 0 {
		t.Fatalf("sessions after revocation: %#v, %v", got, err)
	}
}
