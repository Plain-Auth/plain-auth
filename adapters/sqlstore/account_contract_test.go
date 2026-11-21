package sqlstore

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authn "github.com/FineStack/frost-auth"
)

func TestAccountEngineContract(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			dsn := filepath.Join(t.TempDir(), "account.db")
			if dialect != "sqlite" {
				dsn = os.Getenv("AUTH_TEST_" + strings.ToUpper(dialect) + "_DSN")
				if dsn == "" {
					t.Skip("local engine DSN is not configured")
				}
			}
			ctx := t.Context()
			store, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			user := testUser("account-" + rand.Text())
			session := testSession(user, "s-"+rand.Text())
			if err = store.CreateUser(ctx, user, "first", &session); err != nil {
				t.Fatal(err)
			}
			defer store.db.ExecContext(ctx, store.bind(`DELETE FROM "user" WHERE "id"=?`), user.ID)
			now := user.CreatedAt.Add(time.Hour)
			if err = store.ChangeCredential(ctx, user.ID, "first", "second", nil); err != nil {
				t.Fatal(err)
			}
			if err = store.CreateCredentialSession(ctx, "first", testSession(user, "reject-"+rand.Text())); !errors.Is(err, authn.ErrNotFound) {
				t.Fatalf("stale proof became a session: %v", err)
			}
			change := authn.PasswordResetToken{ID: rand.Text(), Token: rand.Text(), UserID: user.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
			if err = store.SavePasswordResetToken(ctx, change); err != nil {
				t.Fatal(err)
			}
			defer store.db.ExecContext(ctx, store.bind(`DELETE FROM "verification" WHERE "id"=?`), change.ID)
			if err = store.FinishPasswordReset(ctx, change.Token, "third", now, true); err != nil {
				t.Fatal(err)
			}
			if err = store.FinishPasswordReset(ctx, change.Token, "again", now, true); !errors.Is(err, authn.ErrNotFound) {
				t.Fatalf("token spent twice: %v", err)
			}
			if _, _, err = store.Session(ctx, session.Token); !errors.Is(err, authn.ErrNotFound) {
				t.Fatal("reset failed to revoke session")
			}
			ss := testSession(user, "fresh-"+rand.Text())
			if err = store.CreateCredentialSession(ctx, "third", ss); err != nil {
				t.Fatal(err)
			}
			next := ss.ExpiresAt.Add(time.Hour)
			if won, err := store.RefreshSession(ctx, ss.Token, ss.ExpiresAt, now, next); err != nil || !won {
				t.Fatalf("could not refresh session: %v", err)
			}
			if won, err := store.RefreshSession(ctx, ss.Token, ss.ExpiresAt, now, next); err != nil || won {
				t.Fatalf("stale CAS changed session: %v", err)
			}
			if err = store.VerifyAccountEmail(ctx, user.ID, user.Email, now); err != nil {
				t.Fatal(err)
			}
			if err = store.VerifyAccountEmail(ctx, user.ID, user.Email, now); err != nil {
				t.Fatal(err)
			}
			destination := "new-" + rand.Text() + "@example.test"
			updated, err := store.ChangeAccountEmail(ctx, user.ID, user.Email, destination, true, now)
			if err != nil || !strings.EqualFold(updated.Email, destination) {
				t.Fatalf("email change: %+v %v", updated, err)
			}
			if _, err = store.ChangeAccountEmail(ctx, user.ID, user.Email, "stale@example.test", true, now); !errors.Is(err, authn.ErrNotFound) {
				t.Fatalf("stale email proof: %v", err)
			}
			if err = store.SetInitialPassword(ctx, user.ID, ss.Token, "no", now); !errors.Is(err, authn.ErrPasswordAlreadySet) {
				t.Fatalf("overwrote existing password: %v", err)
			}
			// Model a signed-in social-only account by dropping its local credential.
			if _, err = store.db.ExecContext(ctx, store.bind(`DELETE FROM "account" WHERE "userId"=? AND "providerId"='credential'`), user.ID); err != nil {
				t.Fatal(err)
			}
			if err = store.SetInitialPassword(ctx, user.ID, "wrong-session", "fourth", now); !errors.Is(err, authn.ErrNotFound) {
				t.Fatalf("accepted a foreign session to set a password: %v", err)
			}
			if err = store.SetInitialPassword(ctx, user.ID, ss.Token, "fourth", now); err != nil {
				t.Fatalf("first credential on a social account: %v", err)
			}
			if _, password, err := store.Credential(ctx, destination); err != nil || password != "fourth" {
				t.Fatalf("missing first password: %q %v", password, err)
			}
			d := authn.PasswordResetToken{ID: rand.Text(), Token: rand.Text(), UserID: user.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
			if err = store.SaveDeletionToken(ctx, d); err != nil {
				t.Fatal(err)
			}
			defer store.db.ExecContext(ctx, store.bind(`DELETE FROM "verification" WHERE "id"=?`), d.ID)
			if err = store.DeleteAccount(ctx, user.ID, ss.Token, "", "wrong-token", now); !errors.Is(err, authn.ErrNotFound) {
				t.Fatalf("invalid deletion token: %v", err)
			}
			if err = store.DeleteAccount(ctx, user.ID, ss.Token, "", d.Token, now); err != nil {
				t.Fatal(err)
			}
			for _, q := range []string{`SELECT COUNT(*) FROM "account" WHERE "userId"=?`, `SELECT COUNT(*) FROM "session" WHERE "userId"=?`} {
				var rows int
				if err := store.db.QueryRowContext(ctx, store.bind(q), user.ID).Scan(&rows); err != nil || rows != 0 {
					t.Fatalf("account deletion left child rows: %d %v", rows, err)
				}
			}
			if _, _, err = store.Session(ctx, ss.Token); !errors.Is(err, authn.ErrNotFound) {
				t.Fatal("deleted account still has a session")
			}
		})
	}
}
