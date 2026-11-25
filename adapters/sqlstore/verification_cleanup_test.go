package sqlstore

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// With DisableVerificationCleanup, writes leave expired verification rows of
// other keys in place, an expired row is still refused, and a write that
// reuses an expired row's key replaces it. A store used with one setting
// refuses the other; another store over the same database keeps sweeping.
func TestDisableVerificationCleanup(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			kept, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer kept.Close()
			swept, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer swept.Close()
			start := func(store *Store, keep bool) error {
				_, err := auth.New(auth.Options{Store: store, BaseURL: "https://cleanup.example", Secret: strings.Repeat("s", 40), DisableVerificationCleanup: keep})
				return err
			}
			if err := start(kept, true); err != nil {
				t.Fatal(err)
			}
			if err := start(kept, true); err != nil {
				t.Fatal("the same setting again was refused:", err)
			}
			if err := start(kept, false); err == nil {
				t.Fatal("a store keeping expired rows was started with cleanup on")
			}
			if err := start(swept, false); err != nil {
				t.Fatal(err)
			}
			if err := start(swept, true); err == nil {
				t.Fatal("a sweeping store was started with cleanup off")
			}
			rows := func(prefix string) int {
				t.Helper()
				var n int
				if err := kept.db.QueryRowContext(ctx, kept.bind(`SELECT COUNT(*) FROM "verification" WHERE "identifier" LIKE ?`), prefix+"%").Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			now := time.Now().UTC().Truncate(time.Millisecond)
			past, earlier := now.Add(-time.Hour), now.Add(-2*time.Hour)

			// OAuth states.
			flow := func(state string, expires time.Time) auth.OAuthFlow {
				return auth.OAuthFlow{State: state, Binding: "browser-" + state, Provider: "work", ExpiresAt: expires}
			}
			for _, state := range []string{"old", "older"} {
				if err := kept.SaveOAuthFlow(ctx, flow(state, past), earlier); err != nil {
					t.Fatal(err)
				}
			}
			if err := kept.SaveOAuthFlow(ctx, flow("live", now.Add(time.Hour)), now); err != nil {
				t.Fatal(err)
			}
			if rows("oauth-state:") != 3 {
				t.Fatal("a write deleted expired OAuth states")
			}
			if _, err := kept.ConsumeOAuthFlow(ctx, "old", "browser-old", now); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("a kept expired OAuth state answered", err)
			}
			if err := swept.SaveOAuthFlow(ctx, flow("later", now.Add(time.Hour)), now); err != nil {
				t.Fatal(err)
			}
			if rows("oauth-state:") != 2 {
				t.Fatal("a sweeping store kept expired OAuth states")
			}

			// Magic links, with the owner binding a known address gets.
			owner := auth.User{ID: "owner", Email: "owner@cleanup.example", CreatedAt: earlier, UpdatedAt: earlier}
			session := auth.StoredSession{Session: auth.Session{ID: "source", UserID: owner.ID, Token: "source-token", CreatedAt: earlier, UpdatedAt: earlier, ExpiresAt: now.Add(time.Hour)}}
			if err := kept.CreateUser(ctx, owner, "", &session); err != nil {
				t.Fatal(err)
			}
			link := func(store *Store, key string, at, expires time.Time) error {
				return store.SaveMagicLink(ctx, auth.MagicLinkChallenge{Key: key, Email: owner.Email, CreatedAt: at, ExpiresAt: expires})
			}
			for _, key := range []string{"link-a", "link-b"} {
				if err := link(kept, key, earlier, past); err != nil {
					t.Fatal(err)
				}
			}
			if err := link(kept, "link-a", now, now.Add(time.Hour)); err != nil {
				t.Fatal("reusing an expired link's key failed:", err)
			}
			if rows("magic-link:") != 2 || rows("magic-link-owner:") != 2 {
				t.Fatal("magic link rows after reuse:", rows("magic-link:"), rows("magic-link-owner:"))
			}
			if err := link(swept, "link-c", now, now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if rows("magic-link:") != 2 || rows("magic-link-owner:") != 2 {
				t.Fatal("a sweeping store kept an expired magic link")
			}

			// Password reset links, swept with the other codes.
			reset := func(store *Store, token string, at, expires time.Time) {
				t.Helper()
				if err := store.SavePasswordResetToken(ctx, auth.PasswordResetToken{ID: token, Token: token, UserID: owner.ID, Email: owner.Email, CreatedAt: at, ExpiresAt: expires}); err != nil {
					t.Fatal(err)
				}
			}
			reset(kept, "reset-a", earlier, past)
			reset(kept, "reset-b", now, now.Add(time.Hour))
			if rows("reset-password:") != 2 {
				t.Fatal("a write deleted an expired reset link")
			}
			if _, err := kept.FindPasswordResetToken(ctx, "reset-a", now); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("a kept expired reset link answered", err)
			}
			reset(swept, "reset-c", now, now.Add(time.Hour))
			if rows("reset-password:") != 2 {
				t.Fatal("a sweeping store kept an expired reset link")
			}

			// One-time session transfers.
			transfer := func(store *Store, key string, at, expires time.Time) error {
				return store.SaveOneTimeToken(ctx, key, session.Session, at, expires)
			}
			for _, key := range []string{"transfer-a", "transfer-b"} {
				if err := transfer(kept, key, earlier, past); err != nil {
					t.Fatal(err)
				}
			}
			if err := transfer(kept, "transfer-a", now, now.Add(time.Hour)); err != nil {
				t.Fatal("reusing an expired transfer's key failed:", err)
			}
			if rows("one-time-token:") != 2 || rows("one-time-token-owner:") != 2 {
				t.Fatal("transfer rows after reuse:", rows("one-time-token:"), rows("one-time-token-owner:"))
			}
			if _, err := kept.ConsumeOneTimeToken(ctx, "transfer-b", now); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("a kept expired transfer answered", err)
			}
			if err := transfer(swept, "transfer-c", now, now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if rows("one-time-token:") != 2 {
				t.Fatal("a sweeping store kept an expired transfer")
			}

			// DPoP proofs.
			proof := func(name string) string {
				sum := sha256.Sum256([]byte(name))
				return base64.RawURLEncoding.EncodeToString(sum[:])
			}
			reserve := func(store *Store, name string, at, expires time.Time) {
				t.Helper()
				if fresh, err := store.ReserveDPoPProof(ctx, proof(name), at, expires); err != nil || !fresh {
					t.Fatal("reserving", name, "answered", fresh, err)
				}
			}
			reserve(kept, "proof-a", earlier, past)
			reserve(kept, "proof-b", earlier, past)
			reserve(kept, "proof-a", now, now.Add(time.Minute))
			if fresh, err := kept.ReserveDPoPProof(ctx, proof("proof-a"), now, now.Add(time.Minute)); err != nil || fresh {
				t.Fatal("a live proof was reserved twice:", err)
			}
			if rows("dpop-proof:") != 2 {
				t.Fatal("a write deleted an expired DPoP proof")
			}
			reserve(swept, "proof-c", now, now.Add(time.Minute))
			if rows("dpop-proof:") != 2 {
				t.Fatal("a sweeping store kept an expired DPoP proof")
			}
		})
	}
}

// A code sweep blocked behind another transaction's lock gives up after a
// second on the server, so the password reset write that started it still
// succeeds promptly, and the connection returns to the pool with the
// server's own lock wait.
func TestCodeSweepDoesNotWait(t *testing.T) {
	for _, dialect := range []string{"postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			store, err := Open(ctx, dialect, organizationTestDSN(t, dialect))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			store.db.SetMaxOpenConns(2)
			now := time.Now().UTC().Truncate(time.Millisecond)
			owner := auth.User{ID: "owner", Email: "owner@sweep.example", CreatedAt: now, UpdatedAt: now}
			if err := store.CreateUser(ctx, owner, "", nil); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.ExecContext(ctx, store.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`),
				"stale", "sign-in-otp-locked@sweep.example", "code:0", store.date(now.Add(-time.Hour)), store.date(now.Add(-2*time.Hour)), store.date(now.Add(-2*time.Hour))); err != nil {
				t.Fatal(err)
			}
			holder, err := store.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			var id string
			if err := holder.QueryRowContext(ctx, store.bind(`SELECT "id" FROM "verification" WHERE "id"=? FOR UPDATE`), "stale").Scan(&id); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			err = store.SavePasswordResetToken(ctx, auth.PasswordResetToken{ID: "reset", Token: "reset-token", UserID: owner.ID, Email: owner.Email, CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
			if took := time.Since(started); err != nil || took > 1900*time.Millisecond {
				t.Fatal("a reset behind a locked sweep took", took, err)
			}
			if err := holder.Rollback(); err != nil {
				t.Fatal(err)
			}
			if dialect != "mysql" {
				return
			}
			var global int
			if err := store.db.QueryRowContext(ctx, "SELECT @@GLOBAL.innodb_lock_wait_timeout").Scan(&global); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				conn, err := store.db.Conn(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				var session int
				if err := conn.QueryRowContext(ctx, "SELECT @@SESSION.innodb_lock_wait_timeout").Scan(&session); err != nil || session != global {
					t.Fatal("a pooled connection kept the sweep's lock wait:", session, global, err)
				}
			}
		})
	}
}
