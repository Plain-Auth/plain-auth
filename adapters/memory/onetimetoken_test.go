package memory

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

func TestMemorySessionTransfer(t *testing.T) {
	ctx := t.Context()
	db := New()
	now := time.Now().UTC().Truncate(time.Millisecond)
	owner := auth.User{ID: "owner", Email: "owner@example.test", CreatedAt: now, UpdatedAt: now}
	row := auth.StoredSession{Session: auth.Session{ID: "original", UserID: owner.ID, Token: "original-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
	if err := db.CreateUser(ctx, owner, "", &row); err != nil {
		t.Fatal(err)
	}
	save := func(key string, expiry time.Time) {
		t.Helper()
		if err := db.SaveOneTimeToken(ctx, key, row.Session, now, expiry); err != nil {
			t.Fatal(err)
		}
	}
	save("same-key", now.Add(time.Minute))
	if err := db.SaveOneTimeToken(ctx, "same-key", row.Session, now, now.Add(2*time.Hour)); err == nil {
		t.Fatal("duplicate key replaced an outstanding transfer")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := db.ConsumeOneTimeToken(cancelled, "same-key", now); !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation", err)
	}
	var winners atomic.Int32
	var wait sync.WaitGroup
	for range 12 {
		wait.Go(func() {
			session, err := db.ConsumeOneTimeToken(ctx, "same-key", now)
			if err == nil && session.Session.ID == row.ID && session.User.ID == owner.ID {
				winners.Add(1)
				return
			}
			if !errors.Is(err, auth.ErrNotFound) {
				t.Errorf("unexpected transfer result: %v", err)
			}
		})
	}
	wait.Wait()
	if winners.Load() != 1 {
		t.Fatal("one transfer produced multiple logins", winners.Load())
	}
	save("old", now.Add(time.Second))
	if err := db.SaveOneTimeToken(ctx, "old", row.Session, now.Add(time.Minute), now.Add(2*time.Hour)); err != nil {
		t.Fatal("expired transfer prevented recycling", err)
	}
	if _, err := db.ConsumeOneTimeToken(ctx, "old", row.ExpiresAt); !errors.Is(err, auth.ErrTransferSessionExpired) {
		t.Fatal("expired source was not rejected", err)
	}
	save("revoked", now.Add(time.Hour))
	if err := db.DeleteSession(ctx, row.Token); err != nil {
		t.Fatal(err)
	}
	replacement := row
	replacement.ID = "replacement"
	if err := db.CreateSession(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ConsumeOneTimeToken(ctx, "revoked", now); !errors.Is(err, auth.ErrTransferSessionMissing) {
		t.Fatal("transfer followed a replacement session", err)
	}
	if _, err := db.ConsumeOneTimeToken(ctx, "revoked", now); !errors.Is(err, auth.ErrNotFound) {
		t.Fatal("denied proof was not burned", err)
	}
	if err := db.SaveOneTimeToken(ctx, "stale", row.Session, now, now.Add(time.Minute)); !errors.Is(err, auth.ErrNotFound) {
		t.Fatal("stale source issued a transfer", err)
	}
	if err := db.SaveOneTimeToken(ctx, "cleanup", replacement.Session, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteFixtureUser(ctx, owner.ID); err != nil {
		t.Fatal(err)
	}
	if len(db.transfers) != 0 {
		t.Fatal("deleted account retained transfer credentials")
	}
}
