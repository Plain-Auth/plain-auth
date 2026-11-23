package memory_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

func TestMemoryMagicLinkAtomicPromotion(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)
	store := memory.New()
	const address = "customer@example.test"
	user := auth.User{ID: "owner", Email: address, Name: "Persisted owner", CreatedAt: now, UpdatedAt: now}
	session := func(token string) auth.StoredSession {
		return auth.StoredSession{Session: auth.Session{ID: token, Token: token, UserID: user.ID, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
	}
	prior := session("prior")
	if err := store.CreateUser(ctx, user, "imported-credential", &prior); err != nil {
		t.Fatal(err)
	}
	if err := store.SavePasswordResetToken(ctx, auth.PasswordResetToken{Token: "old-reset", UserID: user.ID, Email: address, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	proof := auth.MagicLinkChallenge{Key: "CaseSensitive", Email: address, Name: "Requested name", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := store.SaveMagicLink(ctx, proof); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveMagicLink(ctx, proof); err == nil {
		t.Fatal("duplicate generator output replaced a live link")
	}
	if _, _, err := store.CompleteMagicLink(ctx, "casesensitive", "other", session("case"), true); !errors.Is(err, auth.ErrNotFound) {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := store.CompleteMagicLink(cancelled, proof.Key, "other", session("canceled"), true); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err := store.CompleteMagicLink(ctx, proof.Key, "other", prior, true); err == nil {
		t.Fatal("duplicate session token accepted")
	}
	if _, _, err := store.Credential(ctx, address); err != nil {
		t.Fatal("failed insertion changed the account", err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			owner, created, err := store.CompleteMagicLink(ctx, proof.Key, "unrelated", session(fmt.Sprintf("new-%d", i)), true)
			if errors.Is(err, auth.ErrNotFound) {
				return
			}
			if err != nil || created || owner.ID != user.ID || owner.Name != user.Name || !owner.EmailVerified {
				t.Errorf("wrong promoted user: %+v, created=%v, err=%v", owner, created, err)
				return
			}
			wins.Add(1)
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("concurrent redemptions issued %d sessions", wins.Load())
	}
	rows, err := store.ListSessions(ctx, user.ID)
	if err != nil || len(rows) != 1 || rows[0].Token == prior.Token {
		t.Fatalf("unexpected live sessions: %v, %v", rows, err)
	}
	if _, _, err := store.Credential(ctx, address); !errors.Is(err, auth.ErrNotFound) {
		t.Fatal("old password still usable", err)
	}
	if _, err := store.FindPasswordResetToken(ctx, "old-reset", now); !errors.Is(err, auth.ErrNotFound) {
		t.Fatal("old password reset survived promotion", err)
	}
}

func TestMemoryMagicLinkOwnerAndExpiry(t *testing.T) {
	ctx := t.Context()
	store := memory.New()
	now := time.Now().UTC()
	session := auth.StoredSession{Session: auth.Session{ID: "session", Token: "token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
	const email = "owner@example.test"
	link := auth.MagicLinkChallenge{Key: "link", Email: email, Name: "First owner", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	save := func() {
		t.Helper()
		if err := store.SaveMagicLink(ctx, link); err != nil {
			t.Fatal(err)
		}
	}
	save()
	if _, _, err := store.CompleteMagicLink(ctx, link.Key, "first", session, false); !errors.Is(err, auth.ErrMagicLinkSignUpDisabled) {
		t.Fatal(err)
	}
	if _, _, err := store.CompleteMagicLink(ctx, link.Key, "first", session, true); !errors.Is(err, auth.ErrNotFound) {
		t.Fatal("closed-signup proof replayed", err)
	}
	save()
	expired := session
	expired.CreatedAt = link.ExpiresAt
	if _, _, err := store.CompleteMagicLink(ctx, link.Key, "first", expired, true); !errors.Is(err, auth.ErrNotFound) {
		t.Fatal("accepted expired link", err)
	}
	save()
	first, created, err := store.CompleteMagicLink(ctx, link.Key, "first", session, true)
	if err != nil || !created || !first.EmailVerified {
		t.Fatal(first, created, err)
	}
	save()
	_, err = store.ChangeAccountEmail(ctx, first.ID, email, "new@example.test", true, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUser(ctx, auth.User{ID: "second", Email: email}, "credential", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CompleteMagicLink(ctx, link.Key, "unused", session, true); !errors.Is(err, auth.ErrNotFound) {
		t.Fatal("link followed a reassigned mailbox", err)
	}
	owner, _, err := store.Credential(ctx, email)
	if err != nil || owner.ID != "second" || owner.EmailVerified {
		t.Fatal("reassigned mailbox was changed", owner, err)
	}
}
