package memory

import (
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// With DisableVerificationCleanup the memory store keeps expired entries of
// other keys, still refuses them, and replaces an expired entry whose key a
// write reuses. A store fixed to one setting refuses the other, and a store
// that cannot keep expired records refuses the option.
func TestDisableVerificationCleanup(t *testing.T) {
	ctx := t.Context()
	start := func(store auth.Store, keep bool) error {
		_, err := auth.New(auth.Options{Store: store, BaseURL: "https://cleanup.example", Secret: strings.Repeat("s", 40), DisableVerificationCleanup: keep})
		return err
	}
	kept, swept := New(), New()
	if err := start(kept, true); err != nil {
		t.Fatal(err)
	}
	if err := start(kept, false); err == nil {
		t.Fatal("a store keeping expired entries was started with cleanup on")
	}
	if err := start(swept, false); err != nil {
		t.Fatal(err)
	}
	if err := start(swept, true); err == nil {
		t.Fatal("a sweeping store was started with cleanup off")
	}
	if err := start(struct{ auth.Store }{New()}, true); err == nil {
		t.Fatal("a store without VerificationCleanupStore accepted the option")
	}
	free := New()
	if _, err := auth.New(auth.Options{Store: free, BaseURL: "https://cleanup.example", Secret: "short", DisableVerificationCleanup: true}); err == nil {
		t.Fatal("a short secret was accepted")
	}
	if err := start(free, false); err != nil {
		t.Fatal("a failed New fixed the store's setting:", err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	past, earlier := now.Add(-time.Hour), now.Add(-2*time.Hour)
	owner := auth.User{ID: "owner", Email: "owner@cleanup.example", CreatedAt: earlier, UpdatedAt: earlier}
	session := auth.StoredSession{Session: auth.Session{ID: "source", UserID: owner.ID, Token: "source-token", CreatedAt: earlier, UpdatedAt: earlier, ExpiresAt: now.Add(time.Hour)}}
	for _, store := range []*Store{kept, swept} {
		row := session
		if err := store.CreateUser(ctx, owner, "", &row); err != nil {
			t.Fatal(err)
		}
	}
	for _, store := range []*Store{kept, swept} {
		for _, token := range []string{"reset-a", "reset-b"} {
			if err := store.SavePasswordResetToken(ctx, auth.PasswordResetToken{ID: token, Token: token, UserID: owner.ID, Email: owner.Email, CreatedAt: earlier, ExpiresAt: past}); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.SavePasswordResetToken(ctx, auth.PasswordResetToken{ID: "reset-c", Token: "reset-c", UserID: owner.ID, Email: owner.Email, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"link-a", "link-b", "link-a"} {
			at, expires := earlier, past
			if _, exists := store.magicLinks[key]; exists {
				at, expires = now, now.Add(time.Hour)
			}
			if err := store.SaveMagicLink(ctx, auth.MagicLinkChallenge{Key: key, Email: owner.Email, CreatedAt: at, ExpiresAt: expires}); err != nil {
				t.Fatal("saving magic link", key, "failed:", err)
			}
		}
		for _, key := range []string{"transfer-a", "transfer-b", "transfer-a"} {
			at, expires := earlier, past
			if _, exists := store.transfers[key]; exists {
				at, expires = now, now.Add(time.Hour)
			}
			if err := store.SaveOneTimeToken(ctx, key, session.Session, at, expires); err != nil {
				t.Fatal("saving transfer", key, "failed:", err)
			}
		}
	}
	if len(kept.resets) != 3 || len(kept.magicLinks) != 2 || len(kept.transfers) != 2 {
		t.Fatal("the keeping store holds", len(kept.resets), len(kept.magicLinks), len(kept.transfers))
	}
	if len(swept.resets) != 1 || len(swept.magicLinks) != 1 || len(swept.transfers) != 1 {
		t.Fatal("the sweeping store holds", len(swept.resets), len(swept.magicLinks), len(swept.transfers))
	}
	if _, err := kept.FindPasswordResetToken(ctx, "reset-a", now); !errors.Is(err, auth.ErrNotFound) {
		t.Fatal("a kept expired reset token answered", err)
	}
	if _, err := kept.ConsumeOneTimeToken(ctx, "transfer-b", now); !errors.Is(err, auth.ErrNotFound) {
		t.Fatal("a kept expired transfer answered", err)
	}
	if _, err := kept.ConsumeOneTimeToken(ctx, "transfer-a", now); err != nil {
		t.Fatal("a replaced transfer was refused:", err)
	}
}
