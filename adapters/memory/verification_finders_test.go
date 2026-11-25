package memory

import (
	"errors"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// The memory store's finders read a live magic link or one-time token
// without spending it, still find one whose session has since ended, and
// report ErrNotFound for an expired or unknown one without deleting it.
func TestMemoryVerificationFinders(t *testing.T) {
	ctx := t.Context()
	db := New()
	now := time.Now().UTC().Truncate(time.Millisecond)
	owner := auth.User{ID: "owner", Email: "owner@finder.example", EmailVerified: true, CreatedAt: now, UpdatedAt: now}
	row := auth.StoredSession{Session: auth.Session{ID: "source", UserID: owner.ID, Token: "source-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
	if err := db.CreateUser(ctx, owner, "", &row); err != nil {
		t.Fatal(err)
	}
	for key, expires := range map[string]time.Time{"live-link": now.Add(time.Minute), "stale-link": now.Add(-time.Minute)} {
		if err := db.SaveMagicLink(ctx, auth.MagicLinkChallenge{Key: key, Email: owner.Email, Name: "Owner", CreatedAt: now.Add(-time.Hour), ExpiresAt: expires}); err != nil {
			t.Fatal(err)
		}
	}
	link, err := db.FindMagicLink(ctx, "live-link", now)
	if err != nil || link.Email != owner.Email || link.Name != "Owner" || !link.ExpiresAt.After(now) {
		t.Fatal("a live magic link was found as", link, err)
	}
	for _, key := range []string{"stale-link", "unknown"} {
		if _, err := db.FindMagicLink(ctx, key, now); !errors.Is(err, auth.ErrNotFound) {
			t.Fatal("FindMagicLink for", key, "answered", err)
		}
	}
	if _, ok := db.magicLinks["stale-link"]; !ok {
		t.Fatal("finding an expired link deleted it")
	}
	returning := auth.StoredSession{Session: auth.Session{ID: "link-session", Token: "link-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
	if _, _, err := db.CompleteMagicLink(ctx, "live-link", "unused", returning, true); err != nil {
		t.Fatal("finding the link spent it:", err)
	}

	if err := db.SaveOneTimeToken(ctx, "transfer", row.Session, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	userID, expires, err := db.FindOneTimeToken(ctx, "transfer", now)
	if err != nil || userID != owner.ID || !expires.After(now) {
		t.Fatal("a live one-time token was found as", userID, expires, err)
	}
	if _, _, err := db.FindOneTimeToken(ctx, "transfer", now.Add(2*time.Minute)); !errors.Is(err, auth.ErrNotFound) {
		t.Fatal("an expired one-time token answered", err)
	}
	if err := db.DeleteSession(ctx, row.Token); err != nil {
		t.Fatal(err)
	}
	if found, _, err := db.FindOneTimeToken(ctx, "transfer", now); err != nil || found != owner.ID {
		t.Fatal("a token whose session ended was not found:", err)
	}
	if _, err := db.ConsumeOneTimeToken(ctx, "transfer", now); !errors.Is(err, auth.ErrTransferSessionMissing) {
		t.Fatal("finding the token spent it, or the consume answered", err)
	}
}
