package sqlstore

import (
	"errors"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

func TestOAuthAccountUpdateOnSignIn(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			store, err := Open(ctx, dialect, organizationTestDSN(t, dialect))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			owner := testUser("account-owner")
			owner.EmailVerified = true
			now := owner.CreatedAt
			session := func(id string, age time.Duration) auth.StoredSession {
				draft := testSession(owner, id)
				draft.CreatedAt = now.Add(age)
				draft.UpdatedAt = draft.CreatedAt
				return draft
			}
			initial := auth.OAuthTokens{AccessToken: "first", RefreshToken: "offline", IDToken: "initial-id", Scope: "profile,email",
				ExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour)}
			preserve := auth.OAuthLoginOptions{DisableAccountUpdateOnSignIn: true}
			first := session("registration", 0)
			user, created, err := store.CompleteOAuth(ctx, "work", "subject", initial, owner, first, preserve)
			if err != nil || !created || user.ID != owner.ID {
				t.Fatalf("registration: created %t, error %v", created, err)
			}
			accounts, err := store.ListUserAccounts(ctx, owner.ID)
			if err != nil || len(accounts) != 1 {
				t.Fatalf("accounts after registration: %d, error %v", len(accounts), err)
			}
			account := accounts[0].ID
			check := func(want auth.OAuthTokens, updated time.Time) {
				t.Helper()
				row, err := store.ProviderCredential(ctx, owner.ID, account)
				if err != nil || row.AccessToken != want.AccessToken || row.RefreshToken != want.RefreshToken ||
					row.IDToken != want.IDToken || row.Scope != want.Scope || !row.ExpiresAt.Equal(want.ExpiresAt) || !row.RefreshExpiresAt.Equal(want.RefreshExpiresAt) {
					t.Fatalf("stored grant differs from expected values: %v", err)
				}
				var modified time.Time
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "updatedAt" FROM "account" WHERE "id"=?`), account).Scan(&modified); err != nil || !modified.Equal(updated) {
					t.Fatalf("account updated at %v, want %v, error %v", modified, updated, err)
				}
			}
			check(initial, now)
			next := auth.OAuthTokens{AccessToken: "second", RefreshToken: "rotated", IDToken: "single-use", Scope: "write",
				ExpiresAt: now.Add(2 * time.Hour), RefreshExpiresAt: now.Add(48 * time.Hour)}
			preserve.IDTokenValidUntil = now.Add(time.Hour)
			returning := session("returning", time.Minute)
			user, created, err = store.CompleteOAuth(ctx, "work", "subject", next, owner, returning, preserve)
			if err != nil || created || user.ID != owner.ID {
				t.Fatalf("returning sign-in: created %t, error %v", created, err)
			}
			if _, u, err := store.Session(ctx, returning.Token); err != nil || u.ID != owner.ID {
				t.Fatalf("returning session owner: %v", err)
			}
			replay := session("replay", 2*time.Minute)
			if _, _, err := store.CompleteOAuth(ctx, "work", "subject", next, owner, replay, preserve); !errors.Is(err, auth.ErrIDTokenUsed) {
				t.Fatalf("replayed ID token: %v", err)
			}
			if _, _, err := store.Session(ctx, replay.Token); !errors.Is(err, auth.ErrNotFound) {
				t.Fatalf("session after replay: %v", err)
			}
			check(initial, now)

			renew := session("renew", 3*time.Minute)
			if _, _, err := store.CompleteOAuth(ctx, "work", "subject", auth.OAuthTokens{AccessToken: "fresh", Scope: "ignored"}, owner, renew, auth.OAuthLoginOptions{}); err != nil {
				t.Fatal(err)
			}
			initial.AccessToken = "fresh"
			check(initial, renew.CreatedAt)

			link := auth.OAuthLoginOptions{LinkUserID: owner.ID, LinkSessionToken: first.Token, DisableAccountUpdateOnSignIn: true}
			approval := session("approval", 4*time.Minute)
			next.Scope = "email,write,write"
			if _, _, err := store.RefreshOwnedOAuthLink(ctx, "work", "subject", next, owner, approval, link); err != nil {
				t.Fatal(err)
			}
			next.Scope = "profile,email,write"
			check(next, approval.CreatedAt)
		})
	}
}
