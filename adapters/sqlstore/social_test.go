package sqlstore

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
)

func TestSocialStore(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			dsn := ":memory:"
			if dialect != "sqlite" {
				name := "AUTH_TEST_" + strings.ToUpper(dialect) + "_DSN"
				dsn = os.Getenv(name)
				if dsn == "" {
					t.Skipf("set %s", name)
				}
			}
			ctx := context.Background()
			store, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			now := time.Now().UTC().Truncate(time.Millisecond)
			flow := auth.OAuthFlow{State: rand.Text(), Binding: rand.Text(), Provider: "demo", ExpiresAt: now.Add(time.Minute)}
			if err := store.SaveOAuthFlow(ctx, flow, now); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ConsumeOAuthFlow(ctx, flow.State, "wrong", now); !errors.Is(err, auth.ErrNotFound) {
				t.Fatalf("foreign binding: %v", err)
			}
			if _, err := store.ConsumeOAuthFlow(ctx, flow.State, flow.Binding, flow.ExpiresAt); !errors.Is(err, auth.ErrNotFound) {
				t.Fatalf("expiry boundary: %v", err)
			}
			var wg sync.WaitGroup
			results := make(chan error, 2)
			for i := 0; i < 2; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := store.ConsumeOAuthFlow(ctx, flow.State, flow.Binding, now)
					results <- err
				}()
			}
			wg.Wait()
			close(results)
			var accepted, spent int
			for err := range results {
				if err == nil {
					accepted++
				} else if errors.Is(err, auth.ErrNotFound) {
					spent++
				} else {
					t.Fatal(err)
				}
			}
			if accepted != 1 || spent != 1 {
				t.Fatalf("accepted %d, spent %d", accepted, spent)
			}

			cred := testUser(rand.Text())
			if err := store.CreateUser(ctx, cred, "hash", nil); err != nil {
				t.Fatal(err)
			}
			remove := func(id string) {
				if _, err := store.db.ExecContext(ctx, store.bind(`DELETE FROM "user" WHERE "id"=?`), id); err != nil {
					t.Error(err)
				}
			}
			defer remove(cred.ID)
			subject := rand.Text()
			candidate := testUser(rand.Text())
			candidate.EmailVerified = true
			candidate.Email = cred.Email
			tokens := auth.OAuthTokens{AccessToken: "first", RefreshToken: "renew", ExpiresAt: now.Add(time.Hour)}
			session := testSession(candidate, rand.Text())
			if _, _, err := store.CompleteOAuth(ctx, "demo", subject, tokens, candidate, session, auth.OAuthLoginOptions{AllowVerifiedEmailLink: true}); !errors.Is(err, auth.ErrOAuthLinkRequired) {
				t.Fatalf("linked unverified local email: %v", err)
			}
			if _, _, err := store.Session(ctx, session.Token); !errors.Is(err, auth.ErrNotFound) {
				t.Fatalf("created session on collision: %v", err)
			}
			if _, err = store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "emailVerified"=? WHERE "id"=?`), true, cred.ID); err != nil {
				t.Fatal(err)
			}
			actual, created, err := store.CompleteOAuth(ctx, "demo", subject, tokens, candidate, session, auth.OAuthLoginOptions{AllowVerifiedEmailLink: true})
			if err != nil || created || actual.ID != cred.ID {
				t.Fatalf("verified link %#v, %v, %v", actual, created, err)
			}
			saved, owner, err := store.Session(ctx, session.Token)
			if err != nil || owner.ID != cred.ID || saved.UserID != cred.ID {
				t.Fatalf("session owner %#v, %v", owner, err)
			}
			tokens.AccessToken = "second"
			tokens.RefreshToken = ""
			candidate.Email = "different-" + strings.ToLower(rand.Text()) + "@example.org"
			actual, created, err = store.CompleteOAuth(ctx, "demo", subject, tokens, candidate, testSession(candidate, rand.Text()), auth.OAuthLoginOptions{})
			if err != nil || created || actual.ID != cred.ID {
				t.Fatalf("existing subject unexpectedly changed identity %#v, %v, %v", actual, created, err)
			}
			var access, refresh string
			err = store.db.QueryRowContext(ctx, store.bind(`SELECT "accessToken","refreshToken" FROM "account" WHERE "providerId"=? AND "accountId"=?`), "demo", subject).Scan(&access, &refresh)
			if err != nil || access != "second" || refresh != "renew" {
				t.Fatalf("tokens after login %q %q %v", access, refresh, err)
			}
		})
	}
}
