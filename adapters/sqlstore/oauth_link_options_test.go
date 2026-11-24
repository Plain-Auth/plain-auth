package sqlstore

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// Trusted providers and different-email links decide inside the login
// transaction on every engine.
func TestOAuthLinkOptionsStore(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			dsn := ":memory:"
			if dialect != "sqlite" {
				name := "AUTH_TEST_" + strings.ToUpper(dialect) + "_DSN"
				if dsn = os.Getenv(name); dsn == "" {
					t.Skipf("set %s", name)
				}
			}
			ctx := context.Background()
			store, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			provider := "links-" + strings.ToLower(rand.Text()[:8])
			// owner creates a user with a live session.
			owner := func(verified bool) (auth.User, string) {
				u := testUser(strings.ToLower(rand.Text()))
				u.EmailVerified = verified
				session := testSession(u, rand.Text())
				if err := store.CreateUser(ctx, u, "hash", &session); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _, _ = store.db.ExecContext(ctx, store.bind(`DELETE FROM "user" WHERE "id"=?`), u.ID) })
				return u, session.Token
			}
			complete := func(subject, email string, verified bool, options auth.OAuthLoginOptions) (auth.User, error) {
				candidate := testUser(strings.ToLower(rand.Text()))
				candidate.Email, candidate.EmailVerified = email, verified
				u, _, err := store.CompleteOAuth(ctx, provider, subject, auth.OAuthTokens{AccessToken: "access"}, candidate, testSession(candidate, rand.Text()), options)
				if err == nil {
					t.Cleanup(func() {
						_, _ = store.db.ExecContext(ctx, store.bind(`DELETE FROM "account" WHERE "providerId"=? AND "accountId"=?`), provider, subject)
					})
				}
				return u, err
			}
			trusted := auth.OAuthLoginOptions{TrustedProvider: true}

			// Sign-in: trust stands in for the provider's verified email, never for the local one.
			verified, _ := owner(true)
			if u, err := complete(rand.Text(), verified.Email, false, trusted); err != nil || u.ID != verified.ID || !u.EmailVerified {
				t.Fatal("a trusted provider did not link to the verified owner", u, err)
			}
			if _, err := complete(rand.Text(), verified.Email, false, auth.OAuthLoginOptions{AllowVerifiedEmailLink: true}); !errors.Is(err, auth.ErrOAuthLinkRequired) {
				t.Fatal("an untrusted provider linked an unverified email", err)
			}
			unverified, _ := owner(false)
			if _, err := complete(rand.Text(), unverified.Email, true, trusted); !errors.Is(err, auth.ErrOAuthLinkRequired) {
				t.Fatal("a trusted provider linked to an unverified owner", err)
			}
			if _, err := complete(rand.Text(), verified.Email, false, auth.OAuthLoginOptions{TrustedProvider: true, DisableImplicitLinking: true}); !errors.Is(err, auth.ErrOAuthLinkRequired) {
				t.Fatal("trust overrode DisableImplicitLinking", err)
			}

			// Explicit links.
			u, token := owner(true)
			link := func(o auth.OAuthLoginOptions) auth.OAuthLoginOptions {
				o.LinkUserID, o.LinkSessionToken = u.ID, token
				return o
			}
			if _, err := complete(rand.Text(), u.Email, false, link(auth.OAuthLoginOptions{})); !errors.Is(err, auth.ErrOAuthLinkNotAllowed) {
				t.Fatal("an untrusted unverified identity linked", err)
			}
			owned := rand.Text()
			if got, err := complete(owned, u.Email, false, link(trusted)); err != nil || got.ID != u.ID {
				t.Fatal("a trusted unverified identity did not link", got, err)
			}
			if _, err := complete(rand.Text(), "else@example.net", true, link(auth.OAuthLoginOptions{})); !errors.Is(err, auth.ErrOAuthLinkEmailMismatch) {
				t.Fatal("a different email linked", err)
			}
			// With AllowDifferentEmails the identity joins the signed-in user
			// even when its email belongs to someone else.
			other, _ := owner(true)
			if got, err := complete(rand.Text(), other.Email, true, link(auth.OAuthLoginOptions{AllowDifferentEmails: true})); err != nil || got.ID != u.ID || got.Email != u.Email {
				t.Fatal("AllowDifferentEmails did not link to the signed-in user", got, err)
			}
			// A browser link checks trust, then the email, then who owns the
			// identity, and an owned identity goes through the same checks.
			taken := rand.Text()
			if _, err := complete(taken, other.Email, true, auth.OAuthLoginOptions{AllowVerifiedEmailLink: true}); err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				subject, email string
				verified       bool
				want           error
			}{
				{taken, u.Email, false, auth.ErrOAuthLinkNotAllowed},
				{taken, other.Email, true, auth.ErrOAuthLinkEmailMismatch},
				{taken, u.Email, true, auth.ErrOAuthAccountAlreadyLinked},
				{owned, "renamed@example.net", true, auth.ErrOAuthLinkEmailMismatch},
				{owned, u.Email, false, auth.ErrOAuthLinkNotAllowed},
				{owned, u.Email, true, nil},
			} {
				if _, err := complete(tc.subject, tc.email, tc.verified, link(auth.OAuthLoginOptions{})); !errors.Is(err, tc.want) {
					t.Errorf("browser link of %s as %s (verified %v): got %v, want %v", tc.subject, tc.email, tc.verified, err, tc.want)
				}
			}
			// An ID-token link settles ownership first: the owner refreshes their
			// identity whatever the claims, and another user's is refused.
			idToken := func(subject, email string) error {
				o := link(auth.OAuthLoginOptions{IDTokenValidUntil: time.Now().Add(time.Hour)})
				copy(o.IDTokenHash[:], rand.Text())
				_, err := complete(subject, email, false, o)
				return err
			}
			if err := idToken(owned, "renamed@example.net"); err != nil {
				t.Fatal("the owner could not refresh their own identity with an ID token", err)
			}
			if err := idToken(taken, "else@example.net"); !errors.Is(err, auth.ErrOAuthAccountAlreadyLinked) {
				t.Fatal("an ID token linked another user's identity", err)
			}
		})
	}
}
