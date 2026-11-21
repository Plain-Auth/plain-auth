package sqlstore

import (
	"errors"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func TestLegacyOAuthSourceUpgrade(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			old, e := Open(ctx, dialect, dsn)
			must(e)
			defer old.Close()
			now := time.Now().UTC()
			owner := auth.User{ID: "owner", Email: "owner@example.test", Name: "Owner", CreatedAt: now, UpdatedAt: now}
			must(old.CreateUser(ctx, owner, "credential", nil))
			insert := func(id, subject string) {
				_, e := old.db.ExecContext(ctx, old.bind(`INSERT INTO "account" ("id","providerId","accountId","userId","accessToken","createdAt","updatedAt") VALUES (?,'work',?,'owner','historical',?,?)`), id, subject, old.date(now), old.date(now))
				must(e)
			}
			insert("before-profile", "known")
			input := OAuthAccountAttribution{AccountID: "before-profile", UserID: "owner", ProviderID: "work", Subject: "known"}
			cred, e := old.ProviderCredential(ctx, "owner", "before-profile")
			must(e)
			if cred.AccessToken != "historical" {
				t.Fatal("lost static-only compatibility")
			}
			must(old.ReconcileOAuthAccount(ctx, input))
			insert("unknown", "unknown")
			ddl, e := schema.Generate(dialect, []string{"sso"})
			must(e)
			migrated, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer migrated.Close()
			if dialect == "postgres" {
				tx, e := migrated.db.BeginTx(ctx, nil)
				must(e)
				var path string
				must(tx.QueryRowContext(ctx, `SELECT pg_catalog.set_config('search_path','pg_catalog,'||pg_catalog.quote_ident(current_schema()),true)`).Scan(&path))
				_, e = migrated.readProviderCredential(ctx, tx, "owner", "unknown", true)
				must(tx.Rollback())
				if !errors.Is(e, auth.ErrNotFound) {
					t.Fatalf("catalog on a secondary search_path schema did not protect an unmarked account: %v", e)
				}
			}
			// Nodes opened before migration observe the physical schema too.
			for _, store := range []*Store{old, migrated} {
				if _, e = store.ProviderCredential(ctx, "owner", "unknown"); !errors.Is(e, auth.ErrNotFound) {
					t.Fatalf("claimed unclassified historical token: %v", e)
				}
				cred, e = store.ProviderCredential(ctx, "owner", "before-profile")
				must(e)
				if cred.AccessToken != "historical" {
					t.Fatal("classified credential changed after schema migration")
				}
			}
			SS := auth.StoredSession{Session: auth.Session{ID: "legacy-login", Token: "legacy-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			_, _, e = migrated.CompleteOAuth(ctx, "work", "unknown", auth.OAuthTokens{}, owner, SS, auth.OAuthLoginOptions{})
			if !errors.Is(e, auth.ErrOAuthLinkRequired) {
				t.Fatalf("unclassified historical subject accepted: %v", e)
			}
			must(old.ReconcileOAuthAccount(ctx, OAuthAccountAttribution{AccountID: "unknown", UserID: "owner", ProviderID: "work", Subject: "unknown"}))
			user, created, e := migrated.CompleteOAuth(ctx, "work", "unknown", auth.OAuthTokens{}, owner, SS, auth.OAuthLoginOptions{})
			must(e)
			if created || user.ID != "owner" {
				t.Fatal("could not restore original identity after explicit source check")
			}
		})
	}
}
