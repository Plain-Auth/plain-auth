package sqlstore

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

// An enterprise sign-in can link a resolver's chosen user without email
// matching or sign-up rules, and keeps or copies the provider profile.
func TestEnterpriseSelectedUserLogin(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"organization", "sso"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			now := time.Now().UTC().Truncate(time.Millisecond)
			image := "https://directory.example/avatar.png"
			for _, u := range []auth.User{
				{ID: "owner", Name: "Owner", Email: "owner@example.test", CreatedAt: now, UpdatedAt: now},
				{ID: "selected", Name: "Provisioned Employee", Email: "provisioned@example.test", Image: &image, CreatedAt: now, UpdatedAt: now},
				{ID: "other", Name: "Other", Email: "other@example.test", CreatedAt: now, UpdatedAt: now},
			} {
				must(store.CreateUser(ctx, u, "credential", nil))
			}
			pkce := true
			raw, err := json.Marshal(sso.Config{Issuer: "https://idp.example", ClientID: "enterprise-client", ClientSecret: "oidc-secret", AuthorizationEndpoint: "https://idp.example/authorize", TokenEndpoint: "https://idp.example/token", JWKSEndpoint: "https://idp.example/keys", PKCE: &pkce})
			must(err)
			_, err = store.db.ExecContext(ctx, store.bind(`INSERT INTO "ssoProvider" ("id","providerId","issuer","oidcConfig","domain","userId") VALUES (?,?,?,?,?,?)`), "record-acme", "acme", "https://idp.example", string(raw), "acme.example", "owner")
			must(err)
			browser, err := store.FindBrowserProvider(ctx, sso.Selector{ProviderID: "acme"})
			must(err)
			login := func(subject, selected string, update, disableSignUp bool) (auth.User, bool, error) {
				candidate := auth.User{ID: rand.Text(), Name: "Enterprise User", Email: subject + "@acme.example", CreatedAt: now, UpdatedAt: now}
				session := auth.StoredSession{Session: auth.Session{ID: rand.Text(), Token: rand.Text(), CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
				return store.CompleteEnterpriseLogin(ctx, browser.Reference, "member", "acme", subject, auth.OAuthTokens{AccessToken: "access-" + subject}, candidate, session, auth.OAuthLoginOptions{SelectUserID: selected, UpdateSelectedProfile: update, DisableSignUp: disableSignUp})
			}
			count := func(q string, args ...any) int {
				t.Helper()
				var n int
				must(store.db.QueryRowContext(ctx, store.bind(q), args...).Scan(&n))
				return n
			}
			type profile struct {
				name, email string
				image       *string
				verified    bool
			}
			read := func(id string) profile {
				t.Helper()
				var p profile
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "name","email","image","emailVerified" FROM "user" WHERE "id"=?`), id).Scan(&p.name, &p.email, &p.image, &p.verified))
				return p
			}

			if u, created, err := login("employee", "selected", false, true); err != nil || created || u.ID != "selected" {
				t.Fatal("a selected-user login did not sign in the selected user", u.ID, created, err)
			}
			if n := count(`SELECT COUNT(*) FROM "user"`); n != 3 {
				t.Fatal("a selected-user login created a user", n)
			}
			if n := count(`SELECT COUNT(*) FROM "account" WHERE "providerId"=? AND "accountId"=? AND "userId"=?`, "acme", "employee", "selected"); n != 1 {
				t.Fatal("a selected-user login did not link the identity to the selected user")
			}
			if p := read("selected"); p.name != "Provisioned Employee" || p.email != "provisioned@example.test" || p.image == nil || *p.image != image || p.verified {
				t.Fatal("a selected-user login without a profile update changed the user", p)
			}
			if u, _, err := login("employee", "selected", true, false); err != nil || u.Name != "Enterprise User" || u.Email != "employee@acme.example" || u.EmailVerified {
				t.Fatal("UpdateSelectedProfile did not copy the provider profile to the selected user", u, err)
			}
			if p := read("selected"); p.name != "Enterprise User" || p.email != "employee@acme.example" || p.verified {
				t.Fatal("UpdateSelectedProfile did not copy the provider profile to the selected user", p)
			}
			if _, _, err := login("employee", "other", false, false); !errors.Is(err, auth.ErrOAuthAccountAlreadyLinked) {
				t.Fatal("a selected-user login took an identity another user owns", err)
			}
			if n := count(`SELECT COUNT(*) FROM "session" WHERE "userId"=?`, "other"); n != 0 {
				t.Fatal("a refused selected-user login stored a session", n)
			}
			if _, _, err := login("newcomer", "missing", false, false); !errors.Is(err, auth.ErrNotFound) || count(`SELECT COUNT(*) FROM "account" WHERE "accountId"=?`, "newcomer") != 0 {
				t.Fatal("a selected-user login to a missing user did not answer ErrNotFound", err)
			}
		})
	}
}
