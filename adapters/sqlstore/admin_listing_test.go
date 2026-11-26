package sqlstore

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"slices"
	"strings"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/admin"
	"github.com/Plain-Org/plain-auth/schema"
)

// User listing applies the pattern and equality operators and echoes page
// bounds; session listing and revocation cover every session of a user
// signed in on several clients; and a password set for an account without
// one signs in.
func TestAdminListingAndSessionsAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"admin"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			p, err := admin.New(admin.Options{})
			must(err)
			const origin = "https://listing.example"
			off := false
			service, err := authn.New(authn.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("l", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []authn.Plugin{p}})
			must(err)
			browser := func() *client.Client {
				jar, err := cookiejar.New(nil)
				must(err)
				c, err := client.New(origin, &http.Client{Jar: jar, Transport: guestTransport{service}})
				must(err)
				return c
			}
			root, err := service.AdminCreateUser(ctx, authn.AdminCreateUserRequest{Name: "Root", Email: "root@example.test", Password: "root-password-phrase", Role: []string{"admin"}})
			must(err)
			rootClient := browser()
			_, err = rootClient.SignInEmail(ctx, client.SignInRequest{Email: "root@example.test", Password: "root-password-phrase"})
			must(err)
			signUp := func(name, email string) (*client.Client, *client.EmailResult) {
				t.Helper()
				c := browser()
				res, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: name, Email: email, Password: "listing-password"})
				must(err)
				return c, res
			}
			anaClient, ana := signUp("Ana", "ana@alpha.test")
			bobClient, bob := signUp("Bob", "bob@beta.test")
			_, cara := signUp("Cara", "cara@alpha.test")
			ids := func(page *authn.AdminPage) []string {
				var out []string
				for _, u := range page.Users {
					out = append(out, u.ID)
				}
				return out
			}
			list := func(q authn.AdminQuery) *authn.AdminPage {
				t.Helper()
				page, err := rootClient.AdminListUsers(ctx, q)
				must(err)
				return page
			}
			if page := list(authn.AdminQuery{SearchField: "name", SearchOperator: "starts_with", SearchValue: "Ca"}); page.Total != 1 || !slices.Equal(ids(page), []string{cara.User.ID}) {
				t.Fatal("starts_with name search", page)
			}
			if page := list(authn.AdminQuery{SearchField: "email", SearchOperator: "ends_with", SearchValue: "@alpha.test", SortBy: "email", SortDirection: "asc"}); page.Total != 2 || !slices.Equal(ids(page), []string{ana.User.ID, cara.User.ID}) {
				t.Fatal("ends_with email search", page)
			}
			if page := list(authn.AdminQuery{SearchField: "email", SearchOperator: "starts_with", SearchValue: "_"}); page.Total != 0 || len(page.Users) != 0 {
				t.Fatal("a starts_with search matched a LIKE wildcard", page)
			}
			if page := list(authn.AdminQuery{FilterField: "email", FilterOperator: "eq", FilterValues: []string{"bob@beta.test"}}); page.Total != 1 || !slices.Equal(ids(page), []string{bob.User.ID}) {
				t.Fatal("eq email filter", page)
			}
			if page := list(authn.AdminQuery{FilterField: "role", FilterOperator: "eq", FilterValues: []string{"admin"}}); page.Total != 1 || !slices.Equal(ids(page), []string{root.ID}) {
				t.Fatal("eq role filter", page)
			}
			var paged map[string]json.RawMessage
			must(rootClient.Do(ctx, http.MethodGet, "/admin/list-users?sortBy=email&limit=2&offset=1", nil, &paged))
			if string(paged["limit"]) != "2" || string(paged["offset"]) != "1" || string(paged["total"]) != "4" {
				t.Fatal("a paged listing did not echo its limit and offset", paged)
			}
			var pagedUsers []authn.User
			must(json.Unmarshal(paged["users"], &pagedUsers))
			if len(pagedUsers) != 2 || pagedUsers[0].ID != bob.User.ID || pagedUsers[1].ID != cara.User.ID {
				t.Fatal("a paged listing returned the wrong accounts", pagedUsers)
			}
			var whole map[string]json.RawMessage
			must(rootClient.Do(ctx, http.MethodGet, "/admin/list-users", nil, &whole))
			_, limit := whole["limit"]
			_, offset := whole["offset"]
			if limit || offset || string(whole["total"]) != "4" {
				t.Fatal("an unpaged listing echoed limit or offset", whole)
			}

			anaClients := []*client.Client{anaClient}
			tokens := []string{*ana.Token}
			for range 2 {
				c := browser()
				res, err := c.SignInEmail(ctx, client.SignInRequest{Email: "ana@alpha.test", Password: "listing-password"})
				must(err)
				anaClients = append(anaClients, c)
				tokens = append(tokens, *res.Token)
			}
			expired := testSession(ana.User, "ana-expired")
			expired.ExpiresAt = time.Now().Add(-time.Minute)
			must(store.CreateSession(ctx, expired))
			listed, err := rootClient.AdminListUserSessions(ctx, ana.User.ID)
			must(err)
			seen := map[string]bool{}
			for _, s := range listed {
				if s.UserID != ana.User.ID || seen[s.ID] || !strings.HasPrefix(s.Token, "revoke.") || slices.Contains(tokens, s.Token) || s.ID == expired.ID {
					t.Fatal("the listing missed one of the user's sessions", listed)
				}
				seen[s.ID] = true
			}
			if len(listed) != 3 {
				t.Fatal("the listing missed one of the user's sessions", listed)
			}
			must(rootClient.AdminRevokeUserSessions(ctx, ana.User.ID))
			for i, c := range anaClients {
				if s, err := c.GetSession(ctx); err != nil || s != nil {
					t.Fatal("a session survived revoke-user-sessions", i, err)
				}
			}
			if s, err := bobClient.GetSession(ctx); err != nil || s == nil || s.User.ID != bob.User.ID {
				t.Fatal("revoking one user's sessions ended another user's", err)
			}
			if after, err := rootClient.AdminListUserSessions(ctx, ana.User.ID); err != nil || len(after) != 0 {
				t.Fatal("revoked sessions are still listed", after, err)
			}

			dana, err := rootClient.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Dana", Email: "dana@alpha.test"})
			must(err)
			danaClient := browser()
			var refused *authn.APIError
			if _, err := danaClient.SignInEmail(ctx, client.SignInRequest{Email: "dana@alpha.test", Password: "dana-admin-set-password"}); !errors.As(err, &refused) || refused.Code != "INVALID_EMAIL_OR_PASSWORD" {
				t.Fatal("an account without a password signed in", err)
			}
			credentials := func() int {
				var n int
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "account" WHERE "userId"=? AND "providerId"='credential'`), dana.ID).Scan(&n))
				return n
			}
			if n := credentials(); n != 0 {
				t.Fatal("an account created without a password has a credential", n)
			}
			must(rootClient.AdminSetPassword(ctx, dana.ID, "dana-admin-set-password"))
			if n := credentials(); n != 1 {
				t.Fatal("set-user-password did not create one credential account", n)
			}
			if signed, err := danaClient.SignInEmail(ctx, client.SignInRequest{Email: "dana@alpha.test", Password: "dana-admin-set-password"}); err != nil || signed.User.ID != dana.ID {
				t.Fatal("a password set for an account without one does not sign in", err)
			}
		})
	}
}
