package sqlstore

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

// Create organizations over HTTP under host permission checks, a fixed
// membership-based limit and a host-defined limit.
func TestOrganizationCreationPolicy(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			denied := func(err error, code string) {
				t.Helper()
				var problem *auth.APIError
				if !errors.As(err, &problem) || problem.Status != 403 || problem.Code != code {
					t.Fatalf("want 403 %s, got %v", code, err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			store, err := OpenWithOptions(ctx, dialect, dsn, []string{"organization"}, schema.Options{})
			must(err)
			t.Cleanup(func() { store.Close() })
			peer, err := Open(ctx, dialect, dsn)
			must(err)
			t.Cleanup(func() { peer.Close() })
			count := func(q string, args ...any) int {
				t.Helper()
				var n int
				must(store.db.QueryRowContext(ctx, store.bind(q), args...).Scan(&n))
				return n
			}
			now := time.Now().UTC().Truncate(time.Millisecond)
			account := func(id string) auth.Session {
				t.Helper()
				user := auth.User{ID: id, Name: id, Email: id + "@example.test", CreatedAt: now, UpdatedAt: now}
				session := auth.StoredSession{Session: auth.Session{ID: id + "-s", Token: id + "-t", UserID: id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
				must(store.CreateUser(ctx, user, "", &session))
				return session.Session
			}
			ada, blocked, host := account("Ada"), account("Blocked"), account("Host")
			create := func(sdk *client.Client, slug string) error {
				_, err := sdk.CreateOrganization(ctx, client.CreateOrganizationRequest{Name: slug, Slug: slug})
				return err
			}

			// A fixed limit counts every membership, including ones the user did not create.
			limited, err := org.NewService(org.Options{Store: store, OrganizationLimit: 2})
			must(err)
			adaHTTP := organizationRoleClient(t, store, limited, ada)
			created, err := adaHTTP.CreateOrganization(ctx, client.CreateOrganizationRequest{Name: "First", Slug: "first", KeepCurrentActiveOrganization: true})
			must(err)
			if created.Slug != "first" || len(created.Members) != 1 || created.Members[0].UserID != ada.UserID || created.Members[0].Role != "owner" {
				t.Fatal("unexpected created organization", created)
			}
			hosted := org.Organization{ID: "Hosted", Name: "Hosted", Slug: "hosted", CreatedAt: now}
			must(store.CreateOrganization(ctx, hosted, org.Member{ID: "host-m", UserID: host.UserID, OrganizationID: hosted.ID, Role: "owner", CreatedAt: now}, host.ID, false))
			must(store.AddOrganizationMember(ctx, org.Member{ID: "ada-m", UserID: ada.UserID, OrganizationID: hosted.ID, Role: "member", CreatedAt: now}, ""))
			denied(create(adaHTTP, "third"), "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS")
			if count(`SELECT COUNT(*) FROM "organization" WHERE "slug"='third'`) != 0 {
				t.Fatal("a refused creation stored the organization")
			}

			// Two instances racing for the creator's last slot admit one organization.
			_, err = store.db.ExecContext(ctx, store.bind(`DELETE FROM "member" WHERE "id"='ada-m'`))
			must(err)
			second, err := org.NewService(org.Options{Store: peer, OrganizationLimit: 2})
			must(err)
			var wg sync.WaitGroup
			results := make([]error, 2)
			for i, sdk := range []*client.Client{adaHTTP, organizationRoleClient(t, peer, second, ada)} {
				wg.Add(1)
				go func() { defer wg.Done(); results[i] = create(sdk, []string{"race-a", "race-b"}[i]) }()
			}
			wg.Wait()
			if (results[0] == nil) == (results[1] == nil) {
				t.Fatal("concurrent creations did not share the last slot", results)
			}
			for _, err := range results {
				if err != nil {
					denied(err, "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS")
				}
			}
			if n := count(`SELECT COUNT(*) FROM "member" WHERE "userId"=?`, ada.UserID); n != 2 {
				t.Fatal("the creator exceeded the organization limit", n)
			}

			// The host decides who may create and when a plan is full.
			var seen []string
			planErr := errors.New("plan service unavailable")
			full, failing := false, false
			guarded, err := org.NewService(org.Options{
				Store: store,
				AllowUserToCreateOrganization: func(_ context.Context, user auth.User) (bool, error) {
					seen = append(seen, user.ID+":"+user.Email)
					return user.ID != blocked.UserID, nil
				},
				OrganizationLimitReached: func(context.Context, auth.User) (bool, error) {
					if failing {
						return false, planErr
					}
					return full, nil
				},
			})
			must(err)
			denied(create(organizationRoleClient(t, store, guarded, blocked), "blocked"), "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION")
			hostHTTP := organizationRoleClient(t, store, guarded, host)
			full = true
			denied(create(hostHTTP, "full"), "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS")
			full, failing = false, true
			var problem *auth.APIError
			if err := create(hostHTTP, "failing"); err == nil || errors.As(err, &problem) && problem.Status < 500 {
				t.Fatal("a failing plan lookup did not fail the creation", err)
			}
			failing = false
			must(create(hostHTTP, "allowed"))
			if len(seen) != 4 || seen[0] != "Blocked:blocked@example.test" || seen[3] != "Host:host@example.test" {
				t.Fatal("the creation policy saw the wrong users", seen)
			}
			if count(`SELECT COUNT(*) FROM "organization" WHERE "slug" IN ('blocked','full','failing')`) != 0 {
				t.Fatal("a refused creation stored the organization")
			}

			for _, bad := range []org.Options{
				{Store: store, OrganizationLimit: -1},
				{Store: store, OrganizationLimit: 3, OrganizationLimitReached: func(context.Context, auth.User) (bool, error) { return false, nil }},
			} {
				if _, err := org.NewService(bad); err == nil {
					t.Fatal("accepted an invalid organization limit")
				}
			}
		})
	}
}
