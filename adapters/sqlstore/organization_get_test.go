package sqlstore

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

// Read an organization over HTTP and clear the session's selection after a
// lookup the caller is refused.
func TestGetOrganizationClearsDeniedSelection(t *testing.T) {
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
			code := func(err error, status int, want string) {
				t.Helper()
				var problem *auth.APIError
				if !errors.As(err, &problem) || problem.Status != status || problem.Code != want {
					t.Fatalf("want %d %s, got %v", status, want, err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			store, err := OpenWithOptions(ctx, dialect, dsn, []string{"organization"}, schema.Options{})
			must(err)
			t.Cleanup(func() { store.Close() })
			now := time.Now().UTC().Truncate(time.Millisecond)
			account := func(id string) auth.Session {
				t.Helper()
				user := auth.User{ID: id, Name: id, Email: id + "@example.test", CreatedAt: now, UpdatedAt: now}
				session := auth.StoredSession{Session: auth.Session{ID: id + "-s", Token: id + "-t", UserID: id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
				must(store.CreateUser(ctx, user, "", &session))
				return session.Session
			}
			ada, lin, max := account("Ada"), account("Lin"), account("Max")
			acme := org.Organization{ID: "Acme", Name: "Acme", Slug: "acme", CreatedAt: now}
			other := org.Organization{ID: "Other", Name: "Other", Slug: "other", CreatedAt: now}
			must(store.CreateOrganization(ctx, acme, org.Member{ID: "ada-m", UserID: ada.UserID, OrganizationID: acme.ID, Role: "owner", CreatedAt: now}, ada.ID, false))
			must(store.CreateOrganization(ctx, other, org.Member{ID: "lin-m", UserID: lin.UserID, OrganizationID: other.ID, Role: "owner", CreatedAt: now}, lin.ID, false))
			must(store.AddOrganizationMember(ctx, org.Member{ID: "max-m", UserID: max.UserID, OrganizationID: acme.ID, Role: "member", CreatedAt: now}, ""))
			service, err := org.NewService(org.Options{Store: store})
			must(err)
			selection := func(s auth.Session) *string {
				t.Helper()
				var id *string
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "activeOrganizationId" FROM "session" WHERE "id"=?`), s.ID).Scan(&id))
				return id
			}
			selectOrg := func(s auth.Session, id string) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(`UPDATE "session" SET "activeOrganizationId"=? WHERE "id"=?`), id, s.ID)
				must(err)
			}
			adaHTTP := organizationRoleClient(t, store, service, ada)

			// A member reads the selected organization, or one named by ID or slug.
			for _, lookup := range [][2]string{{"", ""}, {acme.ID, ""}, {"", acme.Slug}} {
				got, err := adaHTTP.Organization(ctx, lookup[0], lookup[1])
				must(err)
				if got == nil || got.ID != acme.ID || selection(ada) == nil {
					t.Fatal("a member lookup failed or changed the selection", lookup, got)
				}
			}
			_, err = adaHTTP.Organization(ctx, "missing", "")
			code(err, 400, "ORGANIZATION_NOT_FOUND")
			if selection(ada) == nil {
				t.Fatal("an unknown organization cleared the selection")
			}

			// A refused lookup by ID or slug clears the caller's selection.
			_, err = adaHTTP.Organization(ctx, other.ID, "")
			code(err, 403, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
			if selection(ada) != nil {
				t.Fatal("a refused lookup kept the selection")
			}
			selectOrg(ada, acme.ID)
			_, err = adaHTTP.Organization(ctx, "", other.Slug)
			code(err, 403, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
			if selection(ada) != nil {
				t.Fatal("a refused lookup by slug kept the selection")
			}
			got, err := adaHTTP.Organization(ctx, "", "")
			if err != nil || got != nil {
				t.Fatal("a cleared selection still resolved", got, err)
			}

			// A former member's stale selection is cleared when they look it up.
			selectOrg(max, acme.ID)
			_, err = store.db.ExecContext(ctx, store.bind(`DELETE FROM "member" WHERE "id"='max-m'`))
			must(err)
			_, err = organizationRoleClient(t, store, service, max).Organization(ctx, acme.ID, "")
			code(err, 403, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
			if selection(max) != nil {
				t.Fatal("a former member kept the stale selection")
			}
			if selection(lin) == nil || *selection(lin) != other.ID {
				t.Fatal("another user's selection changed")
			}
		})
	}
}
