package sqlstore

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

// Run the creation hooks over HTTP and from trusted server code, and create
// organizations for a named user without a session.
func TestOrganizationCreationHooks(t *testing.T) {
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
			store, err := OpenWithOptions(ctx, dialect, dsn, []string{"organization-teams"}, schema.Options{})
			must(err)
			t.Cleanup(func() { store.Close() })
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
			ada, grace := account("Ada"), account("Grace")

			var before []org.BeforeOrganizationCreation
			var after []org.AfterOrganizationCreation
			var beforeErr, afterErr error
			var override *org.ProfileUpdate
			service, err := org.NewService(org.Options{
				Store: store, Teams: &org.TeamOptions{},
				AllowUserToCreateOrganization: func(context.Context, auth.User) (bool, error) { return false, nil },
				BeforeCreateOrganization: func(_ context.Context, e org.BeforeOrganizationCreation) (*org.ProfileUpdate, error) {
					before = append(before, e)
					return override, beforeErr
				},
				AfterCreateOrganization: func(_ context.Context, e org.AfterOrganizationCreation) error {
					after = append(after, e)
					return afterErr
				},
			})
			must(err)

			// HTTP: AllowUserToCreateOrganization governs signed-in users.
			_, err = organizationRoleClient(t, store, service, ada).CreateOrganization(ctx, client.CreateOrganizationRequest{Name: "Denied", Slug: "denied"})
			code(err, 403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION")
			open, err := org.NewService(org.Options{
				Store: store, Teams: &org.TeamOptions{},
				BeforeCreateOrganization: func(_ context.Context, e org.BeforeOrganizationCreation) (*org.ProfileUpdate, error) {
					before = append(before, e)
					return override, beforeErr
				},
				AfterCreateOrganization: func(_ context.Context, e org.AfterOrganizationCreation) error {
					after = append(after, e)
					return afterErr
				},
			})
			must(err)
			adaHTTP := organizationRoleClient(t, store, open, ada)

			// The before hook sees the proposal and the creator and can replace fields.
			name, slug := "Renamed", "renamed"
			override = &org.ProfileUpdate{Name: &name, Slug: &slug, Metadata: map[string]any{"plan": "team"}}
			created, err := adaHTTP.CreateOrganization(ctx, client.CreateOrganizationRequest{Name: "Draft", Slug: "draft", Metadata: map[string]any{"plan": "free"}})
			must(err)
			if len(before) != 1 || before[0].Organization.Slug != "draft" || string(before[0].Organization.Metadata) != `{"plan":"free"}` || before[0].User.ID != ada.UserID || before[0].User.Email != "ada@example.test" {
				t.Fatal("unexpected before-hook input", before)
			}
			if created.Name != "Renamed" || created.Slug != "renamed" || string(created.Metadata) != `{"plan":"team"}` || len(created.Members) != 1 || created.Members[0].Role != "owner" {
				t.Fatal("overrides did not reach the saved organization", created)
			}
			if len(after) != 1 || after[0].Organization.ID != created.ID || after[0].Organization.Slug != "renamed" || after[0].Member.UserID != ada.UserID || after[0].User.ID != ada.UserID {
				t.Fatal("unexpected after-hook input", after)
			}
			if count(`SELECT COUNT(*) FROM "organization" WHERE "slug"='renamed' AND "name"='Renamed'`) != 1 ||
				count(`SELECT COUNT(*) FROM "session" WHERE "id"=? AND "activeOrganizationId"=?`, ada.ID, created.ID) != 1 {
				t.Fatal("the HTTP creation was not stored or selected")
			}

			// A before-hook error or an invalid override stores nothing; an after-hook error keeps the organization.
			override, beforeErr = nil, errors.New("plan required")
			if _, err = adaHTTP.CreateOrganization(ctx, client.CreateOrganizationRequest{Name: "Blocked", Slug: "blocked"}); err == nil {
				t.Fatal("the before hook did not cancel the creation")
			}
			blank := ""
			override, beforeErr = &org.ProfileUpdate{Name: &blank}, nil
			_, err = adaHTTP.CreateOrganization(ctx, client.CreateOrganizationRequest{Name: "Invalid", Slug: "invalid"})
			code(err, 400, "VALIDATION_ERROR")
			override, afterErr = nil, errors.New("audit sink unavailable")
			if _, err = adaHTTP.CreateOrganization(ctx, client.CreateOrganizationRequest{Name: "Kept", Slug: "kept"}); err == nil {
				t.Fatal("lost the after-hook error")
			}
			afterErr = nil
			if count(`SELECT COUNT(*) FROM "organization" WHERE "slug" IN ('blocked','invalid')`) != 0 || count(`SELECT COUNT(*) FROM "organization" WHERE "slug"='kept'`) != 1 {
				t.Fatal("hook failures changed the wrong organizations")
			}

			// Trusted creation names a user, skips AllowUserToCreateOrganization and selects nothing.
			before, after = nil, nil
			trusted, err := service.CreateOrganization(ctx, org.CreateOrganizationRequest{UserID: grace.UserID, Name: "Server", Slug: "server", Metadata: map[string]any{"source": "import"}})
			must(err)
			if trusted.Slug != "server" || len(trusted.Members) != 1 || trusted.Members[0].UserID != grace.UserID || trusted.Members[0].Role != "owner" {
				t.Fatal("unexpected trusted creation", trusted)
			}
			if len(before) != 1 || before[0].User.Email != "grace@example.test" || len(after) != 1 || after[0].Member.OrganizationID != trusted.ID {
				t.Fatal("trusted creation skipped the hooks or the creator's profile", before, after)
			}
			if count(`SELECT COUNT(*) FROM "teamMember" tm JOIN "team" t ON t."id"=tm."teamId" WHERE t."organizationId"=? AND tm."userId"=?`, trusted.ID, grace.UserID) != 1 ||
				count(`SELECT COUNT(*) FROM "session" WHERE "id"=? AND "activeOrganizationId" IS NULL`, grace.ID) != 1 {
				t.Fatal("trusted creation missed the default team or selected the organization")
			}
			_, err = service.CreateOrganization(ctx, org.CreateOrganizationRequest{UserID: "missing", Name: "Ghost", Slug: "ghost"})
			code(err, 400, "USER_NOT_FOUND")
			_, err = service.CreateOrganization(ctx, org.CreateOrganizationRequest{UserID: grace.UserID, Name: "Clash", Slug: "server"})
			code(err, 400, "ORGANIZATION_ALREADY_EXISTS")
			for _, bad := range []org.CreateOrganizationRequest{{Name: "No user", Slug: "no-user"}, {UserID: grace.UserID, Slug: "no-name"}, {UserID: grace.UserID, Name: "No slug"}} {
				_, err = service.CreateOrganization(ctx, bad)
				code(err, 400, "VALIDATION_ERROR")
			}
			limited, err := org.NewService(org.Options{Store: store, OrganizationLimit: 1})
			must(err)
			_, err = limited.CreateOrganization(ctx, org.CreateOrganizationRequest{UserID: grace.UserID, Name: "Second", Slug: "second"})
			code(err, 403, "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS")
			if count(`SELECT COUNT(*) FROM "organization" WHERE "slug" IN ('ghost','second','no-user','no-name')`) != 0 {
				t.Fatal("a refused trusted creation stored an organization")
			}
		})
	}
}
