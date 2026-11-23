package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

// Check the create and update parameters, the default member page of the full
// organization, hook API errors and role creation permission over HTTP.
func TestOrganizationRequestContract(t *testing.T) {
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
			store, err := OpenWithOptions(ctx, dialect, dsn, []string{"organization-teams", "organization-roles"}, schema.Options{})
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
			selected := func(s auth.Session) string {
				t.Helper()
				var id *string
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "activeOrganizationId" FROM "session" WHERE "id"=?`), s.ID).Scan(&id))
				if id == nil {
					return ""
				}
				return *id
			}
			ada := account("Ada")
			service, err := org.NewService(org.Options{Store: store, DynamicAccessControl: true, RoleControl: org.DefaultRoleControl()})
			must(err)
			adaHTTP := organizationRoleClient(t, store, service, ada)

			// Create stores name, slug, logo and metadata and selects the new organization.
			logo := "https://cdn.example.test/acme.png"
			acme, err := adaHTTP.CreateOrganization(ctx, client.CreateOrganizationRequest{Name: "Acme", Slug: "acme", Logo: &logo, Metadata: map[string]any{"region": "west", "seats": 5.0}})
			must(err)
			var name, slug, savedLogo, metadata string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "name","slug","logo","metadata" FROM "organization" WHERE "id"=?`), acme.ID).Scan(&name, &slug, &savedLogo, &metadata))
			if acme.Name != "Acme" || name != "Acme" || slug != "acme" || savedLogo != logo || acme.Logo == nil || *acme.Logo != logo || metadata != `{"region":"west","seats":5}` || selected(ada) != acme.ID {
				t.Fatal("create did not store its parameters", acme, name, slug, savedLogo, metadata, selected(ada))
			}
			// keepCurrentActiveOrganization leaves the selection on the previous organization.
			kept, err := adaHTTP.CreateOrganization(ctx, client.CreateOrganizationRequest{Name: "Kept", Slug: "kept", KeepCurrentActiveOrganization: true})
			must(err)
			if kept.Logo != nil || kept.Metadata != nil || selected(ada) != acme.ID {
				t.Fatal("keepCurrentActiveOrganization changed the selection", kept, selected(ada))
			}
			// Missing or invalid create parameters are rejected before anything is stored.
			for _, body := range []map[string]any{{"slug": "no-name"}, {"name": "", "slug": "empty-name"}, {"name": "No slug"}, {"name": "Bad logo", "slug": "bad-logo", "logo": 7}, {"name": "Bad metadata", "slug": "bad-metadata", "metadata": "x"}} {
				code(adaHTTP.Do(ctx, http.MethodPost, "/organization/create", body, nil), 400, "VALIDATION_ERROR")
			}
			var stored int
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "organization"`)).Scan(&stored))
			if stored != 2 {
				t.Fatal("a rejected creation stored an organization", stored)
			}

			// Update sets a new logo.
			next := "https://cdn.example.test/acme-2.png"
			updated, err := adaHTTP.UpdateOrganization(ctx, acme.ID, org.ProfileUpdate{Logo: &next})
			must(err)
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "logo" FROM "organization" WHERE "id"=?`), acme.ID).Scan(&savedLogo))
			if updated.Logo == nil || *updated.Logo != next || savedLogo != next || updated.Name != "Acme" {
				t.Fatal("update did not set the logo", updated, savedLogo)
			}

			// The full organization's default member page is the fixed membership limit.
			for i := range 3 {
				s := account(fmt.Sprintf("Member%d", i))
				must(store.AddOrganizationMember(ctx, org.Member{ID: fmt.Sprintf("m%d", i), UserID: s.UserID, OrganizationID: acme.ID, Role: "member", CreatedAt: now}, ""))
			}
			small, err := org.NewService(org.Options{Store: store, MembershipLimit: org.MembershipLimit{Maximum: 2}})
			must(err)
			full, err := organizationRoleClient(t, store, small, ada).FullOrganization(ctx, org.FullOrganizationQuery{OrganizationID: acme.ID})
			must(err)
			if len(full.Members) != 2 {
				t.Fatal("the default member page ignored the membership limit", len(full.Members))
			}
			full, err = organizationRoleClient(t, store, small, ada).FullOrganization(ctx, org.FullOrganizationQuery{OrganizationID: acme.ID, MembersLimit: 10})
			must(err)
			if len(full.Members) != 4 {
				t.Fatal("an explicit membersLimit was not applied", len(full.Members))
			}

			// A hook's API error reaches the caller with its status and code.
			planRequired := &auth.APIError{Status: 402, Code: "PLAN_REQUIRED", Message: "Upgrade to add teams"}
			hooked, err := org.NewService(org.Options{
				Store: store, Teams: &org.TeamOptions{},
				BeforeCreateOrganization: func(context.Context, org.BeforeOrganizationCreation) (*org.ProfileUpdate, error) {
					return nil, planRequired
				},
				BeforeCreateTeam: func(context.Context, org.TeamChange) (*org.TeamOverride, error) { return nil, planRequired },
			})
			must(err)
			hookedHTTP := organizationRoleClient(t, store, hooked, ada)
			_, err = hookedHTTP.CreateOrganization(ctx, client.CreateOrganizationRequest{Name: "Blocked", Slug: "blocked"})
			code(err, 402, "PLAN_REQUIRED")
			_, err = hookedHTTP.CreateTeam(ctx, "Blocked", acme.ID)
			code(err, 402, "PLAN_REQUIRED")

			// Only a role holding ac:create can create a stored role.
			_, err = organizationRoleClient(t, store, service, auth.Session{ID: "Member0-s", Token: "Member0-t", UserID: "Member0"}).CreateOrganizationRole(ctx, org.CreateRoleRequest{OrganizationID: acme.ID, Role: "auditor", Permission: map[string][]string{"organization": {"update"}}})
			code(err, 403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE")
			created, err := adaHTTP.CreateOrganizationRole(ctx, org.CreateRoleRequest{OrganizationID: acme.ID, Role: "auditor", Permission: map[string][]string{"ac": {"read"}}})
			must(err)
			if created.RoleData.Role != "auditor" {
				t.Fatal("unexpected created role", created)
			}
		})
	}
}
