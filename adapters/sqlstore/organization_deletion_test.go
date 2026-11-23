package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

// Delete an organization over HTTP and check permissions, hooks, the rows that
// go with it, the neighbors that stay, and cleared session selections.
func TestOrganizationDeletion(t *testing.T) {
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
			denied := func(err error, status int, code string) {
				t.Helper()
				var problem *auth.APIError
				if !errors.As(err, &problem) || problem.Status != status || problem.Code != code {
					t.Fatalf("want %d %s, got %v", status, code, err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"organization-teams", "organization-roles", "api-key"})
			must(err)
			dsn := organizationTestDSN(t, dialect)
			store, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			t.Cleanup(func() { store.Close() })
			peer, err := Open(ctx, dialect, dsn)
			must(err)
			t.Cleanup(func() { peer.Close() })
			exec := func(q string, args ...any) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(q), args...)
				must(err)
			}
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
			owner, admin, member, outsider := account("Owner"), account("Admin"), account("Member"), account("Outsider")
			group := org.Organization{ID: "Acme", Name: "Acme", Slug: "acme", CreatedAt: now}
			neighbor := org.Organization{ID: "Other", Name: "Other", Slug: "other", CreatedAt: now}
			must(store.CreateOrganization(ctx, group, org.Member{ID: "owner-m", UserID: owner.UserID, OrganizationID: group.ID, Role: "owner", CreatedAt: now}, owner.ID, false))
			must(store.CreateOrganization(ctx, neighbor, org.Member{ID: "outsider-m", UserID: outsider.UserID, OrganizationID: neighbor.ID, Role: "owner", CreatedAt: now}, outsider.ID, false))
			must(store.AddOrganizationMember(ctx, org.Member{ID: "admin-m", UserID: admin.UserID, OrganizationID: group.ID, Role: "admin", CreatedAt: now}, ""))
			must(store.AddOrganizationMember(ctx, org.Member{ID: "member-m", UserID: member.UserID, OrganizationID: group.ID, Role: "member", CreatedAt: now}, ""))

			var events []string
			var cancelDeletion bool
			service, err := org.NewService(org.Options{
				Store: store, Teams: &org.TeamOptions{},
				BeforeDeleteOrganization: func(_ context.Context, e org.OrganizationDeletion) error {
					events = append(events, "before:"+e.Organization.ID+":"+e.User.ID)
					if cancelDeletion {
						return errors.New("billing review pending")
					}
					return nil
				},
				AfterDeleteOrganization: func(_ context.Context, e org.OrganizationDeletion) error {
					events = append(events, "after:"+e.Organization.ID+":"+e.User.ID)
					return nil
				},
			})
			must(err)
			teams := service.Store().(org.TeamStore)
			design, err := teams.CreateTeam(ctx, org.TeamActor{UserID: owner.UserID, SessionID: owner.ID}, group.ID, "Design")
			must(err)
			_, err = teams.AddTeamMember(ctx, org.TeamActor{UserID: owner.UserID, SessionID: owner.ID}, group.ID, design.ID, member.UserID)
			must(err)
			kept, err := teams.CreateTeam(ctx, org.TeamActor{UserID: outsider.UserID, SessionID: outsider.ID}, neighbor.ID, "Kept")
			must(err)
			exec(`INSERT INTO "invitation" ("id","organizationId","email","status","expiresAt","inviterId","createdAt") VALUES (?,?,?,'pending',?,?,?)`, "pending", group.ID, "new@example.test", store.date(now.Add(time.Hour)), owner.UserID, store.date(now))
			exec(`INSERT INTO "organizationRole" ("id","organizationId","role","permission","createdAt") VALUES (?,?,?,?,?)`, "role", group.ID, "reviewer", `{"organization":["update"]}`, store.date(now))
			must(store.ConfigureKeyReference(ctx, "org-keys", true))
			must(store.ConfigureKeyReference(ctx, "user-keys", false))
			for _, key := range [][3]string{{"acme-key", "org-keys", group.ID}, {"other-key", "org-keys", neighbor.ID}, {"user-key", "user-keys", owner.UserID}} {
				exec(`INSERT INTO "apikey" ("id","configId","referenceId","key","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`, key[0], key[1], key[2], "digest-"+key[0], store.date(now), store.date(now))
			}
			exec(`UPDATE "session" SET "activeOrganizationId"=?,"activeTeamId"=? WHERE "id" IN (?,?)`, group.ID, design.ID, owner.ID, member.ID)
			exec(`UPDATE "session" SET "activeOrganizationId"=?,"activeTeamId"=? WHERE "id"=?`, neighbor.ID, kept.ID, outsider.ID)

			ownerHTTP := organizationRoleClient(t, store, service, owner)
			// The body is validated before the session, and an empty ID names no organization.
			denied(ownerHTTP.Do(ctx, http.MethodPost, "/organization/delete", map[string]any{}, nil), 400, "VALIDATION_ERROR")
			_, err = ownerHTTP.DeleteOrganization(ctx, "")
			denied(err, 400, "ORGANIZATION_NOT_FOUND")
			_, err = organizationRoleClient(t, store, service, auth.Session{Token: "unknown-token"}).DeleteOrganization(ctx, group.ID)
			denied(err, 401, "UNAUTHORIZED")
			// Only a member holding organization.delete can delete.
			_, err = organizationRoleClient(t, store, service, outsider).DeleteOrganization(ctx, group.ID)
			denied(err, 400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
			_, err = ownerHTTP.DeleteOrganization(ctx, "missing")
			denied(err, 400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
			for _, s := range []auth.Session{admin, member} {
				_, err = organizationRoleClient(t, store, service, s).DeleteOrganization(ctx, group.ID)
				denied(err, 403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION")
			}
			// A before hook can cancel the deletion.
			cancelDeletion = true
			if _, err = ownerHTTP.DeleteOrganization(ctx, group.ID); err == nil {
				t.Fatal("a failing before hook did not cancel the deletion")
			}
			cancelDeletion = false
			if count(`SELECT COUNT(*) FROM "organization" WHERE "id"=?`, group.ID) != 1 || len(events) != 1 {
				t.Fatal("refused deletions changed the organization", events)
			}
			events = nil

			deleted, err := ownerHTTP.DeleteOrganization(ctx, group.ID)
			must(err)
			if deleted.ID != group.ID || deleted.Slug != group.Slug || strings.Join(events, ",") != "before:Acme:Owner,after:Acme:Owner" {
				t.Fatal("unexpected deletion result or hooks", deleted, events)
			}
			for table, q := range map[string]string{
				"organization":     `SELECT COUNT(*) FROM "organization" WHERE "id"=?`,
				"member":           `SELECT COUNT(*) FROM "member" WHERE "organizationId"=?`,
				"invitation":       `SELECT COUNT(*) FROM "invitation" WHERE "organizationId"=?`,
				"team":             `SELECT COUNT(*) FROM "team" WHERE "organizationId"=?`,
				"organizationRole": `SELECT COUNT(*) FROM "organizationRole" WHERE "organizationId"=?`,
				"apikey":           `SELECT COUNT(*) FROM "apikey" WHERE "referenceId"=?`,
			} {
				if n := count(q, group.ID); n != 0 {
					t.Fatalf("%d %s rows outlived the organization", n, table)
				}
			}
			if count(`SELECT COUNT(*) FROM "teamMember" WHERE "teamId"=?`, design.ID) != 0 ||
				count(`SELECT COUNT(*) FROM "session" WHERE "activeOrganizationId"=? OR "activeTeamId"=?`, group.ID, design.ID) != 0 {
				t.Fatal("team members or session selections outlived the organization")
			}
			if count(`SELECT COUNT(*) FROM "member" WHERE "organizationId"=?`, neighbor.ID) != 1 ||
				count(`SELECT COUNT(*) FROM "apikey" WHERE "id" IN ('other-key','user-key')`) != 2 ||
				count(`SELECT COUNT(*) FROM "session" WHERE "id"=? AND "activeOrganizationId"=? AND "activeTeamId"=?`, outsider.ID, neighbor.ID, kept.ID) != 1 ||
				count(`SELECT COUNT(*) FROM "user" WHERE "id" IN (?,?,?)`, owner.UserID, admin.UserID, member.UserID) != 3 {
				t.Fatal("deletion reached a neighboring organization, its keys or the accounts")
			}
			_, err = ownerHTTP.DeleteOrganization(ctx, group.ID)
			denied(err, 400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")

			// The deletion rechecks the permission after the before hook returns.
			demoting, err := org.NewService(org.Options{Store: store, BeforeDeleteOrganization: func(context.Context, org.OrganizationDeletion) error {
				_, err := peer.db.ExecContext(ctx, peer.bind(`UPDATE "member" SET "role"='member' WHERE "organizationId"=? AND "userId"=?`), neighbor.ID, outsider.UserID)
				return err
			}})
			must(err)
			_, err = organizationRoleClient(t, store, demoting, outsider).DeleteOrganization(ctx, neighbor.ID)
			denied(err, 403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION")
			if count(`SELECT COUNT(*) FROM "organization" WHERE "id"=?`, neighbor.ID) != 1 {
				t.Fatal("a demoted caller deleted the organization")
			}

			// Disabled deletion answers before authentication.
			disabled, err := org.NewService(org.Options{Store: store, DisableOrganizationDeletion: true})
			must(err)
			_, err = organizationRoleClient(t, store, disabled, auth.Session{Token: "unknown-token"}).DeleteOrganization(ctx, neighbor.ID)
			denied(err, 404, "ORGANIZATION_DELETION_DISABLED")

			// An after-hook error reaches the caller once the deletion has committed.
			third := org.Organization{ID: "Third", Name: "Third", Slug: "third", CreatedAt: now}
			must(store.CreateOrganization(ctx, third, org.Member{ID: "third-m", UserID: member.UserID, OrganizationID: third.ID, Role: "owner", CreatedAt: now}, member.ID, false))
			notifyErr := errors.New("audit sink unavailable")
			notifying, err := org.NewService(org.Options{Store: store, AfterDeleteOrganization: func(context.Context, org.OrganizationDeletion) error { return notifyErr }})
			must(err)
			if _, err = organizationRoleClient(t, store, notifying, member).DeleteOrganization(ctx, third.ID); err == nil {
				t.Fatal("lost the after-hook error")
			}
			if count(`SELECT COUNT(*) FROM "organization" WHERE "id"=?`, third.ID) != 0 {
				t.Fatal("an after-hook error restored the organization")
			}

			// Without the teams profile only the organization selection is cleared.
			plainDSN := organizationTestDSN(t, dialect)
			plain, err := OpenWithOptions(ctx, dialect, plainDSN, []string{"organization"}, schema.Options{})
			must(err)
			t.Cleanup(func() { plain.Close() })
			user := auth.User{ID: "Solo", Name: "Solo", Email: "solo@example.test", CreatedAt: now, UpdatedAt: now}
			solo := auth.StoredSession{Session: auth.Session{ID: "Solo-s", Token: "Solo-t", UserID: "Solo", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			must(plain.CreateUser(ctx, user, "", &solo))
			must(plain.CreateOrganization(ctx, org.Organization{ID: "Solo-org", Name: "Solo", Slug: "solo", CreatedAt: now}, org.Member{ID: "solo-m", UserID: "Solo", OrganizationID: "Solo-org", Role: "owner", CreatedAt: now}, solo.ID, false))
			_, err = plain.db.ExecContext(ctx, plain.bind(`UPDATE "session" SET "activeOrganizationId"=? WHERE "id"=?`), "Solo-org", solo.ID)
			must(err)
			if _, err = plain.DeleteOrganization(ctx, solo.Session, "Solo-org"); err != nil {
				t.Fatal(err)
			}
			var selected *string
			must(plain.db.QueryRowContext(ctx, plain.bind(`SELECT "activeOrganizationId" FROM "session" WHERE "id"=?`), solo.ID).Scan(&selected))
			if selected != nil {
				t.Fatal("the session kept the deleted organization", *selected)
			}
		})
	}
}
