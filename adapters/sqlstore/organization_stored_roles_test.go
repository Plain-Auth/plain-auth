package sqlstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth/plugins/access"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestStoredOrganizationRoleResolution(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			base, peer, _, actor, group := invitationWriterFixture(t, dialect)
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			options := org.Options{Store: base, Teams: &org.TeamOptions{}, DynamicAccessControl: true}
			if _, err := org.NewService(options); err == nil {
				t.Fatal("enabled dynamic roles without their schema")
			}
			sql, err := schema.Generate(dialect, []string{"organization-teams", "organization-roles"})
			must(err)
			must(base.migrate(ctx, sql))
			service, err := org.NewService(options)
			must(err)
			dynamic := service.Store().(*Store)
			write := func(statement string, args ...any) error {
				_, err := peer.db.ExecContext(ctx, peer.bind(statement), args...)
				return err
			}
			must(write(`UPDATE "member" SET "role"=? WHERE "id"=?`, "member", "admin"))
			must(write(`INSERT INTO "organization" ("id","name","slug","createdAt") VALUES (?,?,?,?)`, "other", "Other", "other", peer.date(group.CreatedAt)))
			insert := `INSERT INTO "organizationRole" ("id","organizationId","role","permission","createdAt") VALUES (?,?,?,?,?)`
			must(write(insert, "broken", "other", "member", `{"ac":[null]}`, peer.date(group.CreatedAt)))
			must(write(insert, "main", group.ID, "member", `{"ac":["update"],"invitation":["create"]}`, peer.date(group.CreatedAt)))
			require := func(store *Store, actions access.Statements, want bool) {
				t.Helper()
				allowed, err := store.CheckOrganizationPermission(ctx, actor.ID, actor.UserID, group.ID, actions)
				if err != nil || allowed != want {
					t.Fatalf("permissions %v: got %t, want %t, error %v", actions, allowed, want, err)
				}
			}
			required := access.Statements{"ac": {"read", "update"}, "invitation": {"create"}}
			require(dynamic, required, true)
			require(base, required, false)
			grant := org.Invitation{ID: "withdrawn", InviterID: actor.UserID, OrganizationID: group.ID, Email: "candidate@example.test", Role: "member", Status: "pending", CreatedAt: group.CreatedAt, ExpiresAt: group.CreatedAt.Add(time.Hour)}
			_, err = dynamic.IssuePreparedInvitation(ctx, grant, actor, org.InvitationIssueOptions{}, func(context.Context, org.InvitationCreationEvent) (*org.InvitationChanges, error) {
				return nil, write(`UPDATE "organizationRole" SET "permission"=? WHERE "id"=?`, `{"ac":["update"]}`, "main")
			})
			if !errors.Is(err, org.ErrInviteDenied) {
				t.Fatalf("changed organization grants were not rechecked after the callback: %v", err)
			}
			var count int
			must(base.db.QueryRowContext(ctx, base.bind(`SELECT COUNT(*) FROM "invitation" WHERE "id"=?`), grant.ID).Scan(&count))
			if count != 0 {
				t.Fatal("revoked role committed a new invitation")
			}
			require(dynamic, required, false)
			must(write(`UPDATE "organizationRole" SET "permission"=? WHERE "id"=?`, `{"ac":[null]}`, "main"))
			if allowed, err := dynamic.CheckOrganizationPermission(ctx, actor.ID, actor.UserID, group.ID, access.Statements{"ac": {"read"}}); err == nil || allowed {
				t.Fatal("invalid stored role permissions returned a successful decision")
			}
			must(write(`DELETE FROM "organizationRole" WHERE "id"=?`, "main"))
			require(dynamic, access.Statements{"ac": {"read"}}, true)
		})
	}
}
