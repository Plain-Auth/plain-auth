package sqlstore

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/access"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestOrganizationRoleCreation(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			base, peer, owner, admin, group := invitationWriterFixture(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"organization-teams", "organization-roles"})
			must(err)
			must(base.migrate(ctx, ddl))
			control := access.New(access.Statements{"ac": {"create", "read", "delete"}, "article": {"read", "publish"}})
			roles := org.DefaultRoles()
			roles["admin"] = access.Statements{"ac": {"create", "read"}, "article": {"read"}}
			roles["owner"]["article"] = []string{"read", "publish", "private-action"}
			options := org.Options{Store: base, DynamicAccessControl: true, Roles: roles, RoleControl: &control}
			service, err := org.NewService(options)
			must(err)
			options.Store = peer
			second, err := org.NewService(options)
			must(err)
			first := service.Store().(org.RoleCreationStore)
			other := second.Store().(org.RoleCreationStore)
			sdk := organizationRoleClient(t, base, service, admin)
			request := org.CreateRoleRequest{OrganizationID: group.ID, Role: "Analyst", Permission: access.Statements{"article": {"read"}, "ac": nil}}
			created, err := sdk.CreateOrganizationRole(ctx, request)
			must(err)
			if !created.Success || created.RoleData.Role != "analyst" || created.RoleData.ID == "" || !slices.Equal(created.Statements["article"], []string{"read"}) || created.Statements["ac"] == nil {
				t.Fatal("incorrect SDK create result", created)
			}
			request.Role = "unavailable"
			request.Permission["article"] = []string{"publish", "delete"}
			_, err = sdk.CreateOrganizationRole(ctx, request)
			var denied *auth.MissingPermissionsError
			if !errors.As(err, &denied) || !slices.Equal(denied.MissingPermissions, []string{"article:publish", "article:delete"}) || denied.Code != org.ErrCreateRoleDenied.Code {
				t.Fatal("SDK lost specific delegation errors", err)
			}
			translated := organizationRoleClient(t, base, service, admin, auth.Plugin{ID: "localization", TranslateError: func(_ auth.ErrorContext, e auth.APIError) string {
				if e.Code == org.ErrCreateRoleDenied.Code {
					return "Ce rôle ne peut pas déléguer ces permissions."
				}
				return ""
			}})
			_, err = translated.CreateOrganizationRole(ctx, request)
			var localized *auth.LocalizedError
			if !errors.As(err, &denied) || !errors.As(err, &localized) || localized.OriginalMessage != org.ErrCreateRoleDenied.Message || localized.Message == localized.OriginalMessage || len(denied.MissingPermissions) != 2 {
				t.Fatal("localized denial lost its original message or missing grants", err)
			}
			request.Permission = access.Statements{"article": {"private-action"}}
			_, err = first.CreateOrganizationRole(ctx, owner, request, control, nil)
			if !errors.As(err, &denied) || !slices.Equal(denied.MissingPermissions, []string{"article:private-action"}) {
				t.Fatal("delegated an action outside the host vocabulary", err)
			}
			request.Permission = access.Statements{}
			for _, role := range []string{"", " ", "editor,member", " padded "} {
				request.Role = role
				_, err = sdk.CreateOrganizationRole(ctx, request)
				var issue *auth.APIError
				if !errors.As(err, &issue) || issue.Code != "VALIDATION_ERROR" {
					t.Fatalf("ambiguous name %q accepted: %v", role, err)
				}
			}
			race := func(names [2]string, limit *org.RoleLimit, want error) {
				t.Helper()
				start := make(chan struct{})
				done := make(chan error, 2)
				for i, store := range []org.RoleCreationStore{first, other} {
					go func() {
						<-start
						_, err := store.CreateOrganizationRole(ctx, owner, org.CreateRoleRequest{OrganizationID: group.ID, Role: names[i], Permission: access.Statements{}}, control, limit)
						done <- err
					}()
				}
				close(start)
				left, right := <-done, <-done
				if !((left == nil && errors.Is(right, want)) || (right == nil && errors.Is(left, want))) {
					t.Fatalf("concurrent role creation %q: %v / %v", names, left, right)
				}
			}
			request.Role = "limited"
			_, err = first.CreateOrganizationRole(ctx, owner, request, control, &org.RoleLimit{})
			if !errors.Is(err, org.ErrTooManyRoles) {
				t.Fatal("explicit zero capacity did not stop creation", err)
			}
			var resolved string
			positiveLimit := &org.RoleLimit{Resolve: func(_ context.Context, groupID string) (int, error) {
				resolved = groupID
				return 2, nil
			}}
			spare, err := first.CreateOrganizationRole(ctx, owner, request, control, positiveLimit)
			must(err)
			if resolved != group.ID {
				t.Fatal("role limit was not resolved from its organization", resolved)
			}
			must(second.Store().(org.RoleDeletionStore).DeleteOrganizationRole(ctx, owner.UserID, owner.Token, org.RoleQuery{OrganizationID: group.ID, RoleID: spare.ID}))
			race([2]string{"Editor", "EDITOR"}, nil, org.ErrRoleNameTaken)
			race([2]string{"one", "two"}, &org.RoleLimit{Maximum: 3}, org.ErrTooManyRoles)
			var calls atomic.Int32
			request.Role = "after-callback"
			request.Permission = access.Statements{"article": {"read"}}
			limit := org.RoleLimit{Resolve: func(ctx context.Context, id string) (int, error) {
				calls.Add(1)
				if id != group.ID {
					t.Fatal("quota evaluated for another organization")
				}
				_, err := peer.db.ExecContext(ctx, peer.bind(`UPDATE "member" SET "role"=? WHERE "organizationId"=? AND "userId"=?`), "member", group.ID, admin.UserID)
				return 10, err
			}}
			_, err = first.CreateOrganizationRole(ctx, admin, request, control, &limit)
			if !errors.Is(err, org.ErrCreateRoleDenied) || calls.Load() != 1 {
				t.Fatal("role saved after the resolver revoked the actor's authority", err, calls.Load())
			}
			_, err = first.CreateOrganizationRole(ctx, admin, request, control, &limit)
			if !errors.Is(err, org.ErrCreateRoleDenied) || calls.Load() != 1 {
				t.Fatal("quota callback reached by a member without create permission", err, calls.Load())
			}
			request.OrganizationID = ""
			limit.Resolve = func(ctx context.Context, id string) (int, error) {
				_, err := peer.db.ExecContext(ctx, peer.bind(`UPDATE "session" SET "activeOrganizationId"=NULL WHERE "id"=?`), owner.ID)
				return 10, err
			}
			_, err = first.CreateOrganizationRole(ctx, owner, request, control, &limit)
			if !errors.Is(err, org.ErrCreateRoleNoOrg) {
				t.Fatal("role written after its implicit destination was cleared", err)
			}
			var count int
			must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT COUNT(*) FROM "organizationRole" WHERE "organizationId"=?`), group.ID).Scan(&count))
			if count != 3 {
				t.Fatal("unexpected role count after concurrent and denied writes", count)
			}
		})
	}
}
