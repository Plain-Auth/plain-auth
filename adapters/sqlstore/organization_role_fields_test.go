package sqlstore

import (
	"context"
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/authtest"
	"github.com/Plain-Auth/plain-auth/plugins/access"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestOrganizationRoleFieldLifecycle(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			var defaultCalls int
			defs := map[string]org.RoleField{
				"color":       {Type: auth.FieldString, Column: "display_color", Required: true, Default: "blue"},
				"issued":      {Type: auth.FieldNumber, ServerOnly: true, Required: true, Default: func() int { defaultCalls++; return defaultCalls }},
				"privateNote": {Type: auth.FieldString, Column: "private_note", Hidden: true},
				"reviewAt":    {Type: auth.FieldDate, Column: "review_at"},
			}
			store, err := OpenWithAdditionalFields(ctx, dialect, organizationTestDSN(t, dialect), []string{"organization-roles"}, schema.AdditionalFields{OrganizationRole: defs})
			must(err)
			t.Cleanup(func() { store.Close() })
			app, err := authtest.New(auth.Options{Store: store, BaseURL: "https://roles.example.test", Secret: strings.Repeat("s", 40)})
			must(err)
			user, err := app.SaveUser(ctx, authtest.NewUser())
			must(err)
			login, err := app.Login(ctx, user.ID)
			must(err)
			group := authtest.NewOrganization("studio")
			must(store.CreateOrganization(ctx, group, org.Member{ID: "owner", Role: "owner", UserID: user.ID, OrganizationID: group.ID, CreatedAt: group.CreatedAt}, login.Session.ID, false))
			options := org.Options{Store: store, RoleAdditionalFields: defs, RoleControl: org.DefaultRoleControl(), DynamicAccessControl: true}
			service, err := org.NewService(options)
			must(err)
			sdk := organizationRoleClient(t, store, service, login.Session)
			request := org.CreateRoleRequest{Role: "editor", Permission: access.Statements{}}
			created, err := sdk.CreateOrganizationRole(ctx, request)
			must(err)
			if !maps.Equal(created.RoleData.AdditionalFields, map[string]any{"color": "blue", "issued": int64(1), "reviewAt": nil}) {
				t.Fatalf("unexpected public defaults: %#v", created.RoleData.AdditionalFields)
			}
			query := org.RoleQuery{RoleID: created.RoleData.ID}
			change := org.RoleUpdate{AdditionalFields: map[string]any{"color": "red", "reviewAt": "2026-01-03T09:12:31.9998+02:00", "privateNote": "internal", "issued": 100, "role": "override"}}
			updated, err := sdk.UpdateOrganizationRole(ctx, query, change)
			must(err)
			expected := map[string]any{"color": "red", "issued": int64(1), "reviewAt": "2026-01-03T07:12:31.999Z"}
			if !maps.Equal(updated.RoleData.AdditionalFields, expected) || updated.RoleData.Role != "editor" {
				t.Fatalf("wrong public field projection: %#v", updated.RoleData)
			}
			row, err := sdk.GetOrganizationRole(ctx, query)
			must(err)
			if !maps.Equal(row.AdditionalFields, expected) {
				t.Fatal("stored public fields did not round trip", row.AdditionalFields)
			}
			var secret string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "private_note" FROM "organizationRole" WHERE "id"=?`), row.ID).Scan(&secret))
			if secret != "internal" {
				t.Fatal("hidden input was not saved")
			}
			at := row.UpdatedAt
			if at == nil {
				t.Fatal("missing persisted update time")
			}
			_, err = sdk.UpdateOrganizationRole(ctx, query, org.RoleUpdate{RoleName: "renamed", AdditionalFields: map[string]any{"color": nil}})
			var issue *auth.APIError
			if !errors.As(err, &issue) || issue.Code != "VALIDATION_ERROR" {
				t.Fatal("expected required field validation", err)
			}
			row, err = sdk.GetOrganizationRole(ctx, query)
			must(err)
			if row.Role != "editor" || !row.UpdatedAt.Equal(*at) || !maps.Equal(row.AdditionalFields, expected) {
				t.Fatal("failed field edit modified the role")
			}
			list, err := sdk.ListOrganizationRoles(ctx, group.ID)
			must(err)
			if len(list) != 1 || !maps.Equal(list[0].AdditionalFields, expected) {
				t.Fatal("list and get expose different fields")
			}
			if defaultCalls != 1 {
				t.Fatal("default ran on a read or update", defaultCalls)
			}
			request.Role = "reviewer"
			request.AdditionalFields = map[string]any{"color": "green", "privateNote": "new", "issued": -1}
			next, err := sdk.CreateOrganizationRole(ctx, request)
			must(err)
			if next.RoleData.AdditionalFields["issued"] != int64(2) {
				t.Fatal("client set a server-owned field", next)
			}
			defs["color"] = org.RoleField{Type: auth.FieldNumber}
			if _, err := org.NewService(options); err == nil {
				t.Fatal("bound an incompatible column")
			}
			// A callback may revoke a membership. Recheck authority before saving the generated value.
			delete(defs, "color")
			defs["issued"] = org.RoleField{Type: auth.FieldNumber, ServerOnly: true, Required: true, Default: func() int {
				_, err := store.db.ExecContext(ctx, store.bind(`UPDATE "member" SET "role"='member' WHERE "organizationId"=? AND "userId"=?`), group.ID, user.ID)
				must(err)
				return 3
			}}
			limited, err := org.NewService(options)
			must(err)
			ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_, err = limited.Store().(org.RoleCreationStore).CreateOrganizationRole(ctx2, login.Session, org.CreateRoleRequest{Role: "after-revocation", Permission: access.Statements{}}, *options.RoleControl, nil)
			if !errors.Is(err, org.ErrCreateRoleDenied) {
				t.Fatal("created role after its default revoked authority", err)
			}
		})
	}
}
