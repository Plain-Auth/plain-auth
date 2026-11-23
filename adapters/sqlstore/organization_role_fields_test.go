package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/authtest"
	"github.com/Plain-Org/plain-auth/plugins/access"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
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
			owner, group := createRoleFieldOwner(t, store)
			options := org.Options{Store: store, RoleAdditionalFields: defs, RoleControl: org.DefaultRoleControl(), DynamicAccessControl: true}
			service, err := org.NewService(options)
			must(err)
			sdk := organizationRoleClient(t, store, service, owner)
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
				_, err := store.db.ExecContext(ctx, store.bind(`UPDATE "member" SET "role"='member' WHERE "organizationId"=? AND "userId"=?`), group.ID, owner.UserID)
				must(err)
				return 3
			}}
			limited, err := org.NewService(options)
			must(err)
			ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_, err = limited.Store().(org.RoleCreationStore).CreateOrganizationRole(ctx2, owner, org.CreateRoleRequest{Role: "after-revocation", Permission: access.Statements{}}, *options.RoleControl, nil)
			if !errors.Is(err, org.ErrCreateRoleDenied) {
				t.Fatal("created role after its default revoked authority", err)
			}
		})
	}
}

func createRoleFieldOwner(t *testing.T, store *Store) (auth.Session, org.Organization) {
	t.Helper()
	ctx := t.Context()
	app, err := authtest.New(auth.Options{Store: store, BaseURL: "https://roles.example.test", Secret: strings.Repeat("s", 40)})
	if err != nil {
		t.Fatal(err)
	}
	user, err := app.SaveUser(ctx, authtest.NewUser())
	if err != nil {
		t.Fatal(err)
	}
	login, err := app.Login(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	group := authtest.NewOrganization("studio")
	if err := store.CreateOrganization(ctx, group, org.Member{ID: "owner", Role: "owner", UserID: user.ID, OrganizationID: group.ID, CreatedAt: group.CreatedAt}, login.Session.ID, false); err != nil {
		t.Fatal(err)
	}
	return login.Session, group
}

func TestOrganizationRoleStructuredFields(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			defaults := []string{"desk"}
			fields := map[string]org.RoleField{
				"meta":    {Type: org.RoleJSON, Column: "role_meta"},
				"tags":    {Type: org.RoleStringArray, Required: true, Default: defaults},
				"weights": {Type: org.RoleNumberArray},
			}
			store, err := OpenWithAdditionalFields(ctx, dialect, organizationTestDSN(t, dialect), []string{"organization-roles"}, schema.AdditionalFields{OrganizationRole: fields})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			owner, _ := createRoleFieldOwner(t, store)
			svc, err := org.NewService(org.Options{Store: store, DynamicAccessControl: true, RoleControl: org.DefaultRoleControl(), RoleAdditionalFields: fields})
			if err != nil {
				t.Fatal(err)
			}
			defaults[0] = "mutated"
			sdk := organizationRoleClient(t, store, svc, owner)
			out, err := sdk.CreateOrganizationRole(ctx, org.CreateRoleRequest{Role: "desk", Permission: access.Statements{}})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(out.RoleData.AdditionalFields["tags"], []any{"desk"}) {
				t.Fatal("configured array default lent mutable state to the caller", out.RoleData)
			}
			q := org.RoleQuery{RoleID: out.RoleData.ID}
			members := []any{json.Number("1.25"), json.Number("-3"), json.Number("0")}
			for _, value := range []any{"a plain JSON string", false, json.Number("7"), map[string]any{"key": []any{"✓", nil}}, []any{}, nil} {
				update := org.RoleUpdate{AdditionalFields: map[string]any{"meta": value, "tags": []string{}, "weights": members}}
				changed, err := sdk.UpdateOrganizationRole(ctx, q, update)
				if err != nil {
					t.Fatal(err)
				}
				saved, err := sdk.GetOrganizationRole(ctx, q)
				if err != nil {
					t.Fatal(err)
				}
				// The SDK represents top-level integral JSON numbers as int64.
				want := value
				if _, ok := want.(json.Number); ok {
					want = int64(7)
				}
				for _, role := range []org.RoleDefinition{changed.RoleData, *saved} {
					extra := role.AdditionalFields
					if !reflect.DeepEqual(extra["meta"], want) || !reflect.DeepEqual(extra["tags"], []any{}) || !reflect.DeepEqual(extra["weights"], members) {
						t.Fatalf("stored JSON or array lost its logical type: %#v; want %#v", extra, want)
					}
				}
			}
			for _, invalid := range []map[string]any{{"tags": []any{"ok", false}}, {"weights": []any{2, "2"}}, {"tags": nil}, {"meta": map[string]any{"bad": "bad\x00text"}}} {
				_, err := sdk.UpdateOrganizationRole(ctx, q, org.RoleUpdate{RoleName: "rolled-back", AdditionalFields: invalid})
				var problem *auth.APIError
				if !errors.As(err, &problem) || problem.Code != "VALIDATION_ERROR" {
					t.Fatalf("invalid structured field accepted: %#v, %v", invalid, err)
				}
			}
			row, err := sdk.GetOrganizationRole(ctx, q)
			if err != nil || row.Role != "desk" {
				t.Fatal("invalid structured update changed role", row, err)
			}
		})
	}
}
