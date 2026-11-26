package sqlstore

import (
	"net/http"
	"strings"
	"testing"
	"time"

	plainauth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/access"
	ak "github.com/Plain-Org/plain-auth/plugins/apikey"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

// With RolesFrom, organization key actions follow the organization
// service's roles: its creator role may do everything, other roles need the
// action on the apiKey resource, and a role an organization stores at run
// time counts at once.
func TestOrganizationKeyRolesFromOrganizationPlugin(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"api-key", "organization", "organization-roles"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			all := []string{"create", "read", "update", "delete"}
			grants := org.DefaultRoles()["owner"]
			grants["apiKey"] = all
			control := access.New(grants)
			roles := org.DefaultRoles()
			roles["founder"] = grants
			roles["admin"]["apiKey"] = all
			roles["viewer"] = access.Statements{"apiKey": {"read"}}
			orgs, err := org.NewService(org.Options{Store: store, CreatorRole: "founder", Roles: roles, DynamicAccessControl: true, RoleControl: &control})
			must(err)
			if _, err := ak.New(ak.Options{Store: store, ConfigID: "both", Organization: &ak.OrganizationOptions{RolesFrom: orgs, Roles: map[string][]string{"viewer": {"read"}}}}); err == nil {
				t.Fatal("organization roles were taken from two places")
			}
			teams, err := ak.New(ak.Options{Store: store, ConfigID: "teams", Organization: &ak.OrganizationOptions{RolesFrom: orgs}})
			must(err)
			plugin, err := ak.NewPlugin(teams)
			must(err)
			const origin = "https://org-keys.example"
			off := false
			host, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("o", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{orgs.Plugin(), plugin}})
			must(err)
			signUp := func(name string) (*client.Client, string) {
				t.Helper()
				c, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
				must(err)
				u, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: name, Email: name + "@example.test", Password: "org-keys-password"})
				must(err)
				return c, u.User.ID
			}
			founder, founderID := signUp("founder")
			var group org.Organization
			must(founder.Do(ctx, http.MethodPost, "/organization/create", map[string]any{"name": "Platform", "slug": "platform"}, &group))
			ids := map[string]string{}
			member := func(name, role string) *client.Client {
				t.Helper()
				c, id := signUp(name)
				_, err := store.db.ExecContext(ctx, store.bind(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,?,?,?,?)`), name+"-member", group.ID, id, role, store.date(time.Now()))
				must(err)
				ids[name] = id
				return c
			}
			owner, viewer, admin, auditor := member("owner", "owner"), member("viewer", "viewer"), member("admin", "admin"), member("auditor", "auditor")
			request := client.CreateAPIKeyRequest{ConfigID: "teams", OrganizationID: group.ID, Name: "Deploy"}

			key, err := founder.CreateAPIKey(ctx, request)
			if err != nil || key.ReferenceID != group.ID {
				t.Fatal("the organization's creator role could not manage keys", err)
			}
			_, readErr := owner.GetAPIKey(ctx, key.ID, "teams")
			_, createErr := owner.CreateAPIKey(ctx, request)
			if keyErrorCode(readErr) != "INSUFFICIENT_API_KEY_PERMISSIONS" || keyErrorCode(createErr) != "INSUFFICIENT_API_KEY_PERMISSIONS" {
				t.Fatal("a role outside the creator role managed keys without an apiKey grant", readErr, createErr)
			}

			_, readErr = viewer.GetAPIKey(ctx, key.ID, "teams")
			page, listErr := viewer.ListAPIKeys(ctx, "teams", ak.PageOptions{OrganizationID: group.ID})
			_, createErr = viewer.CreateAPIKey(ctx, request)
			deleteErr := viewer.DeleteAPIKey(ctx, key.ID, "teams")
			made, adminErr := admin.CreateAPIKey(ctx, request)
			if readErr != nil || listErr != nil || page.Total != 1 || keyErrorCode(createErr) != "INSUFFICIENT_API_KEY_PERMISSIONS" || keyErrorCode(deleteErr) != "INSUFFICIENT_API_KEY_PERMISSIONS" || adminErr != nil {
				t.Fatal("apiKey role statements did not set read and management access", readErr, listErr, createErr, deleteErr, adminErr)
			}
			renamed := "Renamed"
			if _, err := admin.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{ConfigID: "teams", KeyID: made.ID, Name: &renamed}); err != nil {
				t.Fatal("apiKey role statements did not allow an update", err)
			}
			if err := admin.DeleteAPIKey(ctx, made.ID, "teams"); err != nil {
				t.Fatal("apiKey role statements did not allow a delete", err)
			}

			if _, err := auditor.GetAPIKey(ctx, key.ID, "teams"); keyErrorCode(err) != "INSUFFICIENT_API_KEY_PERMISSIONS" {
				t.Fatal("a role without grants read an organization key", err)
			}
			must(founder.Do(ctx, http.MethodPost, "/organization/create-role", map[string]any{"organizationId": group.ID, "role": "auditor", "permission": map[string]any{"apiKey": []string{"read"}}}, nil))
			_, readErr = auditor.GetAPIKey(ctx, key.ID, "teams")
			_, createErr = auditor.CreateAPIKey(ctx, request)
			if readErr != nil || keyErrorCode(createErr) != "INSUFFICIENT_API_KEY_PERMISSIONS" {
				t.Fatal("a role stored by the organization did not grant exactly its apiKey actions", readErr, createErr)
			}

			// Without stored roles the linked policy decides alone, and the
			// creator role needs no apiKey grant of its own.
			plainRoles := org.DefaultRoles()
			plainRoles["founder"] = org.DefaultRoles()["member"]
			plainRoles["viewer"] = access.Statements{"apiKey": {"read"}}
			static, err := org.NewService(org.Options{Store: store, CreatorRole: "founder", Roles: plainRoles})
			must(err)
			staticKeys, err := ak.New(ak.Options{Store: store, ConfigID: "static", Organization: &ak.OrganizationOptions{RolesFrom: static}})
			must(err)
			made, err = staticKeys.Create(ctx, founderID, ak.CreateInput{OrganizationID: group.ID})
			if err != nil {
				t.Fatal("the creator role without an apiKey grant could not manage keys", err)
			}
			_, readErr = staticKeys.Get(ctx, ids["viewer"], made.ID)
			_, ownerErr := staticKeys.Get(ctx, ids["owner"], made.ID)
			if readErr != nil || keyErrorCode(ownerErr) != "INSUFFICIENT_API_KEY_PERMISSIONS" {
				t.Fatal("a linked policy without stored roles did not decide key access", readErr, ownerErr)
			}
		})
	}
}
