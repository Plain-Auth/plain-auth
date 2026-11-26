package sqlstore

import (
	"context"
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

// orgKeyHost mounts an organization service with dynamic access control and
// a "teams" key configuration that takes its roles from it. The creator
// role "founder" holds no apiKey grant; "admin" holds every apiKey action and
// "viewer" only read.
type orgKeyHost struct {
	store *Store
	orgs  *org.Service
	teams *ak.Service
	host  *plainauth.Auth
	group org.Organization
	ids   map[string]string
	users map[string]*client.Client
}

func newOrgKeyHost(t *testing.T, dialect string) *orgKeyHost {
	t.Helper()
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
	t.Cleanup(func() { store.Close() })
	all := []string{"create", "read", "update", "delete"}
	vocabulary := org.DefaultRoles()["owner"]
	vocabulary["apiKey"] = all
	control := access.New(vocabulary)
	roles := org.DefaultRoles()
	roles["founder"] = org.DefaultRoles()["owner"]
	roles["admin"]["apiKey"] = all
	roles["viewer"] = access.Statements{"apiKey": {"read"}}
	orgs, err := org.NewService(org.Options{Store: store, CreatorRole: "founder", Roles: roles, DynamicAccessControl: true, RoleControl: &control})
	must(err)
	teams, err := ak.New(ak.Options{Store: store, ConfigID: "teams", Organization: &ak.OrganizationOptions{RolesFrom: orgs}})
	must(err)
	plugin, err := ak.NewPlugin(teams)
	must(err)
	const origin = "https://org-keys.example"
	off := false
	host, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("o", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{orgs.Plugin(), plugin}})
	must(err)
	h := &orgKeyHost{store: store, orgs: orgs, teams: teams, host: host, ids: map[string]string{}, users: map[string]*client.Client{}}
	signUp := func(name string) {
		t.Helper()
		c, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
		must(err)
		u, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: name, Email: name + "@example.test", Password: "org-keys-password"})
		must(err)
		h.ids[name], h.users[name] = u.User.ID, c
	}
	signUp("founder")
	must(h.users["founder"].Do(ctx, http.MethodPost, "/organization/create", map[string]any{"name": "Platform", "slug": "platform"}, &h.group))
	return h
}

// member signs a user up and inserts them into the organization with role.
func (h *orgKeyHost) member(t *testing.T, name, role string) *client.Client {
	t.Helper()
	ctx := t.Context()
	c, err := client.New("https://org-keys.example", &http.Client{Transport: guestTransport{h.host}})
	if err != nil {
		t.Fatal(err)
	}
	u, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: name, Email: name + "@example.test", Password: "org-keys-password"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.db.ExecContext(ctx, h.store.bind(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,?,?,?,?)`), name+"-member", h.group.ID, u.User.ID, role, h.store.date(time.Now())); err != nil {
		t.Fatal(err)
	}
	h.ids[name], h.users[name] = u.User.ID, c
	return c
}

// With RolesFrom, organization key actions follow the organization
// service's roles: its creator role may do everything without an apiKey
// grant, other roles need the action on the apiKey resource, a role an
// organization stores counts at once, and an invalid stored role refuses.
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
			h := newOrgKeyHost(t, dialect)
			if _, err := ak.New(ak.Options{Store: h.store, ConfigID: "both", Organization: &ak.OrganizationOptions{RolesFrom: h.orgs, Roles: map[string][]string{"viewer": {"read"}}}}); err == nil {
				t.Fatal("organization roles were taken from two places")
			}
			founder := h.users["founder"]
			owner, viewer, admin, auditor := h.member(t, "owner", "owner"), h.member(t, "viewer", "viewer"), h.member(t, "admin", "admin"), h.member(t, "auditor", "auditor")
			request := client.CreateAPIKeyRequest{ConfigID: "teams", OrganizationID: h.group.ID, Name: "Deploy"}

			// The creator role holds no apiKey grant and still manages keys.
			key, err := founder.CreateAPIKey(ctx, request)
			if err != nil || key.ReferenceID != h.group.ID {
				t.Fatal("the organization's creator role could not create a key", err)
			}
			renamed := "Renamed"
			_, readErr := founder.GetAPIKey(ctx, key.ID, "teams")
			page, listErr := founder.ListAPIKeys(ctx, "teams", ak.PageOptions{OrganizationID: h.group.ID})
			_, updateErr := founder.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{ConfigID: "teams", KeyID: key.ID, Name: &renamed})
			spare, spareErr := founder.CreateAPIKey(ctx, request)
			must(spareErr)
			deleteErr := founder.DeleteAPIKey(ctx, spare.ID, "teams")
			if readErr != nil || listErr != nil || page.Total != 1 || updateErr != nil || deleteErr != nil {
				t.Fatal("the creator role without an apiKey grant could not read, list, update and delete keys", readErr, listErr, updateErr, deleteErr)
			}

			_, readErr = owner.GetAPIKey(ctx, key.ID, "teams")
			_, createErr := owner.CreateAPIKey(ctx, request)
			if keyErrorCode(readErr) != "INSUFFICIENT_API_KEY_PERMISSIONS" || keyErrorCode(createErr) != "INSUFFICIENT_API_KEY_PERMISSIONS" {
				t.Fatal("a role outside the creator role managed keys without an apiKey grant", readErr, createErr)
			}

			_, readErr = viewer.GetAPIKey(ctx, key.ID, "teams")
			page, listErr = viewer.ListAPIKeys(ctx, "teams", ak.PageOptions{OrganizationID: h.group.ID})
			_, createErr = viewer.CreateAPIKey(ctx, request)
			deleteErr = viewer.DeleteAPIKey(ctx, key.ID, "teams")
			made, adminErr := admin.CreateAPIKey(ctx, request)
			if readErr != nil || listErr != nil || page.Total != 1 || keyErrorCode(createErr) != "INSUFFICIENT_API_KEY_PERMISSIONS" || keyErrorCode(deleteErr) != "INSUFFICIENT_API_KEY_PERMISSIONS" || adminErr != nil {
				t.Fatal("apiKey role statements did not set read and management access", readErr, listErr, createErr, deleteErr, adminErr)
			}
			_, viewerUpdate := viewer.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{ConfigID: "teams", KeyID: key.ID, Name: &renamed})
			_, ownerList := owner.ListAPIKeys(ctx, "teams", ak.PageOptions{OrganizationID: h.group.ID})
			if keyErrorCode(viewerUpdate) != "INSUFFICIENT_API_KEY_PERMISSIONS" || keyErrorCode(ownerList) != "INSUFFICIENT_API_KEY_PERMISSIONS" {
				t.Fatal("a member without the update or read grant updated or listed organization keys", viewerUpdate, ownerList)
			}
			if _, err := admin.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{ConfigID: "teams", KeyID: made.ID, Name: &renamed}); err != nil {
				t.Fatal("apiKey role statements did not allow an update", err)
			}
			if err := admin.DeleteAPIKey(ctx, made.ID, "teams"); err != nil {
				t.Fatal("apiKey role statements did not allow a delete", err)
			}

			if _, err := auditor.GetAPIKey(ctx, key.ID, "teams"); keyErrorCode(err) != "INSUFFICIENT_API_KEY_PERMISSIONS" {
				t.Fatal("a role without grants read an organization key", err)
			}
			must(admin.Do(ctx, http.MethodPost, "/organization/create-role", map[string]any{"organizationId": h.group.ID, "role": "auditor", "permission": map[string]any{"apiKey": []string{"read"}}}, nil))
			_, readErr = auditor.GetAPIKey(ctx, key.ID, "teams")
			_, createErr = auditor.CreateAPIKey(ctx, request)
			if readErr != nil || keyErrorCode(createErr) != "INSUFFICIENT_API_KEY_PERMISSIONS" {
				t.Fatal("a role stored by the organization did not grant exactly its apiKey actions", readErr, createErr)
			}

			// Without stored roles the linked policy decides alone: the stored
			// auditor role grants nothing, and the creator role needs no apiKey
			// grant of its own.
			plainRoles := org.DefaultRoles()
			plainRoles["founder"] = org.DefaultRoles()["member"]
			plainRoles["viewer"] = access.Statements{"apiKey": {"read"}}
			static, err := org.NewService(org.Options{Store: h.store, CreatorRole: "founder", Roles: plainRoles})
			must(err)
			staticKeys, err := ak.New(ak.Options{Store: h.store, ConfigID: "static", Organization: &ak.OrganizationOptions{RolesFrom: static}})
			must(err)
			fixed, err := staticKeys.Create(ctx, h.ids["founder"], ak.CreateInput{OrganizationID: h.group.ID})
			if err != nil {
				t.Fatal("the creator role without an apiKey grant could not manage keys", err)
			}
			_, getErr := staticKeys.Get(ctx, h.ids["founder"], fixed.ID)
			_, listErr = staticKeys.List(ctx, h.ids["founder"], ak.PageOptions{OrganizationID: h.group.ID})
			_, updateErr = staticKeys.Update(ctx, h.ids["founder"], fixed.ID, ak.UpdateInput{Name: &renamed})
			if getErr != nil || listErr != nil || updateErr != nil {
				t.Fatal("a creator without an apiKey grant could not read, list or update keys without stored roles", getErr, listErr, updateErr)
			}
			_, readErr = staticKeys.Get(ctx, h.ids["viewer"], fixed.ID)
			_, ownerErr := staticKeys.Get(ctx, h.ids["owner"], fixed.ID)
			_, auditorErr := staticKeys.Get(ctx, h.ids["auditor"], fixed.ID)
			if readErr != nil || keyErrorCode(ownerErr) != "INSUFFICIENT_API_KEY_PERMISSIONS" || keyErrorCode(auditorErr) != "INSUFFICIENT_API_KEY_PERMISSIONS" {
				t.Fatal("a linked policy without stored roles did not decide key access alone", readErr, ownerErr, auditorErr)
			}
			must(staticKeys.Delete(ctx, h.ids["founder"], fixed.ID))

			// An invalid stored role refuses every member, the creator included.
			_, err = h.store.db.ExecContext(ctx, h.store.bind(`INSERT INTO "organizationRole" ("id","organizationId","role","permission","createdAt") VALUES (?,?,?,?,?)`), "broken-role", h.group.ID, "broken", `{"apiKey":"read"}`, h.store.date(time.Now()))
			must(err)
			_, founderErr := founder.GetAPIKey(ctx, key.ID, "teams")
			_, viewerErr := viewer.GetAPIKey(ctx, key.ID, "teams")
			_, createErr = founder.CreateAPIKey(ctx, request)
			if keyErrorCode(founderErr) != "INSUFFICIENT_API_KEY_PERMISSIONS" || keyErrorCode(viewerErr) != "INSUFFICIENT_API_KEY_PERMISSIONS" || keyErrorCode(createErr) != "INSUFFICIENT_API_KEY_PERMISSIONS" {
				t.Fatal("an invalid stored role did not refuse key management with INSUFFICIENT_API_KEY_PERMISSIONS", founderErr, viewerErr, createErr)
			}
			_, err = h.store.db.ExecContext(ctx, h.store.bind(`DELETE FROM "organizationRole" WHERE "id"=?`), "broken-role")
			must(err)
			if _, err := founder.GetAPIKey(ctx, key.ID, "teams"); err != nil {
				t.Fatal("removing the invalid stored role did not restore access", err)
			}
		})
	}
}

// A key operation that waits on the organization lock checks the member's
// role against the stored grants committed with it, not against the grants
// of the snapshot it started with.
func TestOrganizationKeyRolesReadCurrentGrants(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			h := newOrgKeyHost(t, dialect)
			key, err := h.users["founder"].CreateAPIKey(ctx, client.CreateAPIKeyRequest{ConfigID: "teams", OrganizationID: h.group.ID, Name: "Guarded"})
			must(err)
			_, err = h.store.db.ExecContext(ctx, h.store.bind(`INSERT INTO "organizationRole" ("id","organizationId","role","permission","createdAt") VALUES (?,?,?,?,?)`), "limited-role", h.group.ID, "limited", `{"apiKey":["delete"]}`, h.store.date(time.Now()))
			must(err)
			worker := h.member(t, "worker", "none")

			holder, err := h.store.db.BeginTx(ctx, nil)
			must(err)
			defer holder.Rollback()
			if dialect != "sqlite" {
				var id string
				must(holder.QueryRowContext(ctx, h.store.bind(`SELECT "id" FROM "organization" WHERE "id"=? FOR UPDATE`), h.group.ID).Scan(&id))
			} else {
				_, err = holder.ExecContext(ctx, h.store.bind(`UPDATE "organization" SET "name"="name" WHERE "id"=?`), h.group.ID)
				must(err)
			}
			done := make(chan error, 1)
			go func() { done <- worker.DeleteAPIKey(context.WithoutCancel(ctx), key.ID, "teams") }()
			waiting := map[string]string{
				"mysql":    `SELECT COUNT(*) FROM information_schema.innodb_trx WHERE trx_state='LOCK WAIT'`,
				"postgres": `SELECT COUNT(*) FROM pg_locks WHERE NOT granted`,
			}[dialect]
			if waiting == "" {
				time.Sleep(200 * time.Millisecond)
			}
			// The lock views need privileges a test user may lack, so give up
			// after a second; the operation reaches the lock within it.
			for deadline := time.Now().Add(time.Second); waiting != "" && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
				var n int
				must(h.store.db.QueryRowContext(ctx, waiting).Scan(&n))
				if n > 0 {
					break
				}
			}
			// Revoke the stored grant, then move the worker into that role,
			// both committed while the key operation waits.
			_, err = holder.ExecContext(ctx, h.store.bind(`UPDATE "organizationRole" SET "permission"=? WHERE "id"=?`), `{"ac":["read"]}`, "limited-role")
			must(err)
			_, err = holder.ExecContext(ctx, h.store.bind(`UPDATE "member" SET "role"=? WHERE "id"=?`), "limited", "worker-member")
			must(err)
			must(holder.Commit())
			err = <-done
			if _, getErr := h.users["founder"].GetAPIKey(ctx, key.ID, "teams"); keyErrorCode(err) != "INSUFFICIENT_API_KEY_PERMISSIONS" || getErr != nil {
				t.Fatal("a key operation combined a current role with revoked stored grants", err, getErr)
			}
		})
	}
}
