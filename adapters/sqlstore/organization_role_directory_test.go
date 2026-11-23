package sqlstore

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestOrganizationRoleDirectory(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			db, writer, owner, other, group := invitationWriterFixture(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"organization-teams", "organization-roles"})
			must(err)
			must(db.migrate(ctx, ddl))
			service, err := org.NewService(org.Options{Store: db, DynamicAccessControl: true})
			must(err)
			sdk := organizationRoleClient(t, db, service, owner)
			read := service.Store().(org.RoleDirectoryStore)
			if _, err := db.ListOrganizationRoles(ctx, owner.ID, owner.UserID, group.ID); err == nil {
				t.Fatal("disabled store served the role directory")
			}
			created := time.Date(2023, 4, 5, 6, 7, 8, 0, time.UTC)
			updated := created.Add(120 * time.Millisecond)
			exec := func(q string, args ...any) {
				t.Helper()
				_, err := writer.db.ExecContext(ctx, writer.bind(q), args...)
				must(err)
			}
			exec(`INSERT INTO "organizationRole" ("id","organizationId","role","permission","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`,
				"R-one", group.ID, "review & accept", `{"report":["read","review"]}`, writer.date(created), writer.date(updated))
			def, err := sdk.GetOrganizationRole(ctx, org.RoleQuery{RoleName: "review & accept", RoleID: "wrong"})
			must(err)
			if def.ID != "R-one" || def.OrganizationID != group.ID || !slices.Equal(def.Permission["report"], []string{"read", "review"}) || !def.CreatedAt.Equal(created) || def.UpdatedAt == nil || !def.UpdatedAt.Equal(updated) {
				t.Fatalf("unexpected SDK role: %+v", def)
			}
			var wire map[string]any
			must(sdk.Do(ctx, http.MethodGet, "/organization/get-role?roleId=R-one", nil, &wire))
			if wire["createdAt"] != "2023-04-05T06:07:08.000Z" || wire["updatedAt"] != "2023-04-05T06:07:08.120Z" {
				t.Fatal("unexpected role timestamps on the wire", wire)
			}
			defs, err := sdk.ListOrganizationRoles(ctx, group.ID)
			must(err)
			if len(defs) != 1 || defs[0].ID != def.ID {
				t.Fatalf("unexpected SDK directory: %+v", defs)
			}
			for _, query := range []org.RoleQuery{{RoleName: "Review & accept"}, {RoleID: "r-one"}, {RoleName: "owner"}} {
				_, err = read.GetOrganizationRole(ctx, owner.ID, owner.UserID, query)
				if !errors.Is(err, org.ErrRoleNotFound) {
					t.Fatalf("expected strict stored-role lookup for %+v: %v", query, err)
				}
			}
			_, err = read.ListOrganizationRoles(ctx, owner.ID, other.UserID, group.ID)
			if !errors.Is(err, org.ErrUnauthenticated) {
				t.Fatal("read a directory with a mismatched session", err)
			}
			exec(`UPDATE "member" SET "role"=? WHERE "organizationId"=? AND "userId"=?`, "review & accept", group.ID, owner.UserID)
			_, err = sdk.ListOrganizationRoles(ctx, group.ID)
			var problem *auth.APIError
			if !errors.As(err, &problem) || problem.Code != org.ErrListRoleDenied.Code {
				t.Fatal("read directory after losing ac.read", err)
			}
			exec(`UPDATE "organizationRole" SET "permission"=?,"updatedAt"=NULL WHERE "id"=?`, `{"ac":["read"]}`, def.ID)
			def, err = sdk.GetOrganizationRole(ctx, org.RoleQuery{OrganizationID: group.ID, RoleID: def.ID})
			must(err)
			if def.UpdatedAt != nil || !slices.Equal(def.Permission["ac"], []string{"read"}) {
				t.Fatal("directory did not pick up the new grants and null update time", def)
			}
			must(writer.DeleteSession(ctx, owner.Token))
			_, err = read.GetOrganizationRole(ctx, owner.ID, owner.UserID, org.RoleQuery{OrganizationID: group.ID, RoleID: def.ID})
			if !errors.Is(err, org.ErrUnauthenticated) {
				t.Fatal("read stored role after session revocation", err)
			}
		})
	}
}

func organizationRoleClient(t *testing.T, db *Store, service *org.Service, session auth.Session, plugins ...auth.Plugin) *client.Client {
	t.Helper()
	host := httptest.NewUnstartedServer(nil)
	t.Cleanup(host.Close)
	base := "http://" + host.Listener.Addr().String()
	instance, err := auth.New(auth.Options{Store: db, BaseURL: base, Secret: strings.Repeat("R", 32), Plugins: append([]auth.Plugin{service.Plugin()}, plugins...)})
	if err != nil {
		t.Fatal(err)
	}
	host.Config.Handler = instance
	host.Start()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(u, []*http.Cookie{instance.SessionCookie(session.Token, true)})
	sdk, err := client.New(base, &http.Client{Jar: jar, Transport: host.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	return sdk
}
