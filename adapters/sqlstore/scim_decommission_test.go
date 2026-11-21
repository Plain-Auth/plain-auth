package sqlstore

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/plugins/scim"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func TestSCIMDirectoryRetirement(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"scim-managed"})
			must(err)
			open := func() (*Store, *scim.Handler) {
				s, err := OpenWithSchema(ctx, dialect, dsn, ddl)
				must(err)
				t.Cleanup(func() { s.Close() })
				host, err := auth.New(auth.Options{Secret: strings.Repeat("x", 40), BaseURL: "https://retire.test", BasePath: "/identity/custom", Store: s})
				must(err)
				h, err := scim.New(host, scim.Options{Store: s, Managed: &scim.ManagedOptions{CredentialHashSecret: strings.Repeat("k", 40)}, Connections: []scim.Connection{
					{Directory: scim.Directory{ID: "static", ProvisioningDomainID: "agency"}, Credentials: []scim.Credential{{ID: "static-key", Token: "static-token"}}},
					{Directory: scim.Directory{ID: "other", ProvisioningDomainID: "foreign"}, Credentials: []scim.Credential{{ID: "other-key", Token: "other-token"}}},
				}})
				must(err)
				return s, h
			}
			s, one := open()
			_, two := open()
			issue := func(request string) scim.IssuedCredential {
				i, e := one.Catalog().Create(ctx, "agency", request, "owner", scim.CredentialPolicy{Scopes: []string{scim.UsersRead, scim.UsersWrite}, ExpiresAt: time.Now().Add(time.Hour)})
				must(e)
				return i
			}
			i := issue("catalog-retire-never-used")
			d := scim.Directory{ID: i.Connection.ConnectionID, ProvisioningDomainID: "agency"}
			f, e := one.Catalog().Decommission(ctx, scim.Directory{ID: d.ID, ProvisioningDomainID: "foreign"}, "imposter")
			if !errors.Is(e, scim.ErrManagedNotFound) || f.Connection.ConnectionID != "" {
				t.Fatal(f, e)
			}
			z, e := one.Catalog().Decommission(ctx, d, "owner")
			must(e)
			if z.Connection.Status != "decommissioned" || z.Decommission.Status != "complete" || z.Decommission.Batches != 0 || z.Decommission.ReconciledUsers != 0 || z.Credentials[0].Status != "decommissioned" {
				t.Fatal(z)
			}
			call := func(handler *scim.Handler, token, verb string, body map[string]any, want int) {
				t.Helper()
				res := scimRequest(handler, verb, "Users", token, body)
				if res.Code != want {
					t.Fatalf("%s: %d %s", verb, res.Code, res.Body.String())
				}
			}
			createUser := func(h *scim.Handler, token, email string) {
				call(h, token, "POST", map[string]any{"userName": email, "schemas": []string{scim.UserSchema}}, 201)
			}
			call(two, i.Token, "GET", nil, 401)
			// Even a declared credential available on another node cannot reopen a
			// connection retired before its first directory request.
			static := scim.Directory{ID: "static", ProvisioningDomainID: "agency"}
			if _, e = two.Decommission(ctx, scim.Directory{ID: "static", ProvisioningDomainID: "foreign"}); !errors.Is(e, scim.ErrDomain) {
				t.Fatal(e)
			}
			base, e := two.Decommission(ctx, static)
			must(e)
			if base.Status != "complete" {
				t.Fatal(base)
			}
			call(one, "static-token", "GET", nil, 401)
			if _, e = two.Decommission(ctx, scim.Directory{ID: "static", ProvisioningDomainID: "foreigN"}); !errors.Is(e, scim.ErrDomain) {
				t.Fatal(e)
			}

			i = issue("catalog-retire-populated")
			d.ID = i.Connection.ConnectionID
			for n := range 51 {
				createUser(one, i.Token, fmt.Sprintf("retire-%02d@example.test", n))
			}
			createUser(two, "other-token", "retained@example.test")
			session := func(email, id string) string {
				u, e := s.FindAccountUser(ctx, email)
				must(e)
				now := time.Now().UTC()
				must(s.CreateSession(ctx, auth.StoredSession{Session: auth.Session{ID: id, Token: id, UserID: u.ID, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}))
				return u.ID
			}
			keep := session("retained@example.test", "keep-session")
			owner := session("retire-00@example.test", "retire-session")
			// Import a second participating source for one account. Retiring this
			// directory releases its profile ownership while that source keeps sessions active.
			sharedOwner := session("retire-01@example.test", "shared-session")
			createUser(two, "other-token", "shared-source@example.test")
			foreignSource, err := s.FindAccountUser(ctx, "shared-source@example.test")
			must(err)
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "scimUser" SET "userId"=? WHERE "userId"=?`), sharedOwner, foreignSource.ID)
			must(err)
			// Put the dependent authorization grant in the second page so the
			// resume test starts after an actual persisted 50-user checkpoint.
			var resource, grantOwner string
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "id","userId" FROM "scimUser" WHERE "connectionId"=? ORDER BY "userId" DESC LIMIT 1`), d.ID).Scan(&resource, &grantOwner))
			stamp := s.date(time.Now())
			_, e = s.db.ExecContext(ctx, s.bind(`INSERT INTO "scimProjectionGrant" ("id","connectionId","provisioningDomainId","scimUserId","userId","sourceKind","sourceId","role","grantKey","createdAt","updatedAt") VALUES (?,?,?,?,?,'user',?,'app-role','test-grant',?,?)`), "test-grant", d.ID, d.ProvisioningDomainID, resource, grantOwner, resource, stamp, stamp)
			must(e)
			_, e = one.Catalog().Decommission(ctx, d, "first-admin")
			var typed *scim.Error
			if !errors.As(e, &typed) || typed.Status != 409 {
				t.Fatal(e)
			}
			call(two, i.Token, "GET", nil, 401)
			openState, e := two.Catalog().Get(ctx, d)
			must(e)
			if openState.Connection.Status != "decommissioning" || openState.Credentials[0].Status != "decommissioned" {
				t.Fatal(openState)
			}
			if _, e = one.Catalog().Rotate(ctx, d, "admin", scim.CredentialPolicy{Scopes: []string{scim.UsersRead}, ExpiresAt: time.Now().Add(time.Hour)}); !errors.Is(e, scim.ErrManagedConflict) {
				t.Fatal(e)
			}

			// A pinned peer already processing a lease retains its checkpoint. Once
			// that worker disappears, a new instance can reclaim its expired lease.
			until := time.Now().Add(time.Minute)
			_, e = s.db.ExecContext(ctx, s.bind(`UPDATE "scimConnectionBinding" SET "decommissionLeaseId"='peer',"decommissionLeaseExpiresAt"=? WHERE "connectionKey"=?`), s.date(until), scimKey("scim-connection", d.ID))
			must(e)
			pending, e := two.Catalog().Decommission(ctx, d, "second-admin")
			must(e)
			if pending.Decommission.RetryAfter == nil || pending.Decommission.Status != "reconciling" || pending.Connection.Status != "decommissioning" || pending.Decommission.Batches != 1 || pending.Decommission.ReconciledUsers != 50 {
				t.Fatal(pending)
			}
			var grantCount int
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "scimProjectionGrant" WHERE "id"='test-grant'`)).Scan(&grantCount))
			if grantCount != 1 {
				t.Fatal("stored authorization grant lost on retirement failure")
			}
			_, e = s.db.ExecContext(ctx, s.bind(`DELETE FROM "scimProjectionGrant" WHERE "id"='test-grant'`))
			must(e)
			_, e = s.db.ExecContext(ctx, s.bind(`UPDATE "scimConnectionBinding" SET "decommissionLeaseExpiresAt"=? WHERE "connectionKey"=?`), s.date(time.Now().Add(-time.Minute)), scimKey("scim-connection", d.ID))
			must(e)
			errs := make(chan error, 2)
			for _, h := range []*scim.Handler{one, two} {
				go func() { _, e := h.Catalog().Decommission(ctx, d, "second-admin"); errs <- e }()
			}
			for range 2 {
				must(<-errs)
			}
			done, e := two.Catalog().Decommission(ctx, d, "third-admin")
			must(e)
			if done.Connection.Status != "decommissioned" || *done.Connection.DecommissionStartedBy != "first-admin" || *done.Connection.DecommissionedBy != "second-admin" || done.Decommission.ReconciledUsers != 51 || done.Decommission.Batches != 2 || done.Decommission.CompletedAt == nil || done.Decommission.RetryAfter != nil {
				t.Fatal(done)
			}
			events, e := one.Catalog().Events(ctx, d, scim.EventQuery{})
			must(e)
			if events.Total != 4 || events.Events[2].Type != "connection.decommissioning" || events.Events[3].Type != "connection.decommissioned" {
				t.Fatal(events)
			}
			for _, check := range []struct {
				q, id string
				want  int
			}{
				{`SELECT COUNT(*) FROM "session" WHERE "userId"=?`, owner, 0},
				{`SELECT COUNT(*) FROM "session" WHERE "userId"=?`, keep, 1},
				{`SELECT COUNT(*) FROM "session" WHERE "userId"=?`, sharedOwner, 1},
				{`SELECT COUNT(*) FROM "scimSubject" WHERE "userId"=? AND "profileSourceId" IS NULL`, sharedOwner, 1},
				{`SELECT COUNT(*) FROM "scimSubject" WHERE "userId"=? AND "profileSourceId" IS NULL`, owner, 1},
				{`SELECT COUNT(*) FROM "scimUser" WHERE "connectionId"=?`, d.ID, 51},
			} {
				var n int
				must(s.db.QueryRowContext(ctx, s.bind(check.q), check.id).Scan(&n))
				if n != check.want {
					t.Fatalf("%s: %d; want %d", check.q, n, check.want)
				}
			}
			call(two, "other-token", "GET", nil, 200)
		})
	}
}
