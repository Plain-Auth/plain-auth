package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/scim"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestSCIMGroupApplicationProjection(t *testing.T) {
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
			ddl, e := schema.Generate(dialect, []string{"scim-managed"})
			must(e)
			base, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			t.Cleanup(func() { base.Close() })
			peer, e := Open(ctx, dialect, dsn)
			must(e)
			t.Cleanup(func() { peer.Close() })
			const domain = "Workforce"
			exec := func(q string, args ...any) {
				t.Helper()
				_, err := base.db.ExecContext(ctx, base.bind(q), args...)
				must(err)
			}
			value := func(q string, args ...any) string {
				t.Helper()
				var v string
				must(base.db.QueryRowContext(ctx, base.bind(q), args...).Scan(&v))
				return v
			}
			count := func(q string, args ...any) int {
				t.Helper()
				var v int
				must(base.db.QueryRowContext(ctx, base.bind(q), args...).Scan(&v))
				return v
			}
			exec(`CREATE TABLE "hostRole" ("role" VARCHAR(64) PRIMARY KEY)`)
			exec(`CREATE TABLE "hostAssignment" ("grantKey" VARCHAR(64) PRIMARY KEY,"owner" VARCHAR(36),"domain" VARCHAR(64),"role" VARCHAR(64),"source" VARCHAR(20))`)
			exec(`INSERT INTO "hostRole" ("role") VALUES ('reader'),('editor')`)
			var fail atomic.Int32
			var calls atomic.Int32
			var pause atomic.Bool
			entered, release := make(chan struct{}), make(chan struct{})
			policy := scim.Projection{PolicyID: "team-mapping-v1",
				Map: func(_ context.Context, _ scim.ProjectionTx, in scim.RoleMapping) ([]string, error) {
					if fail.Load() == 1 {
						return nil, errors.New("fixture mapping error")
					}
					if in.Group.ExternalID == "directory-readers" {
						return []string{" reader ", "reader", "missing", ""}, nil
					}
					if in.Group.ExternalID == "directory-editors" {
						return []string{"editor"}, nil
					}
					return nil, nil
				},
				Exists: func(ctx context.Context, tx scim.ProjectionTx, in scim.RoleLookup) (bool, error) {
					if fail.Load() == 2 {
						return false, errors.New("fixture role catalog error")
					}
					var n int
					e := tx.QueryRowContext(ctx, tx.Bind(`SELECT COUNT(*) FROM "hostRole" WHERE "role"=?`), in.Role).Scan(&n)
					return n != 0, e
				},
				ReconcileUser: func(ctx context.Context, tx scim.ProjectionTx, user scim.ProjectedUser) error {
					calls.Add(1)
					if pause.CompareAndSwap(true, false) {
						entered <- struct{}{}
						select {
						case <-release:
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					if _, err := tx.ExecContext(ctx, tx.Bind(`DELETE FROM "hostAssignment" WHERE `+tx.Exact(`"domain"`)+`=? AND `+tx.Exact(`"owner"`)+`=? AND "source"='scim'`), user.ProvisioningDomainID, user.UserID); err != nil {
						return err
					}
					for _, g := range user.Grants {
						if g.UserID != user.UserID || g.ProvisioningDomainID != user.ProvisioningDomainID || !user.Active || !slices.ContainsFunc(user.Sources, func(src scim.IdentitySource) bool {
							return src.ID == g.ID && src.Active && src.SCIMUserID == g.SCIMUserID
						}) {
							return errors.New("inconsistent source")
						}
						if _, err := tx.ExecContext(ctx, tx.Bind(`INSERT INTO "hostAssignment" ("grantKey","owner","domain","role","source") VALUES (?,?,?,?,'scim')`), g.GrantKey, user.UserID, user.ProvisioningDomainID, g.Role); err != nil {
							return err
						}
					}
					if fail.Load() == 3 {
						return errors.New("fixture application error after writes")
					}
					return nil
				},
			}
			serve := func(s *Store) *scim.Handler {
				t.Helper()
				host, e := auth.New(auth.Options{Store: s, BaseURL: "https://directory.test", BasePath: "/identity/custom", Secret: strings.Repeat("p", 36)})
				must(e)
				connections := []scim.Connection{}
				for _, x := range []struct{ id, domain string }{{"north", domain}, {"south", domain}, {"other", "workforce"}} {
					connections = append(connections, scim.Connection{Directory: scim.Directory{ID: x.id, ProvisioningDomainID: x.domain}, Credentials: []scim.Credential{{ID: "main", Token: x.id}, {ID: "read", Token: x.id + "-read", Scopes: []string{scim.GroupsRead}}}})
				}
				h, e := scim.New(host, scim.Options{Store: s, Connections: connections})
				must(e)
				return h
			}
			call := func(h http.Handler, method, path, token string, body map[string]any, status int) map[string]any {
				t.Helper()
				w := scimRequest(h, method, path, token, body)
				if w.Code != status {
					t.Fatalf("%s %s status %d, want %d: %s", method, path, w.Code, status, w.Body.String())
				}
				var data map[string]any
				if status != 204 {
					must(json.Unmarshal(w.Body.Bytes(), &data))
				}
				return data
			}
			usr := func(name string) map[string]any {
				return map[string]any{"schemas": []string{scim.UserSchema}, "userName": name + "@example.test", "externalId": name, "roles": []map[string]string{{"value": "admin"}}}
			}
			group := func(name, external string, members ...string) map[string]any {
				m := []map[string]string{}
				for _, id := range members {
					m = append(m, map[string]string{"value": id})
				}
				return map[string]any{"schemas": []string{scim.GroupSchema}, "displayName": name, "externalId": external, "members": m}
			}
			change := func(op, path string, v any) map[string]any {
				one := map[string]any{"op": op, "path": path}
				if v != nil {
					one["value"] = v
				}
				return map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []map[string]any{one}}
			}
			plain := serve(base)
			n := call(plain, "POST", "Users", "north", usr("n"), 201)["id"].(string)
			s := call(plain, "POST", "Users", "south", usr("s"), 201)["id"].(string)
			other := call(plain, "POST", "Users", "other", usr("other"), 201)["id"].(string)
			owner := value(`SELECT "userId" FROM "scimUser" WHERE "id"=?`, n)
			// A trusted offline import explicitly associates existing directory sources
			// with this canonical subject. Their profile email addresses are different.
			exec(`UPDATE "scimUser" SET "userId"=? WHERE "id" IN (?,?)`, owner, s, other)
			a := call(plain, "POST", "Groups", "north", group("north team", "directory-readers", n), 201)["id"].(string)
			b := call(plain, "POST", "Groups", "south", group("south team", "directory-readers", s), 201)["id"].(string)
			call(plain, "POST", "Groups", "other", group("other team", "directory-editors", other), 201)
			exec(`INSERT INTO "hostAssignment" ("grantKey","owner","domain","role","source") VALUES ('manual',?,?,'editor','manual')`, owner, domain)
			expect := func(read, edit int) {
				t.Helper()
				for _, x := range []struct {
					role string
					n    int
				}{{"reader", read}, {"editor", edit}, {"admin", 0}} {
					if n := count(`SELECT COUNT(*) FROM "hostAssignment" WHERE "domain"=? AND "owner"=? AND "role"=? AND "source"='scim'`, domain, owner, x.role); n != x.n {
						t.Fatalf("host %s=%d want %d", x.role, n, x.n)
					}
					if n := count(`SELECT COUNT(*) FROM "scimProjectionGrant" WHERE "provisioningDomainId"=? AND "userId"=? AND "role"=?`, domain, owner, x.role); n != x.n {
						t.Fatalf("ledger %s=%d want %d", x.role, n, x.n)
					}
				}
				if count(`SELECT COUNT(*) FROM "hostAssignment" WHERE "grantKey"='manual'`) != 1 {
					t.Fatal("manual role was removed")
				}
			}
			// Unknown imported provenance is never claimed, even at initial activation.
			now := base.date(time.Now())
			exec(`INSERT INTO "scimProjectionGrant" ("id","connectionId","provisioningDomainId","scimUserId","userId","sourceKind","sourceId","role","grantKey","createdAt","updatedAt") VALUES ('legacy','north',?,?,?,'import',?,'admin','unknown',?,?)`, domain, n, owner, a, now, now)
			_, e = base.EnableSCIMProjection(ctx, domain, policy)
			if !errors.Is(e, errUnknownGrant) {
				t.Fatal(e)
			}
			if count(`SELECT COUNT(*) FROM "plainauthSCIMProjectionPolicy"`) != 0 || count(`SELECT COUNT(*) FROM "scimProjectionGrant"`) != 1 {
				t.Fatal("import guard changed on failure")
			}
			// Even a matching hash does not authorize an imported source from
			// another connection.
			exec(`UPDATE "scimProjectionGrant" SET "grantKey"=?,"sourceKind"='group',"sourceId"=? WHERE "id"='legacy'`, scimKey("scim-projection-grant", "north", n, "group", b, "admin"), b)
			if _, e = base.EnableSCIMProjection(ctx, domain, policy); !errors.Is(e, errUnknownGrant) {
				t.Fatal("unbound imported source", e)
			}
			exec(`DELETE FROM "scimProjectionGrant" WHERE "id"='legacy'`)
			// A policy that only observes user lifecycle cannot take ownership
			// of existing role grants. A source-aware policy preserves matching rows.
			key := scimKey("scim-projection-grant", "north", n, "group", a, "reader")
			exec(`INSERT INTO "scimProjectionGrant" ("id","connectionId","provisioningDomainId","scimUserId","userId","sourceKind","sourceId","role","grantKey","createdAt","updatedAt") VALUES ('known','north',?,?,?,'group',?,'reader',?,?,?)`, domain, n, owner, a, key, now, now)
			lifecycle := policy
			lifecycle.Map = nil
			lifecycle.Exists = nil
			if _, e = base.EnableSCIMProjection(ctx, domain, lifecycle); e == nil {
				t.Fatal("lifecycle-only adoption removed existing grant")
			}

			first, e := base.EnableSCIMProjection(ctx, domain, policy)
			must(e)
			second, e := peer.EnableSCIMProjection(ctx, domain, policy)
			must(e)
			if calls.Load() != 1 {
				t.Fatalf("activation callback count %d", calls.Load())
			}
			if value(`SELECT "id" FROM "scimProjectionGrant" WHERE "grantKey"=?`, key) != "known" {
				t.Fatal("existing canonical grant replaced")
			}
			one, two := serve(first), serve(second)
			expect(2, 0)
			if value(`SELECT "grantKey" FROM "scimProjectionGrant" WHERE "sourceId"=?`, a) != scimKey("scim-projection-grant", "north", n, "group", a, "reader") {
				t.Fatal("grant key")
			}
			if count(`SELECT COUNT(*) FROM "scimProjectionGrant" WHERE `+base.scimExact(`"provisioningDomainId"`)+`=?`, "workforce") != 0 {
				t.Fatal("other domain projected")
			}
			// Verification cleanup is independent of durable domain ownership.
			exec(`DELETE FROM "verification" WHERE "expiresAt"<=?`, base.date(time.Now().Add(24*time.Hour)))
			call(plain, "GET", "Groups/"+a, "north", nil, 200)
			call(plain, "DELETE", "Groups/"+a, "north", nil, 409)
			call(plain, "POST", "Groups", "other", group("other team 2", "extra"), 201)
			call(one, "DELETE", "Groups/"+a, "north-read", nil, 403)
			wrong := policy
			wrong.PolicyID = "other"
			_, e = peer.EnableSCIMProjection(ctx, domain, wrong)
			if !errors.Is(e, errProjectionPolicy) {
				t.Fatal(e)
			}
			for _, kind := range []int32{1, 2, 3} {
				fail.Store(kind)
				call(two, "PUT", "Groups/"+a, "north", group("failed change", "directory-editors", n), 500)
				expect(2, 0)
				if got := call(one, "GET", "Groups/"+a, "north", nil, 200)["displayName"]; got != "north team" {
					t.Fatal(got)
				}
			}
			fail.Store(0)
			call(one, "PUT", "Groups/"+a, "north", group("changed", "directory-editors", n), 200)
			expect(1, 1)
			before := calls.Load()
			call(two, "PATCH", "Groups/"+a, "north", change("add", "members", []map[string]string{{"value": n}}), 200)
			if calls.Load() != before {
				t.Fatal("idempotent membership addition reran projection")
			}
			call(two, "PATCH", "Users/"+n, "north", change("replace", "active", false), 200)
			expect(1, 0)
			call(one, "POST", "Users", "north", usr("n"), 201)
			expect(1, 1)
			call(two, "PUT", "Groups/"+a, "north", group("changed", "directory-editors"), 200)
			expect(1, 0)
			// Opposite nodes mutate two source connections for the same subject.
			start := make(chan struct{})
			codes := make(chan int, 2)
			go func() {
				<-start
				codes <- scimRequest(one, "PUT", "Groups/"+a, "north", group("changed", "directory-editors", n)).Code
			}()
			go func() { <-start; codes <- scimRequest(two, "DELETE", "Groups/"+b, "south", nil).Code }()
			close(start)
			c1, c2 := <-codes, <-codes
			if c1+c2 != 404 || (c1 != 200 && c1 != 204) {
				t.Fatalf("concurrent responses %d %d", c1, c2)
			}
			expect(0, 1)
			// A server-side catalog change is explicitly replayed.
			exec(`DELETE FROM "hostRole" WHERE "role"='editor'`)
			_, e = first.ReconcileSCIMProjection(ctx, domain)
			must(e)
			expect(0, 0)
			exec(`INSERT INTO "hostRole" ("role") VALUES ('editor')`)
			_, e = second.ReconcileSCIMProjection(ctx, domain)
			must(e)
			expect(0, 1)
			fail.Store(3)
			if e = first.DisableSCIMProjection(ctx, domain); e == nil {
				t.Fatal("failed withdrawal committed")
			}
			expect(0, 1)
			fail.Store(0)
			pause.Store(true)
			withdrawn := make(chan error, 1)
			go func() { withdrawn <- second.DisableSCIMProjection(ctx, domain) }()
			<-entered
			pending := make(chan int, 1)
			go func() { pending <- scimRequest(plain, "POST", "Groups", "south", group("switchover", "switch-1")).Code }()
			release <- struct{}{}
			must(<-withdrawn)
			if status := <-pending; status != 201 {
				t.Fatal("plain writer observed partial withdrawal", status)
			}
			expect(0, 0)
			call(two, "POST", "Groups", "south", group("stale", "stale"), 409)
			call(plain, "POST", "Groups", "south", group("restored", "directory-readers", s), 201)
			pause.Store(true)
			enabled := make(chan error, 1)
			go func() { var err error; first, err = base.EnableSCIMProjection(ctx, domain, policy); enabled <- err }()
			<-entered
			go func() {
				pending <- scimRequest(plain, "POST", "Groups", "south", group("stale switchover", "switch-2")).Code
			}()
			release <- struct{}{}
			must(<-enabled)
			if status := <-pending; status != 409 {
				t.Fatal("plain writer bypassed activation", status)
			}
			expect(1, 1)
			_, e = base.SCIMDecommission(ctx, scim.Directory{ID: "north", ProvisioningDomainID: domain})
			if !errors.Is(e, errProjectionPolicy) {
				t.Fatal(e)
			}
			fail.Store(3)
			if _, e = first.SCIMDecommission(ctx, scim.Directory{ID: "north", ProvisioningDomainID: domain}); e == nil {
				t.Fatal("failed retirement batch committed")
			}
			expect(1, 1)
			call(one, "GET", "Groups/"+a, "north", nil, 401)
			fail.Store(0)
			_, e = first.SCIMDecommission(ctx, scim.Directory{ID: "north", ProvisioningDomainID: domain})
			must(e)
			expect(1, 0)
			call(two, "DELETE", "Users/"+s, "south", nil, 204)
			expect(0, 0)
			var leftover int
			must(base.db.QueryRowContext(ctx, base.bind(`SELECT COUNT(*) FROM "scimUser" WHERE "id"=?`), n).Scan(&leftover))
			if leftover != 1 {
				t.Fatal("retirement removed source")
			}
			// Ordinary account deletion uses the same application's projection.
			// Check rollback after the application writes and the plain-node gate.
			owned := call(two, "POST", "Users", "south", usr("deleted"), 201)["id"].(string)
			subject := value(`SELECT "userId" FROM "scimUser" WHERE "id"=?`, owned)
			call(two, "POST", "Groups", "south", group("deleted user", "directory-editors", owned), 201)
			stamp := time.Now().UTC()
			session := auth.StoredSession{Session: auth.Session{ID: "delete-session", UserID: subject, Token: "delete-token", CreatedAt: stamp, UpdatedAt: stamp, ExpiresAt: stamp.Add(time.Hour)}}
			must(first.CreateSession(ctx, session))
			if e = peer.DeleteAccount(ctx, subject, session.Token, "", "", stamp); !errors.Is(e, errProjectionPolicy) {
				t.Fatal(e)
			}
			fail.Store(3)
			if e = first.DeleteAccount(ctx, subject, session.Token, "", "", stamp); e == nil {
				t.Fatal("failed account withdrawal committed")
			}
			if count(`SELECT COUNT(*) FROM "hostAssignment" WHERE "owner"=?`, subject) != 1 {
				t.Fatal("failed withdrawal lost app role")
			}
			fail.Store(0)
			must(first.DeleteAccount(ctx, subject, session.Token, "", "", stamp))
			if count(`SELECT COUNT(*) FROM "hostAssignment" WHERE "owner"=?`, subject) != 0 {
				t.Fatal("account deletion retained app role")
			}
			// Case-distinct domain IDs can participate in the same identity.
			// The core owner deletion must withdraw both tenant projections.
			both, e := first.EnableSCIMProjection(ctx, "workforce", policy)
			must(e)
			_, e = first.ReconcileSCIMProjection(ctx, domain)
			must(e)
			if count(`SELECT COUNT(*) FROM "hostAssignment" WHERE `+base.scimExact(`"domain"`)+`=? AND "owner"=?`, "workforce", owner) != 1 {
				t.Fatal("tenant replay removed another domain's role")
			}

			session.ID = "both-domains"
			session.Token = "both-domains-token"
			session.UserID = owner
			must(both.CreateSession(ctx, session))
			if e = first.DeleteAccount(ctx, owner, session.Token, "", "", stamp); !errors.Is(e, errProjectionPolicy) {
				t.Fatal("missing other domain policy", e)
			}
			must(both.DeleteAccount(ctx, owner, session.Token, "", "", stamp))
			if count(`SELECT COUNT(*) FROM "hostAssignment" WHERE "owner"=? AND "source"='scim'`, owner) != 0 {
				t.Fatal("case-distinct tenant retained a source grant")
			}

		})
	}
}

// An explicit replay reports its domain, its reconciled users and its one
// committed batch.
func TestSCIMProjectionReplaySummary(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			ddl, e := schema.Generate(dialect, []string{"scim"})
			must(e)
			store, e := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(e)
			defer store.Close()
			calls := 0
			policy := scim.Projection{PolicyID: "replay-v1", ReconcileUser: func(context.Context, scim.ProjectionTx, scim.ProjectedUser) error { calls++; return nil }}
			empty, e := store.EnableSCIMProjection(ctx, "Empty", policy)
			must(e)
			var se *scim.Error
			calls = 0
			if _, e := empty.ReconcileSCIMProjection(ctx, "Tenant"); !errors.As(e, &se) || se.Status != 409 || calls != 0 {
				t.Fatal("replaying a domain without a configured policy did not answer 409", e)
			}
			if replay, e := empty.ReconcileSCIMProjection(ctx, "Empty"); e != nil || replay != (scim.ProjectionReplay{ProvisioningDomainID: "Empty"}) {
				t.Fatal("an empty domain replay reported users or batches", replay, e)
			}
			configured, e := empty.EnableSCIMProjection(ctx, "Tenant", policy)
			must(e)
			host, e := auth.New(auth.Options{BaseURL: "https://directory.example.test", BasePath: "/identity/custom", Secret: strings.Repeat("a", 32), Store: configured})
			must(e)
			h, e := scim.New(host, scim.Options{Store: configured, Connections: []scim.Connection{{Directory: scim.Directory{ID: "ACME", ProvisioningDomainID: "Tenant"}, Credentials: []scim.Credential{{ID: "owned", Token: "writer"}}}}})
			must(e)
			for _, name := range []string{"one@example.test", "two@example.test"} {
				if w := scimRequest(h, "POST", "Users", "writer", map[string]any{"schemas": []string{scim.UserSchema}, "userName": name}); w.Code != 201 {
					t.Fatal("provisioning failed", w.Code, w.Body.String())
				}
			}
			calls = 0
			replay, e := configured.ReconcileSCIMProjection(ctx, "Tenant")
			if e != nil || replay != (scim.ProjectionReplay{ProvisioningDomainID: "Tenant", ReconciledUsers: 2, Batches: 1}) {
				t.Fatal("a domain replay did not report its two users in one batch", replay, e)
			}
			if calls != 2 {
				t.Fatal("the replay did not reconcile each user once", calls)
			}
		})
	}
}
