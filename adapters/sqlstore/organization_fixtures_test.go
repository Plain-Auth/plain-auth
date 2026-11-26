package sqlstore

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/authtest"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestOrganizationFixtureLifecycle(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			ddl, e := schema.Generate(dialect, []string{"organization-teams", "stripe-organization", "api-key", "sso"})
			must(e)
			dsn := organizationTestDSN(t, dialect)
			store, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			t.Cleanup(func() { store.Close() })
			peer, e := Open(ctx, dialect, dsn)
			must(e)
			t.Cleanup(func() { peer.Close() })
			exec := func(q string, args ...any) {
				t.Helper()
				_, e := store.db.ExecContext(ctx, store.bind(q), args...)
				must(e)
			}
			count := func(expected int, q string, args ...any) {
				t.Helper()
				var n int
				must(peer.db.QueryRowContext(ctx, peer.bind(q), args...).Scan(&n))
				if n != expected {
					t.Fatalf("%s: got %d, want %d", q, n, expected)
				}
			}
			opts := auth.Options{Secret: strings.Repeat("t", 40), BaseURL: "https://fixture.example.test", Store: store}
			limit := 1
			withTeams, e := authtest.NewWithOrganizations(opts, org.Options{Teams: &org.TeamOptions{MaximumMembersPerTeam: &limit}})
			must(e)
			opts.Store = peer
			plain, e := authtest.NewWithOrganizations(opts, org.Options{})
			must(e)
			now := time.Now().UTC().Truncate(time.Millisecond)
			testOrg := authtest.NewOrganization("Support")
			testOrg.ID = "FixtureOrg"
			testOrg.Slug = "support"
			logo := "/logo.svg"
			testOrg.Logo = &logo
			testOrg.Metadata = json.RawMessage(`{"tier":"internal"}`)
			saved, e := plain.SaveOrganization(ctx, testOrg)
			must(e)
			if saved.ID != testOrg.ID || saved.Name != testOrg.Name || saved.Slug != "support" || saved.Logo == nil || *saved.Logo != logo || string(saved.Metadata) != string(testOrg.Metadata) || !saved.CreatedAt.Equal(testOrg.CreatedAt) {
				t.Fatal("supplied organization fields were not round-tripped", saved)
			}
			for _, tab := range []string{"team", "member", "session"} {
				count(0, `SELECT COUNT(*) FROM "`+tab+`"`)
			}
			for _, duplicate := range []org.Organization{testOrg, {ID: "different", Name: "slug conflict", Slug: "support", CreatedAt: now}} {
				if _, e := withTeams.SaveOrganization(ctx, duplicate); !errors.Is(e, org.ErrDuplicate) {
					t.Fatal("duplicate fixture overwrote a saved organization", e)
				}
			}
			neighbor, e := plain.SaveOrganization(ctx, authtest.NewOrganization("Neighbor"))
			must(e)
			user := authtest.NewUser()
			user.ID = saved.ID
			u, e := plain.SaveUser(ctx, user)
			must(e)
			second, e := plain.SaveUser(ctx, authtest.NewUser())
			must(e)
			member, e := plain.AddMember(ctx, org.AddMemberRequest{UserID: u.ID, OrganizationID: saved.ID})
			must(e)
			if member.Role != "member" || member.ID == "" || member.UserID != u.ID || member.OrganizationID != saved.ID || member.CreatedAt.IsZero() {
				t.Fatal("default member fixture", member)
			}
			labeled, e := plain.AddMember(ctx, org.AddMemberRequest{UserID: u.ID, OrganizationID: neighbor.ID, Roles: []string{"newsroom", "owner"}})
			must(e)
			if labeled.Role != "newsroom,owner" {
				t.Fatal("fixture lost application role labels", labeled.Role)
			}
			for _, tc := range []struct{ id, team string }{{saved.ID, "team-target"}, {neighbor.ID, "team-keep"}} {
				exec(`INSERT INTO "team" ("id","name","memberCount","organizationId","createdAt") VALUES (?,?,0,?,?)`, tc.team, tc.team, tc.id, store.date(now))
				m, e := withTeams.AddMember(ctx, org.AddMemberRequest{UserID: second.ID, OrganizationID: tc.id, Roles: []string{"admin"}, TeamID: tc.team})
				must(e)
				if m.Role != "admin" {
					t.Fatal("explicit fixture role")
				}
				exec(`INSERT INTO "invitation" ("id","organizationId","email","status","expiresAt","inviterId","createdAt") VALUES (?,?,?,'pending',?,?,?)`, "invite-"+tc.team, tc.id, "invite@example.test", store.date(now.Add(time.Hour)), u.ID, store.date(now))
			}
			extra, e := withTeams.SaveUser(ctx, authtest.NewUser())
			must(e)
			if _, e = withTeams.AddMember(ctx, org.AddMemberRequest{UserID: extra.ID, OrganizationID: saved.ID, TeamID: "team-target"}); !errors.Is(e, org.ErrTeamMemberLimit) {
				t.Fatal("fixture ignored configured team capacity", e)
			}
			count(0, `SELECT count(*) FROM "member" WHERE "userId"=?`, extra.ID)
			must(withTeams.DeleteUser(ctx, extra.ID))
			if dialect == "postgres" {
				tx, e := store.db.BeginTx(ctx, nil)
				must(e)
				var namespace string
				must(tx.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&namespace))
				_, e = tx.ExecContext(ctx, `SET LOCAL search_path TO pg_catalog,"`+strings.ReplaceAll(namespace, `"`, `""`)+`"`)
				must(e)
				present, e := store.organizationBillingColumn(ctx, tx)
				must(e)
				must(tx.Rollback())
				if !present {
					t.Fatal("billing profile hidden by a preceding search-path schema")
				}
			}
			a, e := plain.Login(ctx, u.ID)
			must(e)
			b, e := plain.Login(ctx, u.ID)
			must(e)
			exec(`UPDATE "session" SET "activeOrganizationId"=?,"activeTeamId"='team-target' WHERE "id"=?`, saved.ID, a.Session.ID)
			exec(`UPDATE "session" SET "activeOrganizationId"=?,"activeTeamId"='team-keep' WHERE "id"=?`, neighbor.ID, b.Session.ID)
			for _, tc := range []struct {
				config string
				org    bool
			}{{"org-ns", true}, {"user-ns", false}} {
				must(store.ConfigureKeyReference(ctx, tc.config, tc.org))
			}
			insertKey := func(id, config, ref string) {
				exec(`INSERT INTO "apikey" ("id","configId","referenceId","key","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`, id, config, ref, "digest-"+id, store.date(now), store.date(now))
			}
			insertKey("remove-key", "org-ns", saved.ID)
			insertKey("preserve-key", "user-ns", u.ID)
			insertKey("neighbor-key", "org-ns", neighbor.ID)
			exec(`UPDATE "organization" SET "stripeCustomerId"='cus_org' WHERE "id"=?`, saved.ID)
			exec(`UPDATE "user" SET "stripeCustomerId"='cus_user' WHERE "id"=?`, u.ID)
			insertSub := func(id, ref, customer string) {
				exec(`INSERT INTO "subscription" ("id","plan","referenceId","status","stripeCustomerId") VALUES (?,'test',?,'active',?)`, id, ref, customer)
			}
			insertSub("remove-sub", saved.ID, "cus_org")
			insertSub("preserve-sub", u.ID, "cus_user")
			insertSub("neighbor-sub", neighbor.ID, "cus_neighbor")
			for _, kind := range []string{"stripe-org-checkout:", "stripe-org-sync:", "stripe-org-event:", "stripe-org-return:", seatsDue, seatsIdle, "stripe-event:"} {
				for _, id := range []string{saved.ID, neighbor.ID} {
					rid := stripeRecordID(kind, id)
					exec(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?, 'local',?,?,?)`, rid, kind+id, store.date(now.Add(time.Hour)), store.date(now), store.date(now))
				}
			}
			// Each guard rolls back local deletions and leaves the fixture usable.
			insertSub("unknown-sub", saved.ID, "unclassified")
			if e := plain.DeleteOrganization(ctx, saved.ID); e == nil || !strings.Contains(e.Error(), "subscriptions") {
				t.Fatal("unclassified subscription was claimed", e)
			}
			count(1, `SELECT count(*) FROM "subscription" WHERE "id"='remove-sub'`)
			exec(`DELETE FROM "subscription" WHERE "id"='unknown-sub'`)
			insertKey("unknown-key", "imported", saved.ID)
			if e = plain.DeleteOrganization(ctx, saved.ID); e == nil || !strings.Contains(e.Error(), "API keys") {
				t.Fatal("unclassified credential was claimed", e)
			}
			count(1, `SELECT count(*) FROM "subscription" WHERE "id"='remove-sub'`)
			exec(`DELETE FROM "apikey" WHERE "id"='unknown-key'`)
			exec(`INSERT INTO "ssoProvider" ("id","issuer","userId","providerId","domain","organizationId") VALUES ('directory','issuer',?,'idp','domain.example',?)`, u.ID, saved.ID)
			if e = plain.DeleteOrganization(ctx, saved.ID); e == nil || !strings.Contains(e.Error(), "SSO") {
				t.Fatal("directory became detached from its fixture", e)
			}
			exec(`DELETE FROM "ssoProvider" WHERE "id"='directory'`)
			must(plain.DeleteOrganization(ctx, "fixtureorg"))
			count(2, `SELECT count(*) FROM "organization"`)
			must(plain.DeleteOrganization(ctx, saved.ID))
			must(withTeams.DeleteOrganization(ctx, saved.ID))
			for _, tab := range []string{"member", "invitation", "team"} {
				count(0, `SELECT count(*) FROM "`+tab+`" WHERE "organizationId"=?`, saved.ID)
			}
			count(0, `SELECT count(*) FROM "teamMember" WHERE "teamId"='team-target'`)
			count(1, `SELECT count(*) FROM "teamMember" WHERE "teamId"='team-keep'`)
			count(1, `SELECT count(*) FROM "session" WHERE "id"=? AND "activeOrganizationId" IS NULL AND "activeTeamId" IS NULL`, a.Session.ID)
			count(1, `SELECT count(*) FROM "session" WHERE "id"=? AND "activeOrganizationId"=? AND "activeTeamId"='team-keep'`, b.Session.ID, neighbor.ID)
			count(2, `SELECT count(*) FROM "apikey" WHERE "id" IN ('preserve-key','neighbor-key')`)
			count(2, `SELECT count(*) FROM "apikey"`)
			count(2, `SELECT count(*) FROM "subscription" WHERE "id" IN ('preserve-sub','neighbor-sub')`)
			count(2, `SELECT count(*) FROM "subscription"`)
			for _, kind := range []string{"stripe-org-checkout:", "stripe-org-sync:", "stripe-org-event:", "stripe-org-return:", seatsDue, seatsIdle} {
				count(0, `SELECT count(*) FROM "verification" WHERE "identifier"=?`, kind+saved.ID)
				count(1, `SELECT count(*) FROM "verification" WHERE "identifier"=?`, kind+neighbor.ID)
			}
			count(1, `SELECT count(*) FROM "verification" WHERE "identifier"=?`, "stripe-event:"+u.ID)
			count(2, `SELECT count(*) FROM "member" WHERE "organizationId"=?`, neighbor.ID)
			count(1, `SELECT count(*) FROM "invitation" WHERE "organizationId"=?`, neighbor.ID)
			count(2, `SELECT count(*) FROM "user"`)
			// A grant that races teardown either commits before deletion or observes
			// the removed organization. MySQL cannot rely on its inline reference.
			for range 6 {
				f, e := withTeams.SaveOrganization(ctx, authtest.NewOrganization("parallel"))
				must(e)
				start := make(chan struct{})
				grant, removed := make(chan error, 1), make(chan error, 1)
				go func() {
					<-start
					_, err := withTeams.AddMember(ctx, org.AddMemberRequest{UserID: u.ID, OrganizationID: f.ID})
					grant <- err
				}()
				go func() { <-start; removed <- plain.DeleteOrganization(ctx, f.ID) }()
				close(start)
				must(<-removed)
				if e := <-grant; e != nil && !errors.Is(e, org.ErrNotFound) {
					t.Fatal("unexpected concurrent fixture grant", e)
				}
				count(0, `SELECT count(*) FROM "member" WHERE "organizationId"=?`, f.ID)
			}
			for _, path := range []string{"/test/save-organization", "/test/delete-organization", "/organization/add-member"} {
				w := httptest.NewRecorder()
				plain.Auth.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "https://fixture.example.test/api/auth"+path, nil))
				if w.Code != 404 {
					t.Fatal("test mutation has HTTP endpoint", path, w.Code)
				}
			}
		})
	}
}

func TestOrganizationFixtureConfiguration(t *testing.T) {
	ctx := t.Context()
	ddl, e := schema.Generate("sqlite", []string{"organization"})
	if e != nil {
		t.Fatal(e)
	}
	open := func(name string) *Store {
		db, err := OpenWithSchema(ctx, "sqlite", filepath.Join(t.TempDir(), name+".db"), ddl)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	accountStore, orgStore := open("auth"), open("org")
	opts := auth.Options{BaseURL: "https://fixture.example.test", Secret: strings.Repeat("x", 40), Store: accountStore}
	plain, e := authtest.New(opts)
	if e != nil {
		t.Fatal(e)
	}
	fixture := authtest.NewOrganization("only here")
	if _, e := plain.SaveOrganization(ctx, fixture); e == nil {
		t.Fatal("organization fixture present without setup")
	}
	with, e := authtest.NewWithOrganizations(opts, org.Options{Store: orgStore})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = with.SaveOrganization(ctx, fixture); e != nil {
		t.Fatal(e)
	}
	var n int
	for i, db := range []*Store{accountStore, orgStore} {
		if e = db.db.QueryRow(`SELECT count(*) FROM "organization"`).Scan(&n); e != nil || n != i {
			t.Fatal("organization fixture reached wrong store", n, e)
		}
	}
	separateUser := authtest.NewUser()
	if e = orgStore.SaveFixtureUser(ctx, separateUser); e != nil {
		t.Fatal(e)
	}
	member, e := with.AddMember(ctx, org.AddMemberRequest{UserID: separateUser.ID, OrganizationID: fixture.ID, Roles: []string{""}})
	if e != nil {
		t.Fatal("member grant reached the wrong store", e)
	}
	if member.Role != "member" {
		t.Fatal("empty fixture role did not default to member", member.Role)
	}
	if e = with.DeleteOrganization(ctx, fixture.ID); e != nil {
		t.Fatal(e)
	}
	plugin, e := org.New(org.Options{Store: orgStore})
	if e != nil {
		t.Fatal(e)
	}
	opts.Plugins = []auth.Plugin{plugin}
	if _, e = authtest.NewWithOrganizations(opts, org.Options{Store: orgStore}); e == nil {
		t.Fatal("duplicate organization plugin accepted")
	}
}

// The three login helpers select a supplied organization and team that an
// independent instance reads back over HTTP, and a selection the user cannot
// make, a team without an organization or teams, or an organization on a
// server from New fails without leaving a session.
func TestFixtureSessionSelectsOrganization(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"organization-teams"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			peerStore, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer peerStore.Close()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			opts := auth.Options{Secret: strings.Repeat("o", 40), BaseURL: "https://fixture.example.test", Store: store}
			server, err := authtest.NewWithOrganizations(opts, org.Options{Teams: &org.TeamOptions{}})
			must(err)
			noTeams, err := authtest.NewWithOrganizations(opts, org.Options{})
			must(err)
			plain, err := authtest.New(opts)
			must(err)
			opts.Store = peerStore
			peer, err := authtest.NewWithOrganizations(opts, org.Options{Teams: &org.TeamOptions{}})
			must(err)
			selected, err := server.SaveOrganization(ctx, authtest.NewOrganization("Selected"))
			must(err)
			other, err := server.SaveOrganization(ctx, authtest.NewOrganization("Other"))
			must(err)
			now := time.Now().UTC()
			for _, team := range []string{"team-selected", "team-other"} {
				if _, err := store.db.ExecContext(ctx, store.bind(`INSERT INTO "team" ("id","name","memberCount","organizationId","createdAt") VALUES (?,?,0,?,?)`), team, team, selected.ID, store.date(now)); err != nil {
					t.Fatal(err)
				}
			}
			user, err := server.SaveUser(ctx, authtest.NewUser())
			must(err)
			_, err = server.AddMember(ctx, org.AddMemberRequest{UserID: user.ID, OrganizationID: selected.ID, TeamID: "team-selected"})
			must(err)
			options := authtest.LoginOptions{UserID: user.ID, Fields: map[string]any{"activeOrganizationId": selected.ID, "activeTeamId": "team-selected"}}
			login, err := server.LoginWithOptions(ctx, options)
			if err != nil || login.Session.ActiveOrganizationID == nil || *login.Session.ActiveOrganizationID != selected.ID || login.Session.ActiveTeamID == nil || *login.Session.ActiveTeamID != "team-selected" {
				t.Fatal("login did not select the organization and team", err)
			}
			headers, err := server.GetAuthHeadersWithOptions(ctx, options)
			must(err)
			cookies, err := server.GetCookiesWithOptions(ctx, options, "")
			must(err)
			cookieHeader := http.Header{}
			for _, c := range cookies {
				cookieHeader.Add("Cookie", c.Name+"="+c.Value)
			}
			for _, h := range []http.Header{login.Headers, headers, cookieHeader} {
				r := httptest.NewRequest("GET", "https://fixture.example.test/api/auth/get-session", nil)
				r.Header = h.Clone()
				w := httptest.NewRecorder()
				peer.Auth.ServeHTTP(w, r)
				var read struct {
					Session struct{ ActiveOrganizationID, ActiveTeamID string }
				}
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &read) != nil || read.Session.ActiveOrganizationID != selected.ID || read.Session.ActiveTeamID != "team-selected" {
					t.Fatal("peer did not read the fixture selection", w.Code, w.Body)
				}
			}
			before, err := store.ListSessions(ctx, user.ID)
			must(err)
			for name, tc := range map[string]struct {
				server *authtest.Server
				fields map[string]any
				want   error
			}{
				"another organization": {server, map[string]any{"activeOrganizationId": other.ID}, org.ErrNotMember},
				"another team":         {server, map[string]any{"activeOrganizationId": selected.ID, "activeTeamId": "team-other"}, org.ErrTeamSelect},
				"a team alone":         {server, map[string]any{"activeTeamId": "team-selected"}, nil},
				"no teams":             {noTeams, map[string]any{"activeOrganizationId": selected.ID, "activeTeamId": "team-selected"}, nil},
				"no organizations":     {plain, map[string]any{"activeOrganizationId": selected.ID}, authtest.ErrOrganizationSetup},
				"not a string":         {server, map[string]any{"activeOrganizationId": 7}, nil},
			} {
				_, err := tc.server.LoginWithOptions(ctx, authtest.LoginOptions{UserID: user.ID, Fields: tc.fields})
				if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
					t.Fatal(name, "logged in or failed otherwise:", err)
				}
			}
			after, err := store.ListSessions(ctx, user.ID)
			must(err)
			if len(after) != len(before) {
				t.Fatal("refused selection left a session", len(before), len(after))
			}
			unselected, err := server.LoginWithOptions(ctx, authtest.LoginOptions{UserID: user.ID, Fields: map[string]any{"activeOrganizationId": nil}})
			if err != nil || unselected.Session.ActiveOrganizationID != nil {
				t.Fatal("a nil selection selected an organization", err)
			}
			must(server.DeleteUser(ctx, user.ID))
			must(server.DeleteOrganization(ctx, selected.ID))
			must(server.DeleteOrganization(ctx, other.ID))
		})
	}
}
