package sqlstore

import (
	"errors"
	"fmt"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestFullOrganizationSnapshot(t *testing.T) {
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
			store, err := OpenWithOptions(ctx, dialect, dsn, []string{"organization-teams"}, schema.Options{})
			must(err)
			t.Cleanup(func() { store.Close() })
			writer, err := Open(ctx, dialect, dsn)
			must(err)
			t.Cleanup(func() { writer.Close() })
			now := time.Now().UTC().Truncate(time.Millisecond)
			exec := func(q string, args ...any) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(q), args...)
				must(err)
			}
			host := auth.User{ID: "Actor", Name: "Example", Email: "actor@example.test", CreatedAt: now, UpdatedAt: now}
			must(store.CreateUser(ctx, host, "", &auth.StoredSession{Session: auth.Session{ID: "actorSession", Token: "actorCookie", UserID: host.ID, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}))
			group := org.Organization{ID: "Group", Name: "Studio", Slug: "studio", Metadata: []byte(`{"region":"west"}`), CreatedAt: now}
			membership := org.Member{ID: "z-host", OrganizationID: group.ID, UserID: host.ID, Role: "member, owner", CreatedAt: now}
			must(store.CreateOrganization(ctx, group, membership, "actorSession", false))
			tx, err := store.db.BeginTx(ctx, nil)
			must(err)
			defer tx.Rollback()
			for i := 0; i < 105; i++ {
				id := fmt.Sprintf("p%03d", i)
				u := auth.User{ID: id, Email: id + "@example.test", Name: id, CreatedAt: now, UpdatedAt: now}
				q, args := store.userInsert(u, nil)
				_, err := tx.ExecContext(ctx, store.bind(q), args...)
				must(err)
				_, err = tx.ExecContext(ctx, store.bind(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,?,?,'member',?)`), id, group.ID, id, store.date(now))
				must(err)
			}
			must(tx.Commit())
			exec(`INSERT INTO "invitation" ("id","organizationId","inviterId","email","role","status","expiresAt","createdAt") VALUES ('grant','Group','Actor','invitee@example.test','member, owner','pending',?,?)`, store.date(now.Add(time.Hour)), store.date(now))
			read := func(limit int) *org.FullOrganization {
				t.Helper()
				got, err := store.FullOrganization(ctx, "actorSession", host.ID, org.FullOrganizationQuery{MembersLimit: limit}, true)
				must(err)
				if got == nil {
					t.Fatal("no active organization")
				}
				return got
			}
			defaultPage := read(0)
			if len(defaultPage.Members) != 100 || defaultPage.Teams == nil || len(defaultPage.Invitations) != 1 {
				t.Fatal("incorrect defaults, invitations or empty teams")
			}
			page := read(110)
			if len(page.Members) != 106 || page.Members[105].User.ID != host.ID {
				t.Fatal("failed to hydrate a member page beyond the default limit")
			}
			scoped, err := store.WithMembershipLimit(org.MembershipLimit{Maximum: 12})
			must(err)
			short, err := scoped.FullOrganization(ctx, "actorSession", host.ID, org.FullOrganizationQuery{}, false)
			must(err)
			if len(short.Members) != 12 || short.Teams != nil || short.Members[0].UserID == host.ID {
				t.Fatal("membership authorization depended on appearing on the requested page")
			}
			// The caller can see an owner invitation only while holding that role.
			done := make(chan error, 1)
			go func() {
				for i := 0; i < 50; i++ {
					role := "member, owner"
					if i%2 == 0 {
						role = "member, admin"
					}
					if _, err := writer.db.ExecContext(ctx, writer.bind(`UPDATE "member" SET "role"=? WHERE "id"='z-host'`), role); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			for range 50 {
				got := read(106)
				holdsOwner := membershipHasRole(got.Members[105].Role, "owner")
				if holdsOwner != (len(got.Invitations) == 1) {
					t.Fatal("invitation visibility and caller role came from different snapshots")
				}
			}
			must(<-done)
			for _, mismatch := range []org.FullOrganizationQuery{{OrganizationID: "group"}, {OrganizationSlug: "STUDIO"}} {
				got, err := store.FullOrganization(ctx, "actorSession", host.ID, mismatch, true)
				if got != nil || !errors.Is(err, org.ErrNotFound) {
					t.Fatal("inexact organization selector resolved", err)
				}
			}
			got, err := store.FullOrganization(ctx, "actorsession", host.ID, org.FullOrganizationQuery{}, true)
			if got != nil || !errors.Is(err, org.ErrUnauthenticated) {
				t.Fatal("inexact session read a directory", err)
			}
			// Simulate a switch or re-grant after a denied read observed its original selection.
			must(store.clearDeniedSelection(ctx, "actorSession", host.ID, "formerly-active", "foreign"))
			must(store.clearDeniedSelection(ctx, "actorSession", host.ID, group.ID, group.ID))
			if read(1).ID != group.ID {
				t.Fatal("delayed denial erased a newer selection or membership")
			}
			exec(`UPDATE "session" SET "activeTeamId"='stale-team' WHERE "id"='actorSession'`)
			exec(`DELETE FROM "member" WHERE "id"='z-host'`)
			got, err = store.FullOrganization(ctx, "actorSession", host.ID, org.FullOrganizationQuery{}, false)
			if got != nil || !errors.Is(err, org.ErrNotMember) {
				t.Fatal("returned data for a removed member", err)
			}
			var orgID, teamID *string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "activeOrganizationId","activeTeamId" FROM "session" WHERE "id"='actorSession'`)).Scan(&orgID, &teamID))
			if orgID != nil || teamID != nil {
				t.Fatal("denial did not clear both session selections")
			}
		})
	}
}
