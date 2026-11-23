package sqlstore

import (
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/authtest"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestAtomicInvitationReplacement(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			store, peer, owner, admin, group := invitationWriterFixture(t, dialect)
			teams, err := store.WithOrganizationTeams(org.TeamOptions{})
			must(err)
			base := org.Invitation{ID: "initial", InviterID: owner.UserID, Email: "guest@example.test", Role: "member", OrganizationID: group.ID, Status: "pending", CreatedAt: group.CreatedAt, ExpiresAt: group.CreatedAt.Add(time.Hour)}
			_, err = store.InviteOrganizationMember(ctx, base, owner.ID, false)
			must(err)
			replacement := base
			unknown := "unrelated-team"
			replacement.ID, replacement.TeamID = "bad-team", &unknown
			_, err = teams.(org.InvitationReplacementStore).ReplaceOrganizationInvitation(ctx, replacement, owner.ID)
			if !errors.Is(err, org.ErrTeamNotFound) {
				t.Fatal("invalid replacement granted", err)
			}
			var state string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "status" FROM "invitation" WHERE "id"=?`), base.ID).Scan(&state))
			if state != "pending" {
				t.Fatal("failed replacement consumed the previous invitation")
			}

			start := make(chan struct{})
			done := make(chan error, 2)
			issue := func(s *Store, actor auth.Session, id string) {
				candidate := base
				candidate.ID, candidate.InviterID = id, actor.UserID
				<-start
				_, err := s.ReplaceOrganizationInvitation(ctx, candidate, actor.ID)
				done <- err
			}
			go issue(store, owner, "first")
			go issue(peer, admin, "second")
			close(start)
			firstErr, secondErr := <-done, <-done
			must(firstErr)
			must(secondErr)
			for status, want := range map[string]int{"pending": 1, "canceled": 2} {
				var count int
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "invitation" WHERE "organizationId"=? AND "status"=?`), group.ID, status).Scan(&count))
				if count != want {
					t.Fatalf("competing replacements left %d %s invitations, want %d", count, status, want)
				}
			}
		})
	}
}

func invitationWriterFixture(t *testing.T, dialect string) (*Store, *Store, auth.Session, auth.Session, org.Organization) {
	t.Helper()
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
	peer, err := Open(ctx, dialect, dsn)
	must(err)
	t.Cleanup(func() { peer.Close() })
	app, err := authtest.New(auth.Options{Store: store, BaseURL: "https://org.example.test", Secret: strings.Repeat("s", 40)})
	must(err)
	newSession := func() auth.Session {
		t.Helper()
		user, err := app.SaveUser(ctx, authtest.NewUser())
		must(err)
		login, err := app.Login(ctx, user.ID)
		must(err)
		return login.Session
	}
	owner, admin := newSession(), newSession()
	group := authtest.NewOrganization("studio")
	must(store.CreateOrganization(ctx, group, org.Member{ID: "owner", UserID: owner.UserID, Role: "owner", OrganizationID: group.ID, CreatedAt: group.CreatedAt}, owner.ID, false))
	must(store.AddOrganizationMember(ctx, org.Member{ID: "admin", UserID: admin.UserID, Role: "admin", OrganizationID: group.ID, CreatedAt: group.CreatedAt}, ""))
	return store, peer, owner, admin, group
}
