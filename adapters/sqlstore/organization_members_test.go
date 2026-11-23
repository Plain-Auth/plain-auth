package sqlstore

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestServerOrganizationMembership(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			denied := func(err error, code string) {
				t.Helper()
				var problem *auth.APIError
				if !errors.As(err, &problem) || problem.Code != code {
					t.Fatalf("want %s, got %v", code, err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"organization-teams"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			defer store.Close()
			other, err := Open(ctx, dialect, dsn)
			must(err)
			defer other.Close()
			seats := 1
			teams := org.TeamOptions{MaximumMembersPerTeam: &seats}
			service, err := org.NewService(org.Options{Store: store, Teams: &teams})
			must(err)
			second, err := org.NewService(org.Options{Store: other, Teams: &teams})
			must(err)
			now := time.Now().UTC().Truncate(time.Millisecond)
			account := func(id string) auth.User {
				t.Helper()
				user := auth.User{ID: id, Name: id, Email: id + "@example.test", CreatedAt: now, UpdatedAt: now}
				session := auth.StoredSession{Session: auth.Session{ID: id + "-s", Token: id + "-t", UserID: id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
				must(store.CreateUser(ctx, user, "", &session))
				return user
			}
			owner, peer, invited, direct := account("Owner"), account("Peer"), account("Invited"), account("Direct")
			group := org.Organization{ID: "Acme", Name: "Acme", Slug: "acme", CreatedAt: now}
			must(store.CreateOrganization(ctx, group, org.Member{ID: "creator", UserID: owner.ID, OrganizationID: group.ID, Role: "owner", CreatedAt: now}, "Owner-s", false))
			configured, err := store.WithOrganizationTeams(teams)
			must(err)
			team, err := configured.CreateTeam(ctx, org.TeamActor{UserID: owner.ID, SessionID: "Owner-s"}, group.ID, "Support")
			must(err)
			req := org.AddMemberRequest{OrganizationID: group.ID, UserID: peer.ID, Roles: []string{"admin, editor", " editor ", "member"}, TeamID: team.ID}
			check := func(bad org.AddMemberRequest, code string) {
				t.Helper()
				_, err := service.AddMember(ctx, bad)
				denied(err, code)
			}
			bad := req
			bad.OrganizationID = strings.ToLower(group.ID)
			check(bad, "ORGANIZATION_NOT_FOUND")
			bad = req
			bad.UserID = strings.ToLower(peer.ID)
			check(bad, "USER_NOT_FOUND")
			bad = req
			bad.TeamID = "unknown-team"
			check(bad, "TEAM_NOT_FOUND")
			bad = req
			bad.Roles = nil
			check(bad, "VALIDATION_ERROR")
			bare, err := org.NewService(org.Options{Store: store})
			must(err)
			_, err = bare.AddMember(ctx, req)
			denied(err, "VALIDATION_ERROR")

			type result struct {
				member *org.Member
				err    error
			}
			results := make(chan result, 2)
			for _, instance := range []*org.Service{service, second} {
				go func() { member, err := instance.AddMember(ctx, req); results <- result{member, err} }()
			}
			a, b := <-results, <-results
			if a.err != nil {
				a, b = b, a
			}
			must(a.err)
			denied(b.err, "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION")
			if a.member.ID == "" || a.member.Role != "admin,editor,editor,member" || a.member.UserID != peer.ID {
				t.Fatalf("incorrect member %+v", a.member)
			}
			var n int
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "memberCount" FROM "team" WHERE "id"=?`), team.ID).Scan(&n))
			if n != 1 {
				t.Fatalf("team seat count %d", n)
			}
			req.UserID = direct.ID
			check(req, "TEAM_MEMBER_LIMIT_REACHED")
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "member" WHERE "userId"=?`), direct.ID).Scan(&n))
			if n != 0 {
				t.Fatal("failed team grant left an organization membership")
			}

			// A trusted grant and an invitation compete for the organization's last seat.
			tx, err := store.db.BeginTx(ctx, nil)
			must(err)
			defer tx.Rollback()
			for i := range 97 {
				id := fmt.Sprintf("existing-%d", i)
				_, err := tx.ExecContext(ctx, store.bind(`INSERT INTO "user" ("id","email","emailVerified","name","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`), id, id+"@example.test", false, id, store.date(now), store.date(now))
				must(err)
				must(store.addMember(ctx, tx, org.Member{ID: id, OrganizationID: group.ID, UserID: id, Role: "member", CreatedAt: now}))
			}
			must(tx.Commit())
			inv, err := store.InviteOrganizationMember(ctx, org.Invitation{ID: "invite", OrganizationID: group.ID, InviterID: owner.ID, Email: invited.Email, Role: "member", Status: "pending", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, "Owner-s", false)
			must(err)
			req.TeamID = ""
			out := make(chan error, 2)
			go func() { _, err := second.AddMember(ctx, req); out <- err }()
			go func() {
				_, _, err := store.AcceptOrganizationInvitation(ctx, inv.ID, "Invited-s", invited, now, false)
				out <- err
			}()
			x, y := <-out, <-out
			if x != nil {
				x, y = y, x
			}
			must(x)
			denied(y, "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED")
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "member" WHERE "organizationId"=?`), group.ID).Scan(&n))
			if n != 100 {
				t.Fatalf("organization admitted %d members", n)
			}
		})
	}
}

func TestTeamMembershipWithEmptyRole(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			base, _, owner, peer, group := invitationWriterFixture(t, dialect)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			svc, err := org.NewService(org.Options{Store: base, Teams: &org.TeamOptions{}})
			must(err)
			store := svc.Store().(org.TeamStore)
			leader := org.TeamActor{UserID: owner.UserID, SessionID: owner.ID}
			target := org.TeamActor{UserID: peer.UserID, SessionID: peer.ID}
			team, err := store.CreateTeam(ctx, leader, group.ID, "News")
			must(err)
			_, err = base.db.ExecContext(ctx, base.bind(`DELETE FROM "member" WHERE "organizationId"=? AND "userId"=?`), group.ID, peer.UserID)
			must(err)
			if _, err = store.AddTeamMember(ctx, leader, group.ID, team.ID, peer.UserID); !errors.Is(err, org.ErrTeamOrgMember) {
				t.Fatalf("nonmember was accepted as a target: %v", err)
			}
			member, err := svc.AddMember(ctx, org.AddMemberRequest{OrganizationID: group.ID, UserID: peer.UserID, Roles: []string{}})
			must(err)
			if member.Role != "" {
				t.Fatalf("unexpected role %q", member.Role)
			}
			_, err = store.AddTeamMember(ctx, leader, group.ID, team.ID, peer.UserID)
			must(err)
			teams, err := store.ListUserTeams(ctx, target, group.ID, "")
			must(err)
			if len(teams) != 1 || teams[0].ID != team.ID {
				t.Fatal("membership with an empty role lost its team")
			}
			_, err = store.CreateTeam(ctx, target, group.ID, "Other")
			if !errors.Is(err, org.ErrTeamCreate) {
				t.Fatalf("member without grants attempted team creation: %v", err)
			}
		})
	}
}
