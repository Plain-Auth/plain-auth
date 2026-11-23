package sqlstore

import (
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestOrganizationMembershipLockOrder(t *testing.T) {
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
			ddl, err := schema.Generate(dialect, []string{"organization-teams"})
			must(err)
			control, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			t.Cleanup(func() { control.Close() })
			open := func() *Store {
				t.Helper()
				s, err := Open(ctx, dialect, dsn)
				must(err)
				t.Cleanup(func() { s.Close() })
				s.db.SetMaxOpenConns(1)
				w, err := s.WithOrganizationTeams(org.TeamOptions{DisableDefaultTeam: true})
				must(err)
				return w.(*Store)
			}
			first, second, third := open(), open(), open()
			now := time.Now().UTC().Truncate(time.Millisecond)
			account := func(id string) auth.User {
				t.Helper()
				user := auth.User{ID: id, Name: id, Email: strings.ToLower(id) + "@example.test", CreatedAt: now, UpdatedAt: now}
				must(control.CreateUser(ctx, user, "", &auth.StoredSession{Session: auth.Session{ID: id + "-s", Token: id + "-t", UserID: id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}))
				return user
			}
			owner, other, peer := account("Owner"), account("Other"), account("Peer")
			member := func(group, id, user, role string) org.Member {
				return org.Member{ID: id, OrganizationID: group, UserID: user, Role: role, CreatedAt: now}
			}
			group := func(id string) {
				t.Helper()
				must(control.CreateOrganization(ctx, org.Organization{ID: id, Name: id, Slug: strings.ToLower(id), CreatedAt: now}, member(id, id+"-Owner", owner.ID, "owner"), owner.ID+"-s", false))
			}
			group("Opposed")
			must(first.AddOrganizationMember(ctx, member("Opposed", "Opposed-Other", other.ID, "owner"), ""))

			// In PostgreSQL, hold the tenant lock until both removals are waiting.
			// Calling the single-attempt transaction makes any lock cycle visible.
			var release func()
			if dialect == "postgres" {
				var pids [2]int
				for index, node := range []*Store{first, second} {
					must(node.db.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&pids[index]))
				}
				tx, err := control.db.BeginTx(ctx, nil)
				must(err)
				defer tx.Rollback()
				must(control.lockOrganization(ctx, tx, "Opposed"))
				release = func() {
					t.Helper()
					deadline := time.Now().Add(10 * time.Second)
					for {
						var both bool
						must(tx.QueryRowContext(ctx, "SELECT cardinality(pg_blocking_pids($1))>0 AND cardinality(pg_blocking_pids($2))>0", pids[0], pids[1]).Scan(&both))
						if both {
							break
						}
						if time.Now().After(deadline) {
							t.Fatal("opposing removals did not both reach their database locks")
						}
						time.Sleep(5 * time.Millisecond)
					}
					must(tx.Commit())
				}
			}
			removed := make(chan error, 2)
			go func() {
				_, _, err := first.removeMembershipOnce(ctx, owner.ID, "Owner-t", "Opposed", "Opposed-Other", false, false)
				removed <- err
			}()
			go func() {
				_, _, err := second.removeMembershipOnce(ctx, other.ID, "Other-t", "Opposed", "Opposed-Owner", false, false)
				removed <- err
			}()
			if release != nil {
				release()
			}
			a, b := <-removed, <-removed
			if a != nil {
				a, b = b, a
			}
			must(a)
			if !errors.Is(b, org.ErrMemberMissing) {
				t.Fatalf("opposing removals must resolve in one transaction attempt: %v", b)
			}

			group("Sales")
			group("OtherTenant")
			must(first.AddOrganizationMember(ctx, member("OtherTenant", "Other-Peer", peer.ID, "member"), ""))
			team, err := first.CreateTeam(ctx, org.TeamActor{UserID: owner.ID, SessionID: "Owner-s"}, "Sales", "Sales team")
			must(err)
			inv, err := first.InviteOrganizationMember(ctx, org.Invitation{ID: "Inv", OrganizationID: "Sales", InviterID: owner.ID, Email: peer.Email, Role: "member", Status: "pending", TeamID: &team.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, "Owner-s", false)
			must(err)
			type result struct {
				op  string
				err error
			}
			done := make(chan result, 3)
			start := make(chan struct{})
			go func() {
				<-start
				done <- result{"grant", first.AddOrganizationMember(ctx, member("Sales", "Sales-Peer", peer.ID, "member"), team.ID)}
			}()
			go func() {
				<-start
				_, _, err := second.AcceptOrganizationInvitation(ctx, inv.ID, "Peer-s", peer, now, false)
				done <- result{"accept", err}
			}()
			go func() {
				<-start
				_, err := third.RemoveOrganizationMember(ctx, owner.ID, "Owner-t", "Sales", peer.Email)
				done <- result{"remove", err}
			}()
			close(start)
			balance := 0
			wantStatus := "pending"
			for range 3 {
				out := <-done
				if out.op == "remove" {
					if out.err == nil {
						balance--
					} else if !errors.Is(out.err, org.ErrMemberMissing) {
						t.Fatalf("concurrent removal: %v", out.err)
					}
				} else if out.err == nil {
					balance++
					if out.op == "accept" {
						wantStatus = "accepted"
					}
				} else if !errors.Is(out.err, org.ErrAlreadyMember) {
					t.Fatalf("concurrent %s: %v", out.op, out.err)
				}
			}
			var members, seats, measured, elsewhere int
			var status string
			must(control.db.QueryRowContext(ctx, control.bind(`SELECT (SELECT COUNT(*) FROM "member" WHERE "organizationId"=? AND "userId"=?),t."memberCount",(SELECT COUNT(*) FROM "teamMember" WHERE "teamId"=t."id"),(SELECT COUNT(*) FROM "member" WHERE "organizationId"=? AND "userId"=?),(SELECT "status" FROM "invitation" WHERE "id"=?) FROM "team" t WHERE t."id"=?`), "Sales", peer.ID, "OtherTenant", peer.ID, inv.ID, team.ID).Scan(&members, &seats, &measured, &elsewhere, &status))
			if balance < 0 || balance > 1 || members != balance || seats != balance || measured != balance || elsewhere != 1 || status != wantStatus {
				t.Fatalf("committed grant, acceptance and removal disagree: balance=%d members=%d seats=%d measured=%d elsewhere=%d invitation=%s", balance, members, seats, measured, elsewhere, status)
			}

			deletion := make(chan error, 1)
			begin := make(chan struct{})
			go func() {
				<-begin
				deletion <- first.DeleteAccount(ctx, peer.ID, "Peer-t", "", "", now)
			}()
			go func() {
				<-begin
				_, err := second.RemoveOrganizationMember(ctx, owner.ID, "Owner-t", "OtherTenant", "Other-Peer")
				removed <- err
			}()
			close(begin)
			must(<-deletion)
			if err := <-removed; err != nil && !errors.Is(err, org.ErrMemberMissing) {
				t.Fatalf("account deletion raced with removal: %v", err)
			}
			must(control.db.QueryRowContext(ctx, control.bind(`SELECT (SELECT COUNT(*) FROM "member" WHERE "userId"=?),(SELECT COUNT(*) FROM "teamMember" WHERE "userId"=?),(SELECT COUNT(*) FROM "member" WHERE "organizationId"=? AND "role"='owner')`), peer.ID, peer.ID, "Opposed").Scan(&members, &seats, &elsewhere))
			if members != 0 || seats != 0 || elsewhere != 1 {
				t.Fatalf("account deletion and removal left %d memberships, %d team seats, %d owners in the unrelated tenant", members, seats, elsewhere)
			}
		})
	}
}
