package sqlstore

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

// Exercise a host-resolved team cap through direct team adds, invitation
// issue, renewal and acceptance, trusted grants, retries and concurrency.
func TestResolvedTeamMemberLimits(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
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
			store, err := OpenWithOptions(ctx, dialect, dsn, []string{"organization-teams"}, schema.Options{})
			must(err)
			t.Cleanup(func() { store.Close() })
			peer, err := Open(ctx, dialect, dsn)
			must(err)
			t.Cleanup(func() { peer.Close() })
			count := func(q string, args ...any) int {
				t.Helper()
				var n int
				must(store.db.QueryRowContext(ctx, store.bind(q), args...).Scan(&n))
				return n
			}
			now := time.Now().UTC().Truncate(time.Millisecond)
			account := func(id string) auth.Session {
				t.Helper()
				user := auth.User{ID: id, Name: id, Email: id + "@example.test", CreatedAt: now, UpdatedAt: now}
				session := auth.StoredSession{Session: auth.Session{ID: id + "-s", Token: id + "-t", UserID: id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
				must(store.CreateUser(ctx, user, "", &session))
				return session.Session
			}
			owner, member, direct, invitee, hooked, outsider := account("Owner"), account("Member"), account("Direct"), account("Invitee"), account("Hooked"), account("Outsider")
			group := org.Organization{ID: "Acme", Name: "Acme", Slug: "acme", CreatedAt: now}
			must(store.CreateOrganization(ctx, group, org.Member{ID: "creator", UserID: owner.UserID, OrganizationID: group.ID, Role: "owner", CreatedAt: now}, owner.ID, false))
			for _, s := range []auth.Session{member, direct} {
				must(store.AddOrganizationMember(ctx, org.Member{ID: s.UserID + "-m", UserID: s.UserID, OrganizationID: group.ID, Role: "member", CreatedAt: now}, ""))
			}

			var mu sync.Mutex
			limits := map[string]int{}
			var inputs []org.TeamMemberLimitInput
			setLimit := func(team string, n int) { mu.Lock(); limits[team] = n; mu.Unlock() }
			calls := func() int { mu.Lock(); defer mu.Unlock(); return len(inputs) }
			lastInput := func() org.TeamMemberLimitInput { mu.Lock(); defer mu.Unlock(); return inputs[len(inputs)-1] }
			resolve := func(_ context.Context, in org.TeamMemberLimitInput) (int, error) {
				mu.Lock()
				defer mu.Unlock()
				inputs = append(inputs, in)
				return limits[in.TeamID], nil
			}
			service, err := org.NewService(org.Options{Store: store, Teams: &org.TeamOptions{ResolveMaximumMembersPerTeam: resolve}})
			must(err)
			hookCalls := 0
			observed, err := org.NewService(org.Options{
				Store: store, Teams: &org.TeamOptions{ResolveMaximumMembersPerTeam: resolve},
				BeforeAcceptInvitation: func(context.Context, org.InvitationDecisionEvent) error { hookCalls++; return nil },
			})
			must(err)
			teams := service.Store().(org.TeamStore)
			ownerActor := org.TeamActor{UserID: owner.UserID, SessionID: owner.ID}
			design, err := teams.CreateTeam(ctx, ownerActor, group.ID, "Design")
			must(err)
			support, err := teams.CreateTeam(ctx, ownerActor, group.ID, "Support")
			must(err)
			ownerHTTP := organizationRoleClient(t, store, service, owner)
			expectInput := func(team, user, session string) {
				t.Helper()
				in := lastInput()
				if in.TeamID != team || in.OrganizationID != group.ID || in.Session == nil ||
					in.Session.User.ID != user || in.Session.Session.ID != session || in.Session.User.Email == "" {
					t.Fatalf("unexpected callback input %+v", in)
				}
			}

			// Direct adds ask the host with the manager's session and enforce the answer.
			setLimit(design.ID, 1)
			_, err = ownerHTTP.AddTeamMember(ctx, client.TeamMembershipRequest{OrganizationID: group.ID, TeamID: design.ID, UserID: member.UserID})
			must(err)
			expectInput(design.ID, owner.UserID, owner.ID)
			_, err = ownerHTTP.AddTeamMember(ctx, client.TeamMembershipRequest{OrganizationID: group.ID, TeamID: design.ID, UserID: direct.UserID})
			denied(err, "TEAM_MEMBER_LIMIT_REACHED")
			before := calls()
			_, err = ownerHTTP.AddTeamMember(ctx, client.TeamMembershipRequest{OrganizationID: group.ID, TeamID: design.ID, UserID: member.UserID})
			must(err)
			if calls() != before {
				t.Fatal("an existing team member consulted the host")
			}
			setLimit(support.ID, 0)
			_, err = ownerHTTP.AddTeamMember(ctx, client.TeamMembershipRequest{OrganizationID: group.ID, TeamID: support.ID, UserID: member.UserID})
			denied(err, "TEAM_MEMBER_LIMIT_REACHED")
			if n := count(`SELECT COUNT(*) FROM "teamMember" WHERE "teamId"=?`, support.ID); n != 0 {
				t.Fatal("a zero cap admitted a member", n)
			}

			// A fresh invitation checks every requested team with the inviter's session.
			setLimit(support.ID, 1)
			grant := client.InviteOrganizationMemberRequest{Email: "invitee@example.test", Roles: []string{"member"}, OrganizationID: group.ID, TeamIDs: []string{design.ID, support.ID}}
			_, err = ownerHTTP.InviteOrganizationMember(ctx, grant)
			denied(err, "TEAM_MEMBER_LIMIT_REACHED")
			if n := count(`SELECT COUNT(*) FROM "invitation" WHERE "organizationId"=?`, group.ID); n != 0 {
				t.Fatal("a full team stored an invitation", n)
			}
			setLimit(design.ID, 2)
			before = calls()
			invitation, err := ownerHTTP.InviteOrganizationMember(ctx, grant)
			must(err)
			if calls()-before != 2 {
				t.Fatal("each invited team needs one decision", calls()-before)
			}
			expectInput(support.ID, owner.UserID, owner.ID)

			// Renewing only extends the pending grant and keeps its teams unchecked.
			setLimit(design.ID, 1)
			before = calls()
			grant.Resend = true
			renewed, err := ownerHTTP.InviteOrganizationMember(ctx, grant)
			must(err)
			if renewed.ID != invitation.ID || calls() != before {
				t.Fatal("renewal changed the grant or consulted team caps", renewed.ID, calls()-before)
			}

			// Acceptance asks with the recipient's session and commits all teams or none.
			inviteeHTTP := organizationRoleClient(t, store, service, invitee)
			_, err = inviteeHTTP.AcceptOrganizationInvitation(ctx, invitation.ID)
			denied(err, "TEAM_MEMBER_LIMIT_REACHED")
			if count(`SELECT COUNT(*) FROM "member" WHERE "userId"=?`, invitee.UserID) != 0 ||
				count(`SELECT COUNT(*) FROM "teamMember" WHERE "userId"=?`, invitee.UserID) != 0 ||
				count(`SELECT COUNT(*) FROM "invitation" WHERE "id"=? AND "status"='pending'`, invitation.ID) != 1 {
				t.Fatal("a rejected acceptance left a partial grant")
			}
			setLimit(design.ID, 2)
			accepted, err := inviteeHTTP.AcceptOrganizationInvitation(ctx, invitation.ID)
			must(err)
			expectInput(support.ID, invitee.UserID, invitee.ID)
			if accepted.Member.UserID != invitee.UserID || count(`SELECT COUNT(*) FROM "teamMember" WHERE "userId"=?`, invitee.UserID) != 2 {
				t.Fatal("acceptance did not join both teams", accepted)
			}

			// An observed acceptance settles every team before the host's hook runs once.
			setLimit(design.ID, 3)
			setLimit(support.ID, 2)
			hookedGrant := client.InviteOrganizationMemberRequest{Email: "hooked@example.test", Roles: []string{"member"}, OrganizationID: group.ID, TeamIDs: []string{design.ID, support.ID}}
			hookedInvitation, err := ownerHTTP.InviteOrganizationMember(ctx, hookedGrant)
			must(err)
			before = calls()
			_, err = organizationRoleClient(t, store, observed, hooked).AcceptOrganizationInvitation(ctx, hookedInvitation.ID)
			must(err)
			if hookCalls != 1 || calls()-before != 2 {
				t.Fatal("hook or team decisions repeated", hookCalls, calls()-before)
			}
			expectInput(support.ID, hooked.UserID, hooked.ID)

			// A trusted grant has no session for the host to judge.
			before = calls()
			_, err = service.AddMember(ctx, org.AddMemberRequest{OrganizationID: group.ID, UserID: outsider.UserID, Roles: []string{"member"}, TeamID: support.ID})
			if !errors.Is(err, org.ErrUnauthenticated) || calls() != before {
				t.Fatal("trusted team grant reached the host", err)
			}
			if count(`SELECT COUNT(*) FROM "member" WHERE "userId"=?`, outsider.UserID) != 0 {
				t.Fatal("a rejected team grant kept the organization membership")
			}
			_, err = service.AddMember(ctx, org.AddMemberRequest{OrganizationID: group.ID, UserID: outsider.UserID, Roles: []string{"member"}})
			must(err)

			// A changed session, host errors and invalid answers write nothing.
			setLimit(support.ID, 10)
			changing, err := org.NewService(org.Options{Store: store, Teams: &org.TeamOptions{ResolveMaximumMembersPerTeam: func(context.Context, org.TeamMemberLimitInput) (int, error) {
				_, err := peer.db.ExecContext(ctx, peer.bind(`UPDATE "user" SET "name"=? WHERE "id"=?`), "Renamed", owner.UserID)
				return 10, err
			}}})
			must(err)
			_, err = changing.Store().(org.TeamStore).AddTeamMember(ctx, ownerActor, group.ID, support.ID, direct.UserID)
			if !errors.Is(err, org.ErrTeamLimitChanged) {
				t.Fatal("accepted an obsolete team decision", err)
			}
			hostErr := errors.New("plan service unavailable")
			for _, tc := range []struct {
				name    string
				resolve func(context.Context, org.TeamMemberLimitInput) (int, error)
				want    func(error) bool
			}{
				{"failure", func(context.Context, org.TeamMemberLimitInput) (int, error) { return 0, hostErr }, func(err error) bool { return errors.Is(err, hostErr) }},
				{"negative", func(context.Context, org.TeamMemberLimitInput) (int, error) { return -1, nil }, func(err error) bool { return err != nil }},
			} {
				s, err := org.NewService(org.Options{Store: store, Teams: &org.TeamOptions{ResolveMaximumMembersPerTeam: tc.resolve}})
				must(err)
				_, err = s.Store().(org.TeamStore).AddTeamMember(ctx, ownerActor, group.ID, support.ID, direct.UserID)
				if !tc.want(err) {
					t.Fatal(tc.name, err)
				}
			}
			if count(`SELECT COUNT(*) FROM "teamMember" WHERE "teamId"=? AND "userId"=?`, support.ID, direct.UserID) != 0 {
				t.Fatal("a failed decision added the member")
			}
			one := 1
			if _, err := store.WithOrganizationTeams(org.TeamOptions{MaximumMembersPerTeam: &one, ResolveMaximumMembersPerTeam: resolve}); err == nil {
				t.Fatal("accepted a fixed and a resolved team member limit")
			}

			// Two instances racing for a team's last seat admit exactly one member.
			ops, err := teams.CreateTeam(ctx, ownerActor, group.ID, "Ops")
			must(err)
			entered := make(chan struct{}, 2)
			proceed := make(chan struct{})
			racing := func(db *Store) org.TeamStore {
				s, err := org.NewService(org.Options{Store: db, Teams: &org.TeamOptions{ResolveMaximumMembersPerTeam: func(ctx context.Context, in org.TeamMemberLimitInput) (int, error) {
					entered <- struct{}{}
					select {
					case <-proceed:
						return 1, nil
					case <-ctx.Done():
						return 0, ctx.Err()
					}
				}}})
				must(err)
				return s.Store().(org.TeamStore)
			}
			done := make(chan error, 2)
			for i, racer := range []org.TeamStore{racing(store), racing(peer)} {
				target := []string{member.UserID, direct.UserID}[i]
				go func() { _, err := racer.AddTeamMember(ctx, ownerActor, group.ID, ops.ID, target); done <- err }()
			}
			for range 2 {
				select {
				case <-entered:
				case err := <-done:
					t.Fatalf("an add finished before its decision: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			close(proceed)
			admitted := 0
			for range 2 {
				if err := <-done; err == nil {
					admitted++
				} else {
					denied(err, "TEAM_MEMBER_LIMIT_REACHED")
				}
			}
			if admitted != 1 || count(`SELECT "memberCount" FROM "team" WHERE "id"=?`, ops.ID) != 1 {
				t.Fatal("concurrent adds exceeded the resolved cap", admitted)
			}
		})
	}
}
