package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

func TestTeamCountResolver(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			base, peer, owner, admin, group := invitationWriterFixture(t, dialect)
			service := func(store *Store, resolve func(context.Context, org.TeamLimitInput) (int, error)) *org.Service {
				t.Helper()
				s, err := org.NewService(org.Options{Store: store, Teams: &org.TeamOptions{ResolveMaximumTeams: resolve}})
				if err != nil {
					t.Fatal(err)
				}
				return s
			}
			entered := make(chan bool, 2)
			proceed := make(chan struct{})
			var calls atomic.Int32
			resolve := func(ctx context.Context, in org.TeamLimitInput) (int, error) {
				calls.Add(1)
				if in.OrganizationID != group.ID {
					return 0, errors.New("wrong organization")
				}
				if in.Session != nil && (in.Session.User.ID != owner.UserID || in.Session.Session.ID != owner.ID || in.Session.Session.Token != owner.Token || in.Session.User.Email == "" || in.Request == nil || in.Request.Method != http.MethodPost) {
					return 0, errors.New("incorrect actor or request")
				}
				if in.Session == nil && in.Request != nil {
					return 0, errors.New("unexpected trusted request")
				}
				entered <- in.Session != nil
				select {
				case <-proceed:
					return 1, nil
				case <-ctx.Done():
					return 0, ctx.Err()
				}
			}
			first, second := service(base, resolve), service(peer, resolve)
			sdk := organizationRoleClient(t, base, first, owner)
			done := make(chan error, 2)
			go func() { _, err := sdk.CreateTeam(ctx, "From HTTP", ""); done <- err }()
			go func() {
				_, err := second.CreateTeam(ctx, org.CreateTeamRequest{OrganizationID: group.ID, Name: "From host"})
				done <- err
			}()
			var actors []bool
			for range 2 {
				select {
				case a := <-entered:
					actors = append(actors, a)
				case err := <-done:
					t.Fatalf("creation stopped before quota callback: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			close(proceed)
			if actors[0] == actors[1] {
				t.Fatal("missing authenticated or trusted callback", actors)
			}
			success, denied := 0, 0
			for range 2 {
				err := <-done
				var problem *auth.APIError
				switch {
				case err == nil:
					success++
				case errors.As(err, &problem) && problem.Code == org.ErrTeamLimit.Code:
					denied++
				default:
					t.Fatal(err)
				}
			}
			if success != 1 || denied != 1 || calls.Load() != 2 {
				t.Fatal("a concurrent HTTP and trusted creation did not reserve exactly one slot", success, denied, calls.Load())
			}
			teams, err := sdk.ListOrganizationTeams(ctx, group.ID)
			if err != nil || len(teams) != 1 {
				t.Fatal("unexpected persisted team count", teams, err)
			}
			if _, err = second.CreateTeam(ctx, org.CreateTeamRequest{Name: "no destination"}); !errors.Is(err, org.ErrNoActiveOrg) {
				t.Fatal("trusted caller had an implicit organization", err)
			}
			request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.test/create-team", nil)
			_, err = second.Store().(org.TeamCreationStore).CreateOrganizationTeam(ctx, nil, org.CreateTeamRequest{OrganizationID: group.ID}, request)
			if !errors.Is(err, org.ErrUnauthenticated) {
				t.Fatal("HTTP creation had no actor", err)
			}
			hostErr := errors.New("plan provider unavailable")
			noPlan := service(base, func(context.Context, org.TeamLimitInput) (int, error) { return 0, hostErr })
			if _, err := noPlan.CreateTeam(ctx, org.CreateTeamRequest{OrganizationID: group.ID, Name: "no policy"}); !errors.Is(err, hostErr) {
				t.Fatal("lost resolver failure", err)
			}
			invalid := service(base, func(context.Context, org.TeamLimitInput) (int, error) { return -1, nil })
			if _, err := invalid.CreateTeam(ctx, org.CreateTeamRequest{OrganizationID: group.ID, Name: "invalid limit"}); err == nil {
				t.Fatal("accepted a negative resolved team limit")
			}
			if _, err := base.WithOrganizationTeams(org.TeamOptions{MaximumTeams: 3, ResolveMaximumTeams: resolve}); err == nil {
				t.Fatal("accepted conflicting team limits")
			}
			control := func(q string, args ...any) error {
				_, err := peer.db.ExecContext(ctx, peer.bind(q), args...)
				return err
			}
			for _, tc := range []struct {
				name   string
				want   error
				change func() error
			}{
				{"profile", org.ErrTeamLimitChanged, func() error { return control(`UPDATE "user" SET "name"=? WHERE "id"=?`, "changed", owner.UserID) }},
				{"selection", org.ErrNoActiveOrg, func() error {
					return control(`UPDATE "session" SET "activeOrganizationId"=NULL WHERE "id"=?`, owner.ID)
				}},
				{"demotion", org.ErrTeamCreate, func() error {
					return control(`UPDATE "member" SET "role"='member' WHERE "organizationId"=? AND "userId"=?`, group.ID, owner.UserID)
				}},
				{"revocation", org.ErrUnauthenticated, func() error { return control(`DELETE FROM "session" WHERE "id"=?`, admin.ID) }},
			} {
				t.Run(tc.name, func(t *testing.T) {
					actor := org.TeamActor{UserID: owner.UserID, SessionID: owner.ID}
					explicit := group.ID
					if tc.name == "selection" {
						explicit = ""
					}
					if tc.name == "revocation" {
						actor = org.TeamActor{UserID: admin.UserID, SessionID: admin.ID}
					}
					var resolved int
					s := service(base, func(context.Context, org.TeamLimitInput) (int, error) { resolved++; return 10, tc.change() })
					_, err := s.Store().(org.TeamStore).CreateTeam(ctx, actor, explicit, tc.name)
					if !errors.Is(err, tc.want) || resolved != 1 {
						t.Fatal("wrote using obsolete team quota inputs", tc.name, err, resolved)
					}
				})
			}
			blocked := service(base, func(context.Context, org.TeamLimitInput) (int, error) {
				return 0, errors.New("forbidden resolver reached")
			})
			_, err = blocked.Store().(org.TeamStore).CreateTeam(ctx, org.TeamActor{UserID: owner.UserID, SessionID: owner.ID}, group.ID, "denied")
			if !errors.Is(err, org.ErrTeamCreate) {
				t.Fatal("unauthorized caller evaluated policy", err)
			}
			var count int
			if err := base.db.QueryRowContext(ctx, base.bind(`SELECT COUNT(*) FROM "team" WHERE "organizationId"=?`), group.ID).Scan(&count); err != nil || count != 1 {
				t.Fatal("failed team writes changed capacity", count, err)
			}
		})
	}
}
