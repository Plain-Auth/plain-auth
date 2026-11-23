package sqlstore

import (
	"database/sql"
	"errors"
	"net/http"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

func checkConcurrentOrganizationSelection(t *testing.T, store *Store, caller, sibling *client.Client, first, second, team string) {
	t.Helper()
	ctx := t.Context()
	selectOrg := func(input *org.OrganizationSelection, want string) {
		t.Helper()
		row, err := caller.SetActiveOrganization(ctx, input)
		if err != nil || (row == nil && want != "") || (row != nil && row.ID != want) {
			t.Fatalf("selected %v, want %q: %v", row, want, err)
		}
	}
	selectOrg(&org.OrganizationSelection{}, "")
	selectOrg(&org.OrganizationSelection{OrganizationSlug: "a-group"}, first)
	if _, err := caller.SetActiveTeam(ctx, &team); err != nil {
		t.Fatal(err)
	}
	selectOrg(&org.OrganizationSelection{OrganizationID: first, OrganizationSlug: "b-group"}, first)
	login, err := caller.GetSession(ctx)
	if err != nil || login == nil || login.Session.ActiveTeamID == nil || *login.Session.ActiveTeamID != team {
		t.Fatal("selecting the same organization lost the team", err)
	}
	missingSlug := &org.OrganizationSelection{OrganizationSlug: "A-GROUP"}
	_, err = caller.SetActiveOrganization(ctx, missingSlug)
	var failure *auth.APIError
	if !errors.As(err, &failure) || failure.Code != org.ErrNotFound.Code {
		t.Fatal("expected an unknown case-sensitive slug", err)
	}
	readStored := func() (sql.NullString, sql.NullString) {
		t.Helper()
		var organizationID, teamID sql.NullString
		query := `SELECT "activeOrganizationId","activeTeamId" FROM "session" WHERE "id"=?`
		if err := store.db.QueryRowContext(ctx, store.bind(query), login.Session.ID).Scan(&organizationID, &teamID); err != nil {
			t.Fatal(err)
		}
		return organizationID, teamID
	}
	if group, activeTeam := readStored(); group.String != first || activeTeam.String != team {
		t.Fatal("unknown slug changed the stored selection", group, activeTeam)
	}
	checkDenial := func(err error) {
		t.Helper()
		var problem *auth.APIError
		if !errors.As(err, &problem) || problem.Status != http.StatusForbidden || problem.Code != org.ErrNotMember.Code {
			t.Fatal("unexpected denial", err)
		}
	}
	unknown := &org.OrganizationSelection{OrganizationID: "missing"}
	_, err = caller.SetActiveOrganization(ctx, unknown)
	checkDenial(err)
	if group, activeTeam := readStored(); group.Valid || activeTeam.Valid {
		t.Fatal("denied switch retained an organization or team in storage")
	}
	for range 4 {
		selectOrg(&org.OrganizationSelection{OrganizationID: first}, first)
		if _, err := caller.SetActiveTeam(ctx, &team); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		allowed, denied := make(chan error, 1), make(chan error, 1)
		go func() {
			<-start
			_, err := caller.SetActiveOrganization(ctx, &org.OrganizationSelection{OrganizationID: second})
			allowed <- err
		}()
		go func() {
			<-start
			_, err := caller.SetActiveOrganization(ctx, unknown)
			denied <- err
		}()
		close(start)
		allowErr, denyErr := <-allowed, <-denied
		if allowErr != nil {
			t.Fatal(allowErr)
		}
		checkDenial(denyErr)
		group, activeTeam := readStored()
		if (group.Valid && group.String != second) || activeTeam.Valid {
			t.Fatal("competing selectors left a mismatched organization and team", group, activeTeam)
		}
	}
	selectOrg(nil, "")
	other, err := sibling.SetActiveOrganization(ctx, &org.OrganizationSelection{})
	if err != nil || other == nil || other.ID != second {
		t.Fatal("switching altered a second login's selection", other, err)
	}
}
