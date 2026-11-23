package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

// PrepareTeamCreation runs the creation checks without writing: the caller's
// team.create permission and a fixed team limit. A resolved limit is decided
// when the team is written.
func (s *Store) PrepareTeamCreation(ctx context.Context, actor *org.TeamActor, input org.CreateTeamRequest, request *http.Request) (org.TeamChange, error) {
	var scope org.TeamChange
	if actor == nil && (request != nil || input.OrganizationID == "") {
		if request != nil {
			return scope, org.ErrUnauthenticated
		}
		return scope, org.ErrNoActiveOrg
	}
	err := s.withTeamTransaction(ctx, actor, "", func(t teamTransaction) error {
		id := input.OrganizationID
		var err error
		if actor == nil {
			err = t.lockOrganization(ctx, t.tx, id)
		} else {
			id, err = t.authorizeOrg(id, "team", "create", org.ErrInviteDenied, org.ErrTeamCreate)
		}
		if err != nil {
			return err
		}
		if maximum := s.teamOptions.MaximumTeams; maximum > 0 {
			var count int
			if err := t.tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "team" WHERE "organizationId"=`+s.exactSQLValue("?")), id).Scan(&count); err != nil {
				return err
			}
			if count >= maximum {
				return org.ErrTeamLimit
			}
		}
		scope, err = t.teamScope(id, org.Team{Name: input.Name, OrganizationID: id})
		return err
	})
	return scope, err
}

// PrepareTeamUpdate checks the caller's team.update permission and returns the
// current team without writing.
func (s *Store) PrepareTeamUpdate(ctx context.Context, actor org.TeamActor, explicit, id string, _ *string) (org.TeamChange, error) {
	var scope org.TeamChange
	err := s.withTeamActor(ctx, actor, "", func(t teamTransaction) error {
		group, err := t.authorizeOrg(explicit, "team", "update", org.ErrTeamUpdate, org.ErrTeamUpdate)
		if err != nil {
			return err
		}
		team, err := s.findTeam(ctx, t.tx, group, id)
		if err != nil {
			return err
		}
		scope, err = t.teamScope(group, *team)
		return err
	})
	return scope, err
}

// PrepareTeamRemoval runs every removal check without writing: the caller's
// team.delete permission, the active-team rule and the final-team rule.
func (s *Store) PrepareTeamRemoval(ctx context.Context, actor org.TeamActor, explicit, id string) (org.TeamChange, error) {
	var scope org.TeamChange
	err := s.withTeamActor(ctx, actor, "", func(t teamTransaction) error {
		group, err := t.authorizeOrg(explicit, "team", "delete", org.ErrTeamDeleteActive, org.ErrTeamDelete)
		if err != nil {
			return err
		}
		if t.activeTeam == id {
			return org.ErrTeamDeleteActive
		}
		team, err := s.findTeam(ctx, t.tx, group, id)
		if err != nil {
			return err
		}
		if !s.teamOptions.AllowRemovingAllTeams {
			var count int
			if err = t.tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "team" WHERE "organizationId"=?`), group).Scan(&count); err != nil {
				return err
			}
			if count <= 1 {
				return org.ErrTeamLast
			}
		}
		scope, err = t.teamScope(group, *team)
		return err
	})
	return scope, err
}

// teamScope reads the organization and, for a signed-in caller, their account.
func (t teamTransaction) teamScope(group string, team org.Team) (org.TeamChange, error) {
	scope := org.TeamChange{Team: team}
	row, err := readOrg(t.tx.QueryRowContext(t.ctx, t.bind(`SELECT `+orgFields+` FROM "organization" o WHERE o."id"=`+t.exactSQLValue("?")), group))
	if err != nil {
		return scope, err
	}
	scope.Organization = *row
	if t.actor.SessionID != "" {
		session, err := t.sessionResult(t.ctx, t.tx, t.actor.SessionID, t.actor.UserID)
		if err != nil {
			return scope, err
		}
		scope.User = &session.User
	}
	return scope, nil
}

// PrepareTeamMemberAddition checks the caller's member.update permission and
// that the user belongs to the organization, without writing. It returns the
// existing membership when the user is already on the team.
func (s *Store) PrepareTeamMemberAddition(ctx context.Context, actor org.TeamActor, explicit, id, user string) (org.TeamMembershipChange, error) {
	var change org.TeamMembershipChange
	err := s.withTeamActor(ctx, actor, user, func(t teamTransaction) error {
		group, err := t.authorizeMemberChange(explicit, id, user, "update", org.ErrTeamAdd)
		if err != nil {
			return err
		}
		member := org.TeamMember{TeamID: id, UserID: user}
		if existing, err := s.readTeamMember(ctx, t.tx, id, user); err == nil {
			member = *existing
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		change, err = t.membershipScope(group, id, member)
		return err
	})
	return change, err
}

// PrepareTeamMemberRemoval checks the caller's member.delete permission and
// that the user is on the team, without writing.
func (s *Store) PrepareTeamMemberRemoval(ctx context.Context, actor org.TeamActor, explicit, id, user string) (org.TeamMembershipChange, error) {
	var change org.TeamMembershipChange
	err := s.withTeamActor(ctx, actor, user, func(t teamTransaction) error {
		group, err := t.authorizeMemberChange(explicit, id, user, "delete", org.ErrTeamRemove)
		if err != nil {
			return err
		}
		existing, err := s.readTeamMember(ctx, t.tx, id, user)
		if errors.Is(err, sql.ErrNoRows) {
			return org.ErrTeamMember
		} else if err != nil {
			return err
		}
		change, err = t.membershipScope(group, id, *existing)
		return err
	})
	return change, err
}

// membershipScope reads the team, its organization and the member's account.
func (t teamTransaction) membershipScope(group, id string, member org.TeamMember) (org.TeamMembershipChange, error) {
	change := org.TeamMembershipChange{Member: member}
	team, err := t.findTeam(t.ctx, t.tx, group, id)
	if err != nil {
		return change, err
	}
	scope, err := t.teamScope(group, *team)
	if err != nil {
		return change, err
	}
	change.Team, change.Organization = scope.Team, scope.Organization
	q := `SELECT ` + userColumns + ` FROM "user" u WHERE u."id"=` + t.exactSQLValue("?")
	err = t.tx.QueryRowContext(t.ctx, t.bind(q), member.UserID).Scan(userFields(&change.User)...)
	return change, err
}
