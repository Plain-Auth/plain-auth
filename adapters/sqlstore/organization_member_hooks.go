package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	org "github.com/Plain-Org/plain-auth/plugins/organization"
)

// PrepareMemberAddition checks a trusted grant without writing: the account and
// organization exist, the user is not yet a member, the team belongs to the
// organization and a fixed membership limit has room. AddOrganizationMember
// checks all of them again and resolves host-defined limits.
func (s *Store) PrepareMemberAddition(ctx context.Context, m org.Member, teamID string) (org.MemberCandidate, error) {
	var candidate org.MemberCandidate
	tx, err := s.beginReadSnapshot(ctx)
	if err != nil {
		return candidate, err
	}
	defer tx.Rollback()
	exact := s.exactSQLValue("?")
	err = tx.QueryRowContext(ctx, s.bind(`SELECT `+userColumns+` FROM "user" u WHERE u."id"=`+exact), m.UserID).Scan(userFields(&candidate.User)...)
	if errors.Is(err, sql.ErrNoRows) || err == nil && candidate.User.ID != m.UserID {
		return org.MemberCandidate{}, errUserNotFound
	} else if err != nil {
		return org.MemberCandidate{}, err
	}
	group, err := readOrg(tx.QueryRowContext(ctx, s.bind(`SELECT `+orgFields+` FROM "organization" o WHERE o."id"=`+exact), m.OrganizationID))
	if errors.Is(err, sql.ErrNoRows) || err == nil && group.ID != m.OrganizationID {
		return org.MemberCandidate{}, org.ErrNotFound
	} else if err != nil {
		return org.MemberCandidate{}, err
	}
	candidate.Organization = *group
	var count, existing int
	err = tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*),COALESCE(SUM(CASE WHEN "userId"=? THEN 1 ELSE 0 END),0) FROM "member" WHERE "organizationId"=`+exact), m.UserID, m.OrganizationID).Scan(&count, &existing)
	if err != nil {
		return org.MemberCandidate{}, err
	}
	if existing != 0 {
		return org.MemberCandidate{}, org.ErrAlreadyMember
	}
	if teamID != "" {
		if s.teamOptions == nil {
			return org.MemberCandidate{}, org.ErrTeamNotFound
		}
		team, err := s.findTeam(ctx, tx, m.OrganizationID, teamID)
		if err != nil {
			return org.MemberCandidate{}, err
		}
		if team.ID != teamID || team.OrganizationID != m.OrganizationID {
			return org.MemberCandidate{}, org.ErrTeamNotFound
		}
	}
	if s.membershipLimit.Resolve == nil && count >= s.membershipLimit.DefaultPageSize() {
		return org.MemberCandidate{}, org.ErrMemberLimit
	}
	return candidate, nil
}
