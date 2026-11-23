package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

// FullOrganization authorizes the session before loading any child records.
// Membership is checked independently of the requested page of members.
func (s *Store) FullOrganization(ctx context.Context, sessionID, userID string, q org.FullOrganizationQuery, includeTeams bool) (*org.FullOrganization, error) {
	if q.MembersLimit < 0 {
		return nil, memberQueryError("membersLimit")
	}
	tx, err := s.beginReadSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	exact := s.exactSQLValue
	var active sql.NullString
	query := `SELECT "activeOrganizationId" FROM "session" WHERE "id"=` + exact("?") + ` AND "userId"=` + exact("?") + ` AND "expiresAt">?`
	err = tx.QueryRowContext(ctx, s.bind(query), sessionID, userID, s.date(time.Now())).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, org.ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	field, value := `o."id"`, q.OrganizationID
	if q.OrganizationSlug != "" {
		field, value = `o."slug"`, q.OrganizationSlug
	} else if value == "" {
		value = active.String
	}
	if value == "" {
		return nil, nil
	}
	query = `SELECT ` + orgFields + `,m."role" FROM "organization" o
		LEFT JOIN "member" m ON m."organizationId"=` + exact(`o."id"`) + ` AND m."userId"=` + exact("?") + ` WHERE ` + field + `=` + exact("?")
	var role sql.NullString
	group, err := readOrg(tx.QueryRowContext(ctx, s.bind(query), userID, value), &role)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, org.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !role.Valid {
		if err := tx.Rollback(); err != nil {
			return nil, err
		}
		if active.Valid {
			if err := s.clearDeniedSelection(ctx, sessionID, userID, active.String, group.ID); err != nil {
				return nil, err
			}
		}
		return nil, org.ErrNotMember
	}
	limit := q.MembersLimit
	if limit == 0 {
		limit = s.membershipLimit.DefaultPageSize()
	}
	result := &org.FullOrganization{Organization: *group, Invitations: []org.Invitation{}}
	result.Members, err = s.organizationMemberRows(ctx, tx, ` WHERE m."organizationId"=`+exact("?"), `m."createdAt",m."id"`, group.ID, limit, 0)
	if err != nil {
		return nil, err
	}
	if s.organizationRoles.HasAction(role.String, "invitation", "create") {
		owner := membershipHasRole(role.String, s.organizationRoles.CreatorRole())
		result.Invitations, err = s.visibleOrganizationInvitations(ctx, tx, group.ID, owner, includeTeams)
		if err != nil {
			return nil, err
		}
	}
	if includeTeams {
		result.Teams, err = s.listTeamsQuery(ctx, tx, ` WHERE t."organizationId"=`+exact("?"), 100, group.ID)
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// A denied lookup clears this session's observed selection. The conditional
// write preserves a subsequent switch or newly granted target membership.
func (s *Store) clearDeniedSelection(ctx context.Context, session, user, observed, target string) error {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	teams, err := s.organizationTeamField(ctx, tx, "session", "activeTeamId")
	if err != nil {
		return err
	}
	update := `"activeOrganizationId"=NULL`
	if teams {
		update += `,"activeTeamId"=NULL`
	}
	param := s.exactSQLValue("?")
	query := `UPDATE "session" SET ` + update + ` WHERE "id"=` + param + ` AND "userId"=` + param + ` AND "activeOrganizationId"=` + param + ` AND "expiresAt">?
		AND NOT EXISTS(SELECT 1 FROM "member" WHERE "userId"=` + param + ` AND "organizationId"=` + param + `)`
	if _, err = tx.ExecContext(ctx, s.bind(query), session, user, observed, s.date(time.Now()), user, target); err != nil {
		return err
	}
	return tx.Commit()
}
