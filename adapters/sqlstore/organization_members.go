package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

// ActiveOrganizationMember reads the current selection and role in a single
// snapshot, including when another request switches organizations or removes a member.
func (s *Store) ActiveOrganizationMember(ctx context.Context, sessionID, userID string) (*org.ActiveMember, error) {
	exact := s.exactSQLValue
	query := `SELECT ss."activeOrganizationId", m."id", m."role", m."createdAt", u."id", u."name", u."email", u."image"
		FROM "session" ss
		JOIN "user" u ON u."id"=` + exact(`ss."userId"`) + `
		LEFT JOIN "member" m ON m."userId"=` + exact(`ss."userId"`) + ` AND m."organizationId"=` + exact(`ss."activeOrganizationId"`) + `
		WHERE ss."id"=` + exact("?") + ` AND ss."userId"=` + exact("?") + ` AND ss."expiresAt">?`
	var active, memberID, role sql.NullString
	var created sql.NullTime
	var profile org.MemberUser
	err := s.db.QueryRowContext(ctx, s.bind(query), sessionID, userID, s.date(time.Now())).Scan(
		&active, &memberID, &role, &created, &profile.ID, &profile.Name, &profile.Email, &profile.Image)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, org.ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	if active.String == "" {
		return nil, org.ErrNoActiveOrg
	}
	if !memberID.Valid {
		return nil, org.ErrMemberMissing
	}
	return &org.ActiveMember{
		Member: org.Member{ID: memberID.String, OrganizationID: active.String, UserID: profile.ID, Role: role.String, CreatedAt: created.Time},
		User:   profile,
	}, nil
}

// OrganizationMemberRole resolves the requested tenant and both memberships in
// one statement so concurrent membership or session changes cannot cross tenants.
func (s *Store) OrganizationMemberRole(ctx context.Context, sessionID, actorID string, query org.MemberRoleQuery) (string, error) {
	exact := s.exactSQLValue
	scope := `ss."activeOrganizationId"`
	var args []any
	switch {
	case query.OrganizationSlug != "":
		scope = `(SELECT "id" FROM "organization" WHERE "slug"=` + exact("?") + `)`
		args = append(args, query.OrganizationSlug)
	case query.OrganizationID != "":
		scope = "?"
		args = append(args, query.OrganizationID)
	}
	target := query.UserID
	if target == "" {
		target = actorID
	}
	statement := `SELECT selection.org_id, member_role."role"
		FROM (SELECT ` + scope + ` AS org_id, ss."userId" AS caller
		      FROM "session" ss WHERE ss."id"=` + exact("?") + ` AND ss."userId"=` + exact("?") + ` AND ss."expiresAt">?) selection
		LEFT JOIN "member" actor ON actor."organizationId"=` + exact("selection.org_id") + ` AND actor."userId"=` + exact("selection.caller") + `
		LEFT JOIN "member" member_role ON member_role."organizationId"=` + exact(`actor."organizationId"`) + ` AND member_role."userId"=` + exact("?")
	args = append(args, sessionID, actorID, s.date(time.Now()), target)
	var organization, role sql.NullString
	err := s.db.QueryRowContext(ctx, s.bind(statement), args...).Scan(&organization, &role)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", org.ErrUnauthenticated
	case err != nil:
		return "", err
	case organization.String == "" && query.OrganizationSlug != "":
		return "", org.ErrNotFound
	case organization.String == "":
		return "", org.ErrNoActiveOrg
	case !role.Valid:
		return "", org.ErrRoleReadDenied
	default:
		return role.String, nil
	}
}

// AddOrganizationMember adds an existing account from trusted application code.
func (s *Store) AddOrganizationMember(ctx context.Context, m org.Member, teamID string) error {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var userID string
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id" FROM "user" WHERE "id"=?`), m.UserID).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && userID != m.UserID {
		return &auth.APIError{Status: 400, Code: "USER_NOT_FOUND", Message: "User not found"}
	}
	if err != nil {
		return err
	}
	if err = s.lockOrganization(ctx, tx, m.OrganizationID); err != nil {
		return err
	}
	if err = s.checkNewMember(ctx, tx, m.OrganizationID, m.UserID); err != nil {
		return err
	}
	if teamID != "" {
		if s.teamOptions == nil {
			return org.ErrTeamNotFound
		}
		team, err := s.findTeam(ctx, tx, m.OrganizationID, teamID)
		if err != nil {
			return err
		}
		if team.ID != teamID || team.OrganizationID != m.OrganizationID {
			return org.ErrTeamNotFound
		}
		if _, err = s.insertTeamMember(ctx, tx, team.ID, m.UserID, true); err != nil {
			return err
		}
	}
	if err = s.addMember(ctx, tx, m); err != nil {
		return err
	}
	return tx.Commit()
}

// A waiting writer must see changes committed by the previous lock holder,
// even after it read an invitation to determine which organization to lock.
func (s *Store) beginMembershipChange(ctx context.Context) (*sql.Tx, error) {
	if s.dialect == "sqlite" {
		return s.db.BeginTx(ctx, nil)
	}
	return s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
}

// The caller holds the organization lock through insertion.
func (s *Store) checkNewMember(ctx context.Context, tx *sql.Tx, organizationID, userID string) error {
	var count, existing int
	err := tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*),COALESCE(SUM(CASE WHEN "userId"=? THEN 1 ELSE 0 END),0) FROM "member" WHERE "organizationId"=?`), userID, organizationID).Scan(&count, &existing)
	if err != nil {
		return err
	}
	if existing != 0 {
		return org.ErrAlreadyMember
	}
	if count >= 100 {
		return org.ErrMemberLimit
	}
	return nil
}
