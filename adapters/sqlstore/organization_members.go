package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	auth "github.com/Stonewrit/stonewrit-auth"
	org "github.com/Stonewrit/stonewrit-auth/plugins/organization"
)

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
