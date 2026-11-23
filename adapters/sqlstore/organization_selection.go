package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

// SetActiveOrganization applies an explicit ID from a direct store caller.
func (s *Store) SetActiveOrganization(ctx context.Context, sessionID, userID string, id *string) error {
	var q *org.OrganizationSelection
	if id != nil {
		q = &org.OrganizationSelection{OrganizationID: *id}
	}
	_, err := s.selectOrganization(ctx, sessionID, userID, q, false)
	return err
}

// SelectOrganization resolves the target, checks membership and changes only
// this session while holding the account, session and organization locks.
func (s *Store) SelectOrganization(ctx context.Context, sessionID, userID string, selection *org.OrganizationSelection) (*org.Organization, error) {
	return s.selectOrganization(ctx, sessionID, userID, selection, true)
}

func (s *Store) selectOrganization(ctx context.Context, sessionID, userID string, selection *org.OrganizationSelection, sessionSelector bool) (*org.Organization, error) {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = s.organizationActor(ctx, tx, userID, sessionID, time.Now()); err != nil {
		return nil, err
	}
	var group *org.Organization
	var decision error
	if selection != nil {
		group, decision = s.organizationToSelect(ctx, tx, sessionID, userID, *selection, sessionSelector)
		if decision != nil && !(sessionSelector && errors.Is(decision, org.ErrNotMember)) {
			return nil, decision
		}
	}
	var id *string
	if group != nil {
		id = &group.ID
	}
	// On a denied switch, commit the same session-scoped clear as an explicit
	// null. Database and authorization errors from the transaction take priority.
	if err := s.selectOrganizationAndTeam(ctx, tx, sessionID, userID, id, nil); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return group, decision
}

// The account and session are already locked. Resolve the selector against
// their current state and lock the target before reading its membership.
func (s *Store) organizationToSelect(ctx context.Context, tx *sql.Tx, sessionID, userID string, selection org.OrganizationSelection, sessionSelector bool) (*org.Organization, error) {
	exact := s.exactSQLValue("?")
	field, value := `o."id"`, selection.OrganizationID
	bySlug := value == "" && selection.OrganizationSlug != ""
	switch {
	case bySlug:
		field, value = `o."slug"`, selection.OrganizationSlug
	case value == "" && sessionSelector:
		query := `SELECT COALESCE("activeOrganizationId",'') FROM "session" WHERE "id"=` + exact + ` AND "userId"=` + exact
		if err := tx.QueryRowContext(ctx, s.bind(query), sessionID, userID).Scan(&value); err != nil || value == "" {
			return nil, err
		}
	}

	row := `SELECT ` + orgFields + ` FROM "organization" o WHERE ` + field + `=` + exact
	group, err := readOrg(tx.QueryRowContext(ctx, s.readForUpdate(row), value))
	if errors.Is(err, sql.ErrNoRows) {
		if sessionSelector && !bySlug {
			return nil, org.ErrNotMember
		}
		return nil, org.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var member bool
	query := `SELECT EXISTS(SELECT 1 FROM "member" WHERE "organizationId"=` + exact + ` AND "userId"=` + exact + `)`
	if err := tx.QueryRowContext(ctx, s.bind(query), group.ID, userID).Scan(&member); err != nil {
		return nil, err
	}
	if !member {
		return nil, org.ErrNotMember
	}
	return group, nil
}
