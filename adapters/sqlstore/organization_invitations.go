package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

// ListOrganizationInvitations resolves the live session and current role in
// the same snapshot as the invitation rows, without changing the selection.
func (s *Store) ListOrganizationInvitations(ctx context.Context, sessionID, userID, organizationID string, includeTeams bool) ([]org.Invitation, error) {
	tx, err := s.beginReadSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	group, role, err := s.organizationRole(ctx, tx, sessionID, userID, org.MemberRoleQuery{OrganizationID: organizationID})
	switch {
	case errors.Is(err, org.ErrNoActiveOrg):
		return nil, org.ErrInvitationOrganizationRequired
	case errors.Is(err, org.ErrRoleReadDenied):
		return nil, org.ErrInvitationListNonmember
	case err != nil:
		return nil, err
	}
	owner := membershipHasRole(role, "owner")
	if !owner && !membershipHasRole(role, "admin") {
		return nil, org.ErrInvitationListDenied
	}
	items, err := s.visibleOrganizationInvitations(ctx, tx, group, owner, includeTeams)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *Store) visibleOrganizationInvitations(ctx context.Context, tx *sql.Tx, group string, owner, teams bool) ([]org.Invitation, error) {
	query := `SELECT ` + invitationColumns(teams) + ` FROM "invitation" WHERE "organizationId"=` + s.exactSQLValue("?") + ` ORDER BY "createdAt","id" LIMIT 100`
	rows, err := tx.QueryContext(ctx, s.bind(query), group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []org.Invitation{}
	for rows.Next() {
		invite, err := scanInvitation(rows, teams)
		if err != nil {
			return nil, err
		}
		if owner || !membershipHasRole(invite.Role, "owner") {
			out = append(out, invite)
		}
	}
	return out, rows.Err()
}
