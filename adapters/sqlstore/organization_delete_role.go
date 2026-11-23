package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

// DeleteOrganizationRole serializes with membership changes for the same tenant.
func (s *Store) DeleteOrganizationRole(ctx context.Context, userID, token string, query org.RoleQuery) error {
	if !s.dynamicOrganizationRoles {
		return errDynamicRoleStoreDisabled
	}
	var err error
	for range 3 {
		err = s.deleteOrganizationRole(ctx, userID, token, query)
		if !retryIdentity(err) {
			break
		}
	}
	return err
}

func (s *Store) deleteOrganizationRole(ctx context.Context, userID, token string, query org.RoleQuery) error {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	group, err := s.lockMembershipScope(ctx, tx, userID, token, query.OrganizationID)
	if err != nil {
		return err
	}
	member, err := s.lockMembershipActor(ctx, tx, userID, group)
	if errors.Is(err, org.ErrMemberMissing) {
		return org.ErrRoleReadDenied
	}
	if err != nil {
		return err
	}
	if err := s.requireOrganizationAction(ctx, tx, group, member.Role, "ac", "delete", org.ErrDeleteRoleDenied); err != nil {
		return err
	}
	if query.RoleName != "" && s.organizationRoles.IsPredefined(query.RoleName) {
		return org.ErrPredefinedRole
	}
	field, selector, err := roleLookupFilter(query)
	if err != nil {
		return err
	}
	arg := s.exactSQLValue("?")
	statement := `SELECT "id","role" FROM "organizationRole" WHERE "organizationId"=` + arg + " AND " + field + "=" + arg + " LIMIT 1"
	var id, role string
	err = tx.QueryRowContext(ctx, s.readForUpdate(statement), group, selector).Scan(&id, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return org.ErrRoleNotFound
	}
	if err != nil {
		return err
	}
	assigned, err := s.organizationRoleAssigned(ctx, tx, group, role, "")
	if err != nil {
		return err
	}
	if assigned {
		return org.ErrRoleAssigned
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "organizationRole" WHERE "organizationId"=`+arg+` AND "id"=`+arg), group, id); err != nil {
		return err
	}
	return tx.Commit()
}
