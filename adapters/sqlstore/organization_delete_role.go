package sqlstore

import (
	"context"
	"errors"

	org "github.com/Plain-Org/plain-auth/plugins/organization"
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
	role, err := s.lockStoredRole(ctx, tx, group, query)
	if err != nil {
		return err
	}
	assigned, err := s.organizationRoleAssigned(ctx, tx, group, role.Role, "")
	if err != nil {
		return err
	}
	if assigned {
		return org.ErrRoleAssigned
	}
	arg := s.exactSQLValue("?")
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "organizationRole" WHERE "organizationId"=`+arg+` AND "id"=`+arg), group, role.ID); err != nil {
		return err
	}
	return tx.Commit()
}
