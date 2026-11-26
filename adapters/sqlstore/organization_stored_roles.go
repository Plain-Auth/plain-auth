package sqlstore

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Plain-Org/plain-auth/plugins/access"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
)

// WithOrganizationDynamicRoles enables role resolution on this adapter only.
func (s *Store) WithOrganizationDynamicRoles() (org.DynamicRoleStore, error) {
	rows, err := s.db.Query(s.bind(`SELECT "id","organizationId","role","permission","createdAt","updatedAt" FROM "organizationRole" WHERE 1=0`))
	if err != nil {
		return nil, fmt.Errorf("sqlstore: dynamic organization roles require the organization-roles schema: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	scoped := *s
	scoped.dynamicOrganizationRoles = true
	return &scoped, nil
}

func (s *Store) resolveOrganizationRoles(ctx context.Context, tx *sql.Tx, group string) (org.RolePolicy, error) {
	if !s.dynamicOrganizationRoles {
		return s.organizationRoles, nil
	}
	return s.withStoredOrganizationRoles(ctx, tx, group, s.organizationRoles, false)
}

// withStoredOrganizationRoles merges the roles organization group stored
// with dynamic access control into base. A locking read sees the latest
// committed roles, as the member row read under lock does, where a plain
// read in a repeatable-read transaction sees its first snapshot.
func (s *Store) withStoredOrganizationRoles(ctx context.Context, tx *sql.Tx, group string, base org.RolePolicy, locking bool) (org.RolePolicy, error) {
	query := `SELECT "role","permission" FROM "organizationRole" WHERE "organizationId"=` + s.exactSQLValue("?")
	bound := s.bind(query)
	if locking {
		bound = s.readForUpdate(query)
	}
	rows, err := tx.QueryContext(ctx, bound, group)
	if err != nil {
		return org.RolePolicy{}, err
	}
	defer rows.Close()
	var definitions []org.StoredRoleGrants
	for rows.Next() {
		var row org.StoredRoleGrants
		var raw string
		if err := rows.Scan(&row.Role, &raw); err != nil {
			return org.RolePolicy{}, err
		}
		row.Permission, err = org.DecodeStoredRoleGrants(raw)
		if err != nil {
			return org.RolePolicy{}, err
		}
		definitions = append(definitions, row)
	}
	if err := rows.Err(); err != nil {
		return org.RolePolicy{}, err
	}
	return base.WithStoredRoles(definitions), nil
}

func (s *Store) requireOrganizationAction(ctx context.Context, tx *sql.Tx, group, role, resource, action string, denied error) error {
	policy, err := s.resolveOrganizationRoles(ctx, tx, group)
	if err != nil {
		return err
	}
	if !policy.HasAction(role, resource, action) {
		return denied
	}
	return nil
}

// CheckOrganizationPermission resolves an implicit destination in the same
// snapshot as membership and tenant grants. It leaves the session untouched.
func (s *Store) CheckOrganizationPermission(ctx context.Context, sessionID, actorID, group string, requested access.Statements) (bool, error) {
	query := org.MemberRoleQuery{OrganizationID: group}
	if !s.dynamicOrganizationRoles {
		role, err := s.OrganizationMemberRole(ctx, sessionID, actorID, query)
		return s.organizationRoles.HasPermission(role, requested), err
	}
	tx, err := s.beginReadSnapshot(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	group, role, err := s.organizationRole(ctx, tx, sessionID, actorID, query)
	if err != nil {
		return false, err
	}
	policy, err := s.resolveOrganizationRoles(ctx, tx, group)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return policy.HasPermission(role, requested), nil
}

// OrganizationRolePolicyFor returns the role policy in effect for one
// organization, including its stored roles when dynamic roles are enabled.
func (s *Store) OrganizationRolePolicyFor(ctx context.Context, organizationID string) (org.RolePolicy, error) {
	tx, err := s.beginReadSnapshot(ctx)
	if err != nil {
		return org.RolePolicy{}, err
	}
	defer tx.Rollback()
	return s.resolveOrganizationRoles(ctx, tx, organizationID)
}
