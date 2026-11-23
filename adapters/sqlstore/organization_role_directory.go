package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

var errDynamicRoleStoreDisabled = errors.New("sqlstore: stored organization roles require dynamic access control")

// roleLookupFilter returns a fixed SQL column and a separately bound selector.
func roleLookupFilter(query org.RoleQuery) (string, string, error) {
	if query.RoleName != "" {
		return `"role"`, query.RoleName, nil
	}
	if query.RoleID != "" {
		return `"id"`, query.RoleID, nil
	}
	return "", "", org.ErrRoleNotFound
}

const organizationRoleColumns = `"id","organizationId","role","permission","createdAt","updatedAt"`

func (s *Store) scanOrganizationRole(row rowScanner) (org.RoleDefinition, error) {
	var role org.RoleDefinition
	var raw string
	dest := []any{&role.ID, &role.OrganizationID, &role.Role, &raw, &role.CreatedAt, &role.UpdatedAt}
	names := s.roleReadNames
	for _, name := range names {
		dest = append(dest, scalarDestination(s.roleFields[name].Type))
	}
	err := row.Scan(dest...)
	if err != nil {
		return role, err
	}
	if len(names) > 0 {
		role.AdditionalFields = make(map[string]any, len(names))
		for i, name := range names {
			role.AdditionalFields[name], err = s.roleFields[name].PublicValue(scannedScalar(dest[6+i]))
			if err != nil {
				return role, err
			}
		}
	}
	role.Permission, err = org.DecodeStoredRoleGrants(raw)
	return role, err
}

func (s *Store) lockStoredRole(ctx context.Context, tx *sql.Tx, group string, q org.RoleQuery) (org.RoleDefinition, error) {
	field, selector, err := roleLookupFilter(q)
	if err != nil {
		return org.RoleDefinition{}, err
	}
	arg := s.exactSQLValue("?")
	statement := "SELECT " + organizationRoleColumns + s.roleReadColumns + ` FROM "organizationRole" WHERE "organizationId"=` + arg + " AND " + field + "=" + arg + " LIMIT 1"
	role, err := s.scanOrganizationRole(tx.QueryRowContext(ctx, s.readForUpdate(statement), group, selector))
	if errors.Is(err, sql.ErrNoRows) {
		return role, org.ErrRoleNotFound
	}
	return role, err
}

// ListOrganizationRoles returns up to 100 stored definitions for the destination organization.
func (s *Store) ListOrganizationRoles(ctx context.Context, sessionID, actorID, organizationID string) ([]org.RoleDefinition, error) {
	return s.readOrganizationRoles(ctx, sessionID, actorID, org.RoleQuery{OrganizationID: organizationID}, false)
}

// GetOrganizationRole looks up the exact name or ID in the caller's authorized scope.
func (s *Store) GetOrganizationRole(ctx context.Context, sessionID, actorID string, query org.RoleQuery) (*org.RoleDefinition, error) {
	rows, err := s.readOrganizationRoles(ctx, sessionID, actorID, query, true)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, org.ErrRoleNotFound
	}
	return &rows[0], nil
}

func (s *Store) readOrganizationRoles(ctx context.Context, sessionID, actorID string, query org.RoleQuery, lookup bool) ([]org.RoleDefinition, error) {
	if !s.dynamicOrganizationRoles {
		return nil, errDynamicRoleStoreDisabled
	}
	tx, err := s.beginReadSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	group, role, err := s.organizationRole(ctx, tx, sessionID, actorID, org.MemberRoleQuery{OrganizationID: query.OrganizationID})
	if err != nil {
		return nil, err
	}
	denied := org.ErrListRoleDenied
	if lookup {
		denied = org.ErrGetRoleDenied
	}
	if err := s.requireOrganizationAction(ctx, tx, group, role, "ac", "read", denied); err != nil {
		return nil, err
	}

	statement := "SELECT " + organizationRoleColumns + s.roleReadColumns + ` FROM "organizationRole" WHERE "organizationId"=` + s.exactSQLValue("?")
	args := []any{group}
	if lookup {
		field, selector, err := roleLookupFilter(query)
		if err != nil {
			return nil, err
		}
		statement += " AND " + field + "=" + s.exactSQLValue("?") + " LIMIT 1"
		args = append(args, selector)
	} else {
		statement += " LIMIT 100"
	}
	rows, err := tx.QueryContext(ctx, s.bind(statement), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	definitions := []org.RoleDefinition{}
	for rows.Next() {
		definition, err := s.scanOrganizationRole(rows)
		if err != nil {
			return nil, err
		}
		definitions = append(definitions, definition)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return definitions, nil
}
