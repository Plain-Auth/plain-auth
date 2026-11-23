package sqlstore

import (
	"context"
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

	statement := `SELECT "id","organizationId","role","permission","createdAt","updatedAt" FROM "organizationRole" WHERE "organizationId"=` + s.exactSQLValue("?")
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
		var definition org.RoleDefinition
		var raw string
		if err := rows.Scan(&definition.ID, &definition.OrganizationID, &definition.Role, &raw, &definition.CreatedAt, &definition.UpdatedAt); err != nil {
			return nil, err
		}
		definition.Permission, err = org.DecodeStoredRoleGrants(raw)
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
