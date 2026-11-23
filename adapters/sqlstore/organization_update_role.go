package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Plain-Auth/plain-auth/internal/sessionfields"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/access"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// UpdateOrganizationRole keeps the definition stable while checking the actor,
// new grants, and tenant-local name. Other memberships are keyed by their labels.
func (s *Store) UpdateOrganizationRole(ctx context.Context, userID, token string, query org.RoleQuery, change org.RoleUpdate, control access.Control) (*org.RoleDefinition, error) {
	if !s.dynamicOrganizationRoles {
		return nil, errDynamicRoleStoreDisabled
	}
	var row *org.RoleDefinition
	var err error
	for range 3 {
		row, err = s.updateOrganizationRole(ctx, userID, token, query, change, control)
		if !retryIdentity(err) {
			break
		}
	}
	return row, err
}

func (s *Store) updateOrganizationRole(ctx context.Context, userID, token string, query org.RoleQuery, change org.RoleUpdate, control access.Control) (*org.RoleDefinition, error) {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	group, err := s.lockMembershipScope(ctx, tx, userID, token, query.OrganizationID)
	if err != nil {
		return nil, err
	}
	actor, err := s.lockMembershipActor(ctx, tx, userID, group)
	if errors.Is(err, org.ErrMemberMissing) {
		return nil, org.ErrRoleReadDenied
	}
	if err != nil {
		return nil, err
	}
	policy, err := s.resolveOrganizationRoles(ctx, tx, group)
	if err != nil {
		return nil, err
	}
	if !policy.HasAction(actor.Role, "ac", "update") {
		return nil, org.ErrUpdateRoleDenied
	}
	role, err := s.lockStoredRole(ctx, tx, group, query)
	if err != nil {
		return nil, err
	}

	updates := []string{`"updatedAt"=?`}
	args := []any{s.date(time.Now().UTC().Truncate(time.Millisecond))}
	if change.Permission != nil {
		if err := policy.CheckDelegation(actor.Role, change.Permission, control, org.ErrUpdateRoleDenied); err != nil {
			return nil, err
		}
		// Store nil slices from trusted Go callers as empty JSON action arrays.
		role.Permission = make(access.Statements, len(change.Permission))
		for resource, actions := range change.Permission {
			role.Permission[resource] = append([]string{}, actions...)
		}
		raw, err := json.Marshal(role.Permission)
		if err != nil {
			return nil, err
		}
		updates = append(updates, `"permission"=?`)
		args = append(args, string(raw))
	}
	if change.RoleName != "" {
		if !org.ValidRoleName(change.RoleName) {
			return nil, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "A role name must be a nonempty, trimmed label without commas"}
		}
		name := cases.Lower(language.Und).String(change.RoleName)
		if s.organizationRoles.IsPredefined(name) {
			return nil, org.ErrRoleNameTaken
		}
		if err := s.requireUnusedRoleName(ctx, tx, group, name); err != nil {
			return nil, err
		}
		// Moving grants to a different membership label delegates them even
		// when the request leaves the permission field out.
		if change.Permission == nil {
			if err := policy.CheckDelegation(actor.Role, role.Permission, control, org.ErrUpdateRoleDenied); err != nil {
				return nil, err
			}
		}
		role.Role = name
		updates = append(updates, `"role"=?`)
		args = append(args, name)
	}
	values, err := org.ParseRoleFieldInput(s.roleFields, change.AdditionalFields, true)
	if err != nil {
		return nil, err
	}
	for _, name := range sessionfields.Names(s.roleFields) {
		value, present := values[name]
		if !present {
			continue
		}
		f := s.roleFields[name]
		updates = append(updates, `"`+f.Column+`"=?`)
		args = append(args, s.fieldParameter(value))
		if !f.Hidden {
			role.AdditionalFields[name], err = f.PublicValue(value)
			if err != nil {
				return nil, err
			}
		}
	}
	arg := s.exactSQLValue("?")
	statement := `UPDATE "organizationRole" SET ` + strings.Join(updates, ",") + ` WHERE "organizationId"=` + arg + ` AND "id"=` + arg
	args = append(args, group, role.ID)
	if _, err := tx.ExecContext(ctx, s.bind(statement), args...); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	// The acknowledgement carries the previous updatedAt. A get returns the
	// modification time recorded by this write.
	return &role, nil
}
