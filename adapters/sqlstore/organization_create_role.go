package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/Plain-Org/plain-auth/internal/sessionfields"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/access"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// CreateOrganizationRole resolves a host quota without holding a connection or
// lock. The saving transaction repeats all authorization and capacity checks.
func (s *Store) CreateOrganizationRole(ctx context.Context, actor auth.Session, request org.CreateRoleRequest, control access.Control, limit *org.RoleLimit) (*org.RoleDefinition, error) {
	if !s.dynamicOrganizationRoles {
		return nil, errDynamicRoleStoreDisabled
	}
	if actor.Token == "" || actor.UserID == "" || actor.IsApplicationCredential() {
		return nil, org.ErrUnauthenticated
	}
	if err := actor.RequireOwner(); err != nil {
		return nil, err
	}
	if request.Permission == nil {
		return nil, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "A role requires a permission object"}
	}
	if !org.ValidRoleName(request.Role) {
		return nil, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "A role name must be a nonempty, trimmed label without commas"}
	}
	grants := make(access.Statements, len(request.Permission))
	for key, actions := range request.Permission {
		grants[key] = append([]string{}, actions...)
	}
	row := org.RoleDefinition{ID: rand.Text(), Role: cases.Lower(language.Und).String(request.Role), Permission: grants}
	var fields map[string]any
	var maximum *int
	var expectedGroup string
	run := func(preflight bool) (string, error) {
		var group string
		var err error
		for range 3 {
			group, err = s.createOrganizationRoleOnce(ctx, actor, request.OrganizationID, expectedGroup, row, fields, control, maximum, preflight)
			if !retryIdentity(err) {
				break
			}
		}
		return group, err
	}
	if limit != nil {
		value := limit.Maximum
		if limit.Resolve != nil {
			group, err := run(true)
			if err != nil {
				return nil, err
			}
			expectedGroup = group
			value, err = limit.Resolve(ctx, group)
			if err != nil {
				return nil, err
			}
		}
		if value < 0 {
			return nil, errors.New("organization: role limit must be nonnegative")
		}
		maximum = &value
	}
	if len(s.roleFields) > 0 {
		// A host-supplied default may run application code. Run it once, outside
		// the write transaction, after checking the caller's current scope.
		if expectedGroup == "" && s.hasComputedRoleDefault() {
			group, err := run(true)
			if err != nil {
				return nil, err
			}
			expectedGroup = group
		}
		var err error
		fields, err = s.newRoleFields(request.AdditionalFields)
		if err != nil {
			return nil, err
		}
		row.AdditionalFields, err = s.publicRoleFields(fields)
		if err != nil {
			return nil, err
		}
	}
	row.CreatedAt = time.Now().UTC().Truncate(time.Millisecond)
	group, err := run(false)
	if err != nil {
		return nil, err
	}
	row.OrganizationID = group
	return &row, nil
}

func (s *Store) createOrganizationRoleOnce(ctx context.Context, actor auth.Session, explicit, expected string, row org.RoleDefinition, fields map[string]any, control access.Control, maximum *int, preflight bool) (string, error) {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	group, err := s.lockMembershipScope(ctx, tx, actor.UserID, actor.Token, explicit)
	if errors.Is(err, org.ErrNoActiveOrg) {
		return "", org.ErrCreateRoleNoOrg
	}
	if err != nil {
		return "", err
	}
	if expected != "" && group != expected {
		return "", org.ErrRoleScopeChanged
	}
	if s.organizationRoles.IsPredefined(row.Role) {
		return "", org.ErrRoleNameTaken
	}
	member, err := s.lockMembershipActor(ctx, tx, actor.UserID, group)
	if errors.Is(err, org.ErrMemberMissing) {
		return "", org.ErrRoleReadDenied
	}
	if err != nil {
		return "", err
	}
	policy, err := s.resolveOrganizationRoles(ctx, tx, group)
	if err != nil {
		return "", err
	}
	if !policy.HasAction(member.Role, "ac", "create") {
		return "", org.ErrCreateRoleDenied
	}
	if preflight {
		return group, nil
	}
	arg := s.exactSQLValue("?")
	if maximum != nil {
		var count int
		if err := tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "organizationRole" WHERE "organizationId"=`+arg), group).Scan(&count); err != nil {
			return "", err
		}
		if count >= *maximum {
			return "", org.ErrTooManyRoles
		}
	}
	if err := policy.CheckDelegation(member.Role, row.Permission, control, org.ErrCreateRoleDenied); err != nil {
		return "", err
	}
	if err := s.requireUnusedRoleName(ctx, tx, group, row.Role); err != nil {
		return "", err
	}
	raw, err := json.Marshal(row.Permission)
	if err != nil {
		return "", err
	}
	columns, params := `"id","organizationId","role","permission","createdAt"`, "?,?,?,?,?"
	args := []any{row.ID, group, row.Role, string(raw), s.date(row.CreatedAt)}
	for _, name := range sessionfields.Names(s.roleFields) {
		columns += `,"` + s.roleFields[name].Column + `"`
		params += ",?"
		args = append(args, s.fieldParameter(fields[name]))
	}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "organizationRole" (`+columns+`) VALUES (`+params+`)`), args...)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return group, nil
}

func (s *Store) requireUnusedRoleName(ctx context.Context, tx *sql.Tx, group, name string) error {
	arg := s.exactSQLValue("?")
	var taken bool
	if err := tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "organizationRole" WHERE "organizationId"=`+arg+` AND "role"=`+arg+`)`), group, name).Scan(&taken); err != nil {
		return err
	}
	if taken {
		return org.ErrRoleNameTaken
	}
	return nil
}
