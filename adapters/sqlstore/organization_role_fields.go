package sqlstore

import (
	"fmt"

	"github.com/Plain-Auth/plain-auth/internal/sessionfields"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

// WithOrganizationRoleFields validates physical columns without modifying the shared pool.
func (s *Store) WithOrganizationRoleFields(defs map[string]org.RoleField) (org.Store, error) {
	fields, err := sessionfields.NormalizeRole(defs)
	if err != nil {
		return nil, err
	}
	if err := s.validateModelFields("organizationRole", fields); err != nil {
		return nil, err
	}
	view := *s
	view.roleFields = fields
	view.roleReadNames = nil
	view.roleReadColumns = ""
	for _, name := range sessionfields.Names(fields) {
		if !fields[name].Hidden {
			view.roleReadNames = append(view.roleReadNames, name)
			view.roleReadColumns += `,"` + fields[name].Column + `"`
		}
	}
	return &view, nil
}

func (s *Store) hasComputedRoleDefault() bool {
	for _, f := range s.roleFields {
		if f.Default != nil && f.StaticDefault() == nil {
			return true
		}
	}
	return false
}

func (s *Store) newRoleFields(input map[string]any) (map[string]any, error) {
	values, err := org.ParseRoleFieldInput(s.roleFields, input, false)
	if err != nil {
		return nil, err
	}
	if values == nil {
		values = make(map[string]any, len(s.roleFields))
	}
	for _, name := range sessionfields.Names(s.roleFields) {
		if _, present := values[name]; present {
			continue
		}
		value, err := s.roleFields[name].CreationDefault()
		if err != nil {
			return nil, fmt.Errorf("sqlstore: default for organization role field %q: %w", name, err)
		}
		values[name] = value
	}
	return values, nil
}

func (s *Store) publicRoleFields(values map[string]any) (map[string]any, error) {
	public := make(map[string]any)
	for _, name := range s.roleReadNames {
		value, err := s.roleFields[name].PublicValue(values[name])
		if err != nil {
			return nil, err
		}
		public[name] = value
	}
	return public, nil
}
