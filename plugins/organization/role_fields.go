package organization

import (
	"errors"
	"github.com/Plain-Auth/plain-auth/internal/jsjson"
	"strconv"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/sessionfields"
)

// RoleField declares a host-defined column on a stored organization role.
type RoleField = auth.SessionField

// Structured field types for organization.RoleField.Type.
const (
	RoleJSON        = sessionfields.JSON
	RoleStringArray = sessionfields.StringArray
	RoleNumberArray = sessionfields.NumberArray
)

// RoleFieldStoreProvider binds declarations to an independent store view.
type RoleFieldStoreProvider interface {
	WithOrganizationRoleFields(map[string]RoleField) (Store, error)
}

// ParseRoleFieldInput collects declared writable fields from a creation envelope
// or a partial update. Unknown and server-owned properties are ignored.
func ParseRoleFieldInput(defs map[string]RoleField, input map[string]any, patch bool) (map[string]any, error) {
	path := "additionalFields."
	if patch {
		path = "data."
	}
	var values map[string]any
	var issues []string
	for _, name := range sessionfields.Names(defs) {
		f := defs[name]
		if f.ServerOnly {
			continue
		}
		value, present := input[name]
		if !present && (patch || !f.Required || (input == nil && f.Default != nil)) {
			continue
		}
		v, err := f.Value(value)
		if err != nil {
			fieldPath := path + name
			expected := string(f.Type)
			var elements sessionfields.ElementErrors
			if errors.As(err, &elements) {
				for _, e := range elements {
					issues = append(issues, bodyTypeIssue(fieldPath+"."+strconv.Itoa(e.Index), e.Expected, e.Value, true))
				}
				continue
			}
			if f.Type == RoleStringArray || f.Type == RoleNumberArray {
				expected = "array"
			}
			if present && (jsjson.TypeName(value) == expected || f.Type == RoleJSON) {
				issues = append(issues, "[body."+fieldPath+"] "+err.Error())
			} else {
				issues = append(issues, bodyTypeIssue(fieldPath, expected, value, present))
			}
			continue
		}
		if values == nil {
			values = make(map[string]any)
		}
		values[name] = v
	}
	if len(issues) != 0 {
		return nil, problem(400, "VALIDATION_ERROR", strings.Join(issues, "; "))
	}
	return values, nil
}
