// Package schema generates fresh-database DDL for authentication and plugin tables.
package schema

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/Plain-Org/plain-auth/internal/polarledger"
	"github.com/Plain-Org/plain-auth/internal/sessionfields"
)

//go:embed catalog.json
var catalog []byte

type fragment struct {
	SQL      string   `json:"sql"`
	Profiles []string `json:"profiles"`
}

type statement struct {
	fragment
	Columns     []fragment `json:"columns"`
	Constraints []string   `json:"constraints"`
}

var layouts struct {
	Profiles []string               `json:"profiles"`
	Dialects map[string][]statement `json:"dialects"`
}

func init() {
	if err := json.Unmarshal(catalog, &layouts); err != nil {
		panic("schema: invalid embedded catalog: " + err.Error())
	}
	// Polar checkout reservations and delivery receipts belong to the Go
	// integration and use the same definitions as its runtime ledger.
	layouts.Profiles = append(layouts.Profiles, "polar")
	for dialect := range layouts.Dialects {
		for _, table := range polarledger.Tables(dialect) {
			object := statement{fragment: fragment{SQL: "create table " + table.Name, Profiles: []string{"polar"}}}
			for _, column := range table.Columns {
				object.Columns = append(object.Columns, fragment{SQL: column})
			}
			layouts.Dialects[dialect] = append(layouts.Dialects[dialect], object)
		}
	}
}

// Profiles returns the available schema selectors in canonical order.
func Profiles() []string { return slices.Clone(layouts.Profiles) }

func (f fragment) included(selected map[string]bool) bool {
	if len(f.Profiles) == 0 {
		return true
	}
	for _, name := range f.Profiles {
		if selected[name] {
			return true
		}
	}
	return false
}

func selection(dialect string, profiles []string) ([]statement, map[string]bool, error) {
	switch dialect {
	case "postgresql":
		dialect = "postgres"
	case "sqlite3":
		dialect = "sqlite"
	}
	objects, ok := layouts.Dialects[dialect]
	if !ok {
		return nil, nil, fmt.Errorf("schema: unsupported dialect %q", dialect)
	}
	selected := make(map[string]bool, len(profiles))
	for _, name := range profiles {
		if !slices.Contains(layouts.Profiles, name) {
			return nil, nil, fmt.Errorf("schema: unknown plugin profile %q", name)
		}
		selected[name] = true
	}
	if selected["username"] && selected["username-only"] {
		return nil, nil, fmt.Errorf("schema: choose one username profile")
	}
	if selected["organization"] && selected["organization-teams"] {
		return nil, nil, fmt.Errorf("schema: choose one organization profile, organization or organization-teams")
	}
	return objects, selected, nil
}

// Generate returns SQL for SQLite, PostgreSQL or MySQL. Profile order does
// not affect output. The organization-teams profile includes organization.
func Generate(dialect string, profiles []string) (string, error) {
	return GenerateWithSessionFields(dialect, profiles, nil)
}

// GenerateWithSessionFields generates the physical session columns alongside
// the selected core and plugin schema. Fresh columns have application defaults.
func GenerateWithSessionFields(dialect string, profiles []string, fields map[string]sessionfields.Field) (string, error) {
	return GenerateWithAdditionalFields(dialect, profiles, AdditionalFields{Session: fields})
}

// UserField declares a scalar column in the user profile.
type UserField = sessionfields.Field

// AccountField declares a scalar column on a linked provider or credential account.
type AccountField = sessionfields.Field

// RoleField declares an additional column on an organization role.
type RoleField = sessionfields.Field

// AdditionalFields declares additional columns independently for each model.
type AdditionalFields struct {
	User             map[string]UserField
	Session          map[string]SessionField
	Account          map[string]AccountField
	OrganizationRole map[string]RoleField
}

// Normalize validates each namespace and returns owned copies of its declarations.
func (f AdditionalFields) Normalize() (AdditionalFields, error) {
	var err error
	f.User, err = sessionfields.NormalizeUser(f.User)
	if err != nil {
		return AdditionalFields{}, err
	}
	f.Session, err = sessionfields.Normalize(f.Session)
	if err != nil {
		return AdditionalFields{}, err
	}
	f.Account, err = sessionfields.NormalizeAccount(f.Account)
	if err != nil {
		return AdditionalFields{}, err
	}
	f.OrganizationRole, err = sessionfields.NormalizeRole(f.OrganizationRole)
	return f, err
}

// GenerateWithAdditionalFields includes configured additional columns in fresh DDL.
func GenerateWithAdditionalFields(dialect string, profiles []string, fields AdditionalFields) (string, error) {
	return GenerateWithOptions(dialect, profiles, Options{AdditionalFields: fields})
}

// GenerateWithOptions generates the physical schema for a configured installation.
func GenerateWithOptions(dialect string, profiles []string, opts Options) (string, error) {
	fields, err := opts.AdditionalFields.Normalize()
	if err != nil {
		return "", err
	}
	objects, selected, err := mappedObjects(dialect, profiles, opts)
	if err != nil {
		return "", err
	}
	statements := make([]string, 0, len(objects))
	for _, object := range objects {
		if !object.included(selected) {
			continue
		}
		sql := object.SQL
		if len(object.Columns) > 0 {
			columns := make([]string, 0, len(object.Columns))
			for _, column := range object.Columns {
				if column.included(selected) {
					columns = append(columns, column.SQL)
				}
			}
			model := strings.Trim(strings.TrimPrefix(object.SQL, "create table "), "\"`")
			var extras map[string]sessionfields.Field
			switch model {
			case "user":
				extras = fields.User
			case "session":
				extras = fields.Session
			case "account":
				extras = fields.Account
			case "organizationRole":
				extras = fields.OrganizationRole
			}
			if len(extras) > 0 {
				for _, name := range sessionfields.Names(extras) {
					columns = append(columns, extras[name].Definition(dialect))
				}
			}
			sql += " (" + strings.Join(append(columns, object.Constraints...), ", ") + ");"
		}
		statements = append(statements, sql)
	}
	return strings.Join(statements, "\n\n") + "\n", nil
}

// Table describes the physical columns used by a configured schema.
type Table struct {
	Name    string
	Columns []string
}

// Tables returns the selected physical names in their canonical schema order.
func Tables(dialect string, profiles []string) ([]Table, error) {
	return TablesWithOptions(dialect, profiles, Options{})
}

// TablesWithOptions includes mapped wallet table and column identifiers.
func TablesWithOptions(dialect string, profiles []string, opts Options) ([]Table, error) {
	objects, selected, err := mappedObjects(dialect, profiles, opts)
	if err != nil {
		return nil, err
	}
	var tables []Table
	for _, object := range objects {
		if len(object.Columns) == 0 || !object.included(selected) {
			continue
		}
		table := Table{Name: strings.Trim(strings.TrimPrefix(object.SQL, "create table "), "\"`")}
		for _, col := range object.Columns {
			if col.included(selected) {
				name, _, _ := strings.Cut(col.SQL, " ")
				table.Columns = append(table.Columns, strings.Trim(name, "\"`"))
			}
		}
		tables = append(tables, table)
	}
	return tables, nil
}
