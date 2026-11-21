// Package schema generates complete fresh-database DDL for supported auth and plugin configurations.
package schema

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

//go:embed catalog.json
var catalog []byte

// Each supported combination references the shared statements in foreign-key
// dependency order. Regenerate the catalog with conformance/plugin-schema.mjs.
type dialectPlan struct {
	Statements []string         `json:"statements"`
	Plans      map[string][]int `json:"plans"`
}

var dialects map[string]dialectPlan

func init() {
	if err := json.Unmarshal(catalog, &dialects); err != nil {
		panic("schema: invalid embedded catalog: " + err.Error())
	}
}

// Generate returns SQL for SQLite, PostgreSQL or MySQL. Supported profiles are
// jwt, organization, organization-teams, passkey, rate-limit, stripe-subscriptions and two-factor.
// organization-teams includes organization and selects its teams option.
// Profile order is canonical so equivalent calls emit the same SQL.
func Generate(dialect string, profiles []string) (string, error) {
	switch dialect {
	case "postgresql":
		dialect = "postgres"
	case "sqlite3":
		dialect = "sqlite"
	}
	spec, ok := dialects[dialect]
	if !ok {
		return "", fmt.Errorf("schema: unsupported dialect %q", dialect)
	}
	names := slices.Clone(profiles)
	slices.Sort(names)
	names = slices.Compact(names)
	for _, name := range names {
		if _, ok := spec.Plans[name]; !ok || name == "" || strings.Contains(name, ",") {
			return "", fmt.Errorf("schema: unknown plugin profile %q", name)
		}
	}
	plan, ok := spec.Plans[strings.Join(names, ",")]
	if !ok {
		return "", fmt.Errorf("schema: choose one organization profile, organization or organization-teams")
	}
	statements := make([]string, 0, len(plan))
	for _, index := range plan {
		statements = append(statements, spec.Statements[index])
	}
	return strings.Join(statements, "\n\n") + "\n", nil
}
