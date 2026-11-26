package scim

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/Plain-Org/plain-auth/internal/jsjson"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var roleFields = []string{"value", "display", "type", "primary"}

func roleType(s string) string { return cases.Lower(language.Und).String(jsjson.TrimSpace(s)) }

// A path can select all entries, a defined type or an explicitly stored
// primary flag. The same selectors can address a whole entry or one field.
var rolePath = regexp.MustCompile(`(?i)^roles(?:\s*\[\s*(?:type\s+eq\s+"([^"]+)"|primary\s+eq\s+(true|false|"true"|"false"))\s*\])?(?:\s*\.\s*([a-z]+))?$`)

func isRolePath(path string) bool {
	name, _, _ := strings.Cut(path, "[")
	name, _, _ = strings.Cut(name, ".")
	return strings.EqualFold(strings.TrimSpace(name), "roles")
}

func roleObject(raw any) (map[string]any, error) {
	input, ok := raw.(map[string]any)
	if !ok {
		return nil, invalid("invalidValue", "roles must contain objects")
	}
	item := map[string]any{}
	for name, v := range input {
		if k := field(name, roleFields); k != "" {
			if _, duplicate := item[k]; duplicate {
				return nil, invalid("invalidSyntax", "Duplicate role attribute "+k)
			}
			if k == "primary" && v != nil {
				if b, e := boolValue(v); e == nil {
					v = b
				}
			}
			item[k] = v
		}
	}
	return item, nil
}

func roleAdditions(value any) ([]map[string]any, error) {
	values, ok := value.([]any)
	if !ok {
		values = []any{value}
	}
	items := make([]map[string]any, 0, len(values))
	for _, v := range values {
		item, e := roleObject(v)
		if e != nil {
			return nil, e
		}
		items = append(items, item)
	}
	return items, nil
}

type roleSelection struct {
	kind, primary, sub string
}

func (s roleSelection) matches(row map[string]any) bool {
	if s.primary != "" {
		return row["primary"] == (s.primary == "true")
	}
	if s.kind != "" {
		v, ok := row["type"].(string)
		return ok && roleType(v) == s.kind
	}
	return true
}

func (s roleSelection) additions(value any) ([]map[string]any, error) {
	if s.sub != "" {
		if s.sub == "primary" {
			if b, e := boolValue(value); e == nil {
				value = b
			}
		}
		return []map[string]any{{s.sub: value}}, nil
	}
	return roleAdditions(value)
}

func (s roleSelection) assignSelector(item map[string]any) {
	if s.kind != "" && s.sub != "type" {
		item["type"] = s.kind
	}
	if s.primary != "" && s.sub != "primary" {
		item["primary"] = s.primary == "true"
	}
}

// Give an explicitly assigned primary entry priority over other entries in a
// PATCH. POST and PUT validate the submitted collection without this step.
func storePatchedRoles(m map[string]any, rows []map[string]any, primary int) {
	result := make([]any, 0, len(rows))
	for i, row := range rows {
		if primary >= 0 && i != primary && row["primary"] == true {
			row["primary"] = false
		}
		result = append(result, row)
	}
	m["roles"] = result
}

func patchRole(m map[string]any, path, op string, value any) error {
	parts := rolePath.FindStringSubmatch(path)
	if parts == nil {
		return invalid("invalidPath", "Unsupported role path")
	}
	selected := roleSelection{kind: roleType(parts[1]), primary: strings.Trim(strings.ToLower(parts[2]), "\""), sub: field(parts[3], roleFields)}
	if parts[3] != "" && selected.sub == "" {
		return invalid("invalidPath", "Unknown role subattribute")
	}
	current, _ := m["roles"].([]any)
	rows := make([]map[string]any, 0, len(current))
	var indexes []int
	for i, raw := range current {
		item, err := roleObject(raw)
		if err != nil {
			return err
		}
		rows = append(rows, item)
		if selected.matches(item) {
			indexes = append(indexes, i)
		}
	}
	whole := selected == (roleSelection{})
	if op == "remove" {
		if whole {
			delete(m, "roles")
			return nil
		}
		if len(indexes) == 0 {
			return nil
		}
		if selected.sub != "" {
			for _, i := range indexes {
				delete(rows[i], selected.sub)
			}
		} else {
			rows = slices.DeleteFunc(rows, selected.matches)
			if len(rows) == 0 {
				delete(m, "roles")
				return nil
			}
		}
		storePatchedRoles(m, rows, -1)
		return nil
	}
	additions, err := selected.additions(value)
	if err != nil {
		return err
	}
	primary := -1
	if whole || len(indexes) == 0 {
		if whole && op == "replace" {
			rows = nil
		}
		appended := false
		for _, item := range additions {
			if !whole {
				// A selector miss creates a new entry unless the change only clears fields.
				nonempty := len(item) > 0
				maps.DeleteFunc(item, func(_ string, v any) bool { return v == nil })
				if nonempty && len(item) == 0 {
					continue
				}
				selected.assignSelector(item)
			}
			if primary < 0 && item["primary"] == true {
				primary = len(rows)
			}
			rows = append(rows, item)
			appended = true
		}
		if !whole && !appended {
			return nil
		}
	} else {
		if len(additions) != 1 {
			return invalid("invalidValue", "Selected roles require one complex value")
		}
		replacement := additions[0]
		if replacement["primary"] == true {
			primary = indexes[0]
		}
		for _, i := range indexes {
			maps.Copy(rows[i], replacement)
		}
	}
	storePatchedRoles(m, rows, primary)
	return nil
}
