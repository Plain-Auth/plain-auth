package scim

import (
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var roleFields = []string{"value", "display", "type", "primary"}

func trimRoleText(s string) string {
	// ECMAScript whitespace includes the byte order mark and excludes NEXT LINE.
	return strings.TrimFunc(s, func(r rune) bool { return r == '\uFEFF' || r != '\u0085' && unicode.IsSpace(r) })
}

func roleText(raw any, maxRunes int) (string, error) {
	s, ok := raw.(string)
	s = trimRoleText(s)
	if !ok || s == "" || utf8.RuneCountInString(s) > maxRunes {
		return "", invalid("invalidValue", "Invalid role string attribute")
	}
	return s, nil
}

func roleType(s string) string { return cases.Lower(language.Und).String(trimRoleText(s)) }

// The roles collection is a directory-owned profile attribute.
func normalizeRoles(raw any) ([]any, error) {
	rows, ok := raw.([]any)
	if !ok || len(rows) > 10 {
		return nil, invalid("invalidValue", "roles must contain up to 10 entries")
	}
	out := make([]any, 0, len(rows))
	types := map[string]bool{}
	primary := false
	for _, row := range rows {
		item, err := object(row, roleFields)
		if err != nil {
			return nil, err
		}
		item["value"], err = roleText(item["value"], 1024)
		if err != nil {
			return nil, err
		}
		if v, ok := item["display"]; ok {
			item["display"], err = roleText(v, 1024)
			if err != nil {
				return nil, err
			}
		}
		if v, ok := item["type"]; ok {
			kind, err := roleText(v, 256)
			if err != nil {
				return nil, err
			}
			kind = roleType(kind)
			if types[kind] {
				return nil, invalid("invalidValue", "roles cannot contain duplicate defined types")
			}
			types[kind] = true
			item["type"] = kind
		}
		if v, exists := item["primary"]; exists {
			b, err := boolValue(v)
			if err != nil {
				return nil, invalid("invalidValue", "roles.primary must be a boolean")
			}
			if primary && b {
				return nil, invalid("invalidValue", "roles cannot contain multiple primary values")
			}
			primary = primary || b
			item["primary"] = b
		}
		out = append(out, item)
	}
	return out, nil
}

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
				return nil, invalid("invalidValue", "Duplicate role attribute "+k)
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
