package scim

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var equality = regexp.MustCompile(`(?i)^(?:urn:ietf:params:scim:schemas:core:2\.0:user:)?(id|userName|externalId|emails\.value|emails\[\s*type\s+eq\s+"work"\s*\]\.value)\s+eq\s+("(?:[^"\\]|\\.)*")(?:\s+(and)\s+|$)`)

var groupEquality = regexp.MustCompile(`(?i)^(?:urn:ietf:params:scim:schemas:core:2\.0:group:)?(id|displayName|externalId)\s+eq\s+("(?:[^"\\]|\\.)*")(?:\s+(and)\s+|$)`)

func query(values url.Values, equality *regexp.Regexp) (Query, error) {
	var q Query
	page := map[string]int{"startIndex": 1, "count": 100}
	for k := range page {
		if list, ok := values[k]; ok {
			if len(list) != 1 {
				return q, invalid("invalidValue", "Expected one "+k)
			}
			n, err := strconv.ParseInt(strings.TrimSpace(list[0]), 10, 53)
			if err != nil {
				return q, invalid("invalidValue", k+" must be an integer")
			}
			page[k] = int(n)
		}
	}
	q.Offset = max(1, page["startIndex"]) - 1
	q.Count = min(100, max(0, page["count"]))
	f := strings.TrimSpace(values.Get("filter"))
	for f != "" {
		match := equality.FindStringSubmatch(f)
		if match == nil || len(q.Filters) >= 10 {
			return q, invalid("invalidFilter", "Expected a supported equality filter")
		}
		k := strings.ToLower(match[1])
		if strings.HasPrefix(k, "emails[") {
			k = "emails.work.value"
		}
		var v string
		if err := json.Unmarshal([]byte(match[2]), &v); err != nil || strings.TrimSpace(v) == "" {
			return q, invalid("invalidFilter", "Invalid filter value")
		}
		q.Filters = append(q.Filters, Filter{k, strings.TrimSpace(v)})
		f = f[len(match[0]):]
		if match[3] != "" && f == "" {
			return q, invalid("invalidFilter", "Missing equality expression")
		}
	}
	return q, nil
}

type projection struct {
	include bool
	fields  map[string]bool
}

func projectQuery(q url.Values, fields []string, schema string) (projection, error) {
	var p projection
	if q.Has("attributes") && q.Has("excludedAttributes") {
		return p, invalid("invalidValue", "Choose one attribute projection")
	}
	key := "excludedAttributes"
	if q.Has("attributes") {
		key = "attributes"
		p.include = true
	}
	if !q.Has(key) {
		return p, nil
	}
	p.fields = map[string]bool{}
	for _, arg := range q[key] {
		for _, s := range strings.Split(arg, ",") {
			s = strings.TrimSpace(s)
			name := field(withoutSchema(s, schema), fields)
			if name == "" {
				return p, invalid("invalidValue", "Unknown projection attribute")
			}
			p.fields[name] = true
		}
	}
	return p, nil
}
func (p projection) apply(m map[string]any) map[string]any {
	if p.fields != nil {
		roles, found := m["roles"]
		for k := range m {
			if k != "id" && k != "schemas" && p.fields[k] != p.include {
				delete(m, k)
			}
		}
		if found && !p.fields["roles"] && p.hasRoleSelection() {
			rows, _ := roles.([]any)
			selected := make([]any, 0, len(rows))
			for _, row := range rows {
				fields, _ := row.(map[string]any)
				item := map[string]any{}
				for key, value := range fields {
					if p.fields["roles."+key] == p.include {
						item[key] = value
					}
				}
				if len(item) != 0 || !p.include {
					selected = append(selected, item)
				}
			}
			if len(selected) != 0 || !p.include {
				m["roles"] = selected
			}
		}
	}
	return m
}

var userProjectionFields = append(append([]string{"id", "meta"}, userFields...), "roles.value", "roles.display", "roles.type", "roles.primary")

func (p projection) hasRoleSelection() bool {
	for _, f := range roleFields {
		if p.fields["roles."+f] {
			return true
		}
	}
	return false
}
