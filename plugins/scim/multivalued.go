package scim

import "strings"

// multiValued describes a bounded multi-valued complex User attribute.
// Strings are trimmed and limits count Unicode code points; defined types are
// lowercased and unique case-insensitively; at most one value is primary.
// anyOf lists the fields of which one must be present; nil requires value.
type multiValued struct {
	name   string
	fields []string
	limits map[string]int
	anyOf  []string
}

var (
	phoneAttribute = multiValued{name: "phoneNumbers", fields: []string{"value", "type", "primary"},
		limits: map[string]int{"value": 1024, "type": 256}}
	addressAttribute = multiValued{name: "addresses", fields: []string{"formatted", "streetAddress", "locality", "region", "postalCode", "country", "type", "primary"},
		limits: map[string]int{"formatted": 1024, "streetAddress": 1024, "locality": 256, "region": 256, "postalCode": 256, "country": 256, "type": 256},
		anyOf:  []string{"formatted", "streetAddress", "locality", "region", "postalCode", "country"}}
	roleAttribute = multiValued{name: "roles", fields: roleFields,
		limits: map[string]int{"value": 1024, "display": 1024, "type": 256}}
	entitlementAttribute = multiValued{name: "entitlements", fields: roleFields,
		limits: map[string]int{"value": 1024, "display": 1024, "type": 256}}

	// multiValuedAttributes are stored in this order.
	multiValuedAttributes = []multiValued{phoneAttribute, addressAttribute, roleAttribute, entitlementAttribute}
)

// normalize checks a submitted collection and returns its canonical entries.
func (a multiValued) normalize(raw any) ([]any, error) {
	rows, ok := raw.([]any)
	if !ok || len(rows) > 10 {
		return nil, invalid("invalidValue", a.name+" must contain up to 10 entries")
	}
	out := make([]any, 0, len(rows))
	types := map[string]bool{}
	primary := false
	for _, row := range rows {
		item, err := object(row, a.fields)
		if err != nil {
			return nil, err
		}
		if a.anyOf == nil {
			if _, ok := item["value"]; !ok {
				return nil, invalid("invalidValue", a.name+".value is required")
			}
		} else if !a.hasAny(item) {
			return nil, invalid("invalidValue", a.name+" must contain at least one address value")
		}
		for key, limit := range a.limits {
			v, ok := item[key]
			if !ok {
				continue
			}
			if item[key], err = stringValue(v, limit); err != nil {
				return nil, err
			}
		}
		if kind, ok := item["type"].(string); ok {
			kind = roleType(kind)
			if types[kind] {
				return nil, invalid("invalidValue", a.name+" cannot contain duplicate defined types")
			}
			types[kind] = true
			item["type"] = kind
		}
		if v, exists := item["primary"]; exists {
			b, err := boolValue(v)
			if err != nil {
				return nil, invalid("invalidValue", a.name+".primary must be a boolean")
			}
			if primary && b {
				return nil, invalid("invalidValue", a.name+" cannot contain multiple primary values")
			}
			primary = primary || b
			item["primary"] = b
		}
		out = append(out, item)
	}
	return out, nil
}

func (a multiValued) hasAny(item map[string]any) bool {
	for _, key := range a.anyOf {
		if _, ok := item[key]; ok {
			return true
		}
	}
	return false
}

// multiValuedNamed finds an attribute by its case-insensitive name.
func multiValuedNamed(name string) (multiValued, bool) {
	for _, a := range multiValuedAttributes {
		if strings.EqualFold(strings.TrimSpace(name), a.name) {
			return a, true
		}
	}
	return multiValued{}, false
}
