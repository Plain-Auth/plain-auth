package scim

import (
	"regexp"
	"strings"
)

// RFC 7643 section 2.1 makes attribute names case-insensitive, so two
// spellings of one declared attribute in a request are refused, null or not.
// Unknown keys are not compared. The declared names come from the discovery
// documents.

var commonAttributes = []any{map[string]any{"name": "schemas"}, map[string]any{"name": "id"}, map[string]any{"name": "externalId"}, map[string]any{"name": "meta"}}

var valuePath = regexp.MustCompile(`(?i)^([a-z$][\w$-]*)\s*\[[^\]]*\](?:\s*\.\s*([a-z$][\w$-]*))?$`)

func schemaAttributes(key string) []any {
	attributes, _ := descriptors[key]["attributes"].([]any)
	return attributes
}

// declared finds an attribute descriptor by its case-insensitive name.
func declared(attributes []any, name string) map[string]any {
	for _, a := range attributes {
		if d, ok := a.(map[string]any); ok && strings.EqualFold(d["name"].(string), name) {
			return d
		}
	}
	return nil
}

// duplicateNames reports two spellings of one declared attribute in a value
// or in each object of an array, and in their declared subattributes. A
// User resource also declares the Enterprise extension by its URN.
func duplicateNames(value any, attributes []any, resource bool) error {
	switch v := value.(type) {
	case []any:
		for _, entry := range v {
			if record, ok := entry.(map[string]any); ok {
				if err := duplicateNames(record, attributes, false); err != nil {
					return err
				}
			}
		}
	case map[string]any:
		seen := map[string]bool{}
		for key, entry := range v {
			name := key
			var subs []any
			if resource && strings.EqualFold(key, EnterpriseUserSchema) {
				name, subs = EnterpriseUserSchema, schemaAttributes("EnterpriseSchema")
			} else if d := declared(attributes, key); d != nil {
				name = d["name"].(string)
				subs, _ = d["subAttributes"].([]any)
			}
			if seen[name] {
				return invalid("invalidSyntax", name+" appears more than once with different letter case")
			}
			seen[name] = true
			if subs != nil {
				if err := duplicateNames(entry, subs, false); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// userPatchDuplicates checks a User PATCH value against what its path
// targets: a pathless value against the User resource and each of its keys
// as a path.
func userPatchDuplicates(path string, value any) error {
	if path != "" {
		return duplicateNames(value, userPathAttributes(path), false)
	}
	if err := duplicateNames(value, append(append([]any{}, commonAttributes...), schemaAttributes("Schemas")...), true); err != nil {
		return err
	}
	record, _ := value.(map[string]any)
	for key, entry := range record {
		if err := duplicateNames(entry, userPathAttributes(key), false); err != nil {
			return err
		}
	}
	return nil
}

// userPathAttributes returns the subattributes a User PATCH path's value
// holds, or nil when the path names no complex attribute.
func userPathAttributes(path string) []any {
	path = strings.TrimSpace(path)
	relative := withoutSchema(path, UserSchema)
	if relative == path {
		if attr, sub, ok, err := enterprisePath(relative); ok {
			enterprise := schemaAttributes("EnterpriseSchema")
			if err != nil || attr == "" {
				return enterprise
			}
			return subAttributes(declared(enterprise, attr), sub)
		}
	}
	attr, sub, _ := strings.Cut(relative, ".")
	if m := valuePath.FindStringSubmatch(relative); m != nil {
		attr, sub = m[1], m[2]
	}
	return subAttributes(declared(schemaAttributes("Schemas"), attr), sub)
}

func subAttributes(d map[string]any, sub string) []any {
	if d == nil {
		return nil
	}
	subs, _ := d["subAttributes"].([]any)
	if sub != "" {
		subs, _ = declared(subs, sub)["subAttributes"].([]any)
	}
	return subs
}
