package scim

import (
	"regexp"
	"slices"
	"strings"
)

// RFC 7643 section 2.1 makes attribute names case-insensitive, so two
// spellings of one declared attribute in a request are refused, null or not.
// Unknown keys are not compared. The declared names come from the discovery
// documents.

var commonAttributes = []any{map[string]any{"name": "schemas"}, map[string]any{"name": "id"}, map[string]any{"name": "externalId"}, map[string]any{"name": "meta"}}

// valuePath matches the type and primary filters a User PATCH path may use.
var valuePath = regexp.MustCompile(`(?i)^([a-z$][\w$-]*)\s*\[\s*(?:type\s+eq\s+"[^"]+"|primary\s+eq\s+"?(?:true|false)"?)\s*\](?:\s*\.\s*([a-z$][\w$-]*))?$`)

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
	record, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if err := duplicateNames(record, append(append([]any{}, commonAttributes...), schemaAttributes("Schemas")...), true); err != nil {
		return err
	}
	for key, entry := range record {
		if err := duplicateNames(entry, userPathAttributes(key), false); err != nil {
			return err
		}
	}
	return nil
}

// userPathAttributes returns the subattributes a User PATCH path's value
// holds, or nil when the path names no complex attribute or cannot be
// resolved, so its operation reports the path error instead.
func userPathAttributes(path string) []any {
	path = strings.TrimSpace(path)
	relative := withoutSchema(path, UserSchema)
	if attr, sub, ok, err := enterprisePath(relative); ok && enterpriseReachable(relative, relative != path) {
		enterprise := schemaAttributes("EnterpriseSchema")
		switch {
		case err != nil:
			return nil
		case attr == "":
			return enterprise
		}
		return subAttributes(declared(enterprise, attr), sub)
	}
	if m := valuePath.FindStringSubmatch(relative); m != nil {
		d := declared(schemaAttributes("Schemas"), m[1])
		if d == nil || d["multiValued"] != true {
			return nil
		}
		return subAttributes(d, m[2])
	}
	segments := strings.Split(relative, ".")
	if len(segments) > 2 || slices.Contains(segments, "") || strings.Contains(relative, "[") {
		return nil
	}
	sub := ""
	if len(segments) == 2 {
		sub = segments[1]
	}
	return subAttributes(declared(schemaAttributes("Schemas"), segments[0]), sub)
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

// opsDuplicates checks each User PATCH operation's value; an operation that
// is not an object or whose path is not a string is left to the parser.
func opsDuplicates(ops []any) error {
	for _, item := range ops {
		op, ok := item.(map[string]any)
		if !ok {
			continue
		}
		// A present path that is not a string fails the body shape check
		// instead, as another runtime leaves such an operation unread.
		if p, present := op["path"]; present {
			if _, isString := p.(string); !isString {
				continue
			}
		}
		// The exact path and value keys are read, as another runtime's
		// request hook reads them before its body schema.
		path, value := op["path"], op["value"]
		text, isString := path.(string)
		if path != nil && !isString {
			continue
		}
		if err := userPatchDuplicates(strings.TrimSpace(text), value); err != nil {
			return err
		}
	}
	return nil
}

// groupOpsDuplicates checks each Group PATCH operation's value before the
// Group is looked up: a pathless value against the Group resource and a
// members value against the member subattributes.
func groupOpsDuplicates(ops []any) error {
	resource := append(append([]any{}, commonAttributes...), schemaAttributes("GroupSchema")...)
	for _, item := range ops {
		op, ok := item.(map[string]any)
		if !ok {
			continue
		}
		// A present path that is not a string fails the body shape check
		// instead, as another runtime leaves such an operation unread.
		if p, present := op["path"]; present {
			if _, isString := p.(string); !isString {
				continue
			}
		}
		// The exact path and value keys are read, as another runtime's
		// request hook reads them before its body schema.
		path, value := op["path"], op["value"]
		text, isString := path.(string)
		if path != nil && !isString {
			continue
		}
		var attributes []any
		switch text = strings.TrimSpace(text); {
		case text == "":
			if _, isMap := value.(map[string]any); !isMap {
				continue
			}
			attributes = resource
		case strings.EqualFold(withoutSchema(text, GroupSchema), "members"):
			attributes = subAttributes(declared(resource, "members"), "")
		default:
			continue
		}
		if err := duplicateNames(value, attributes, false); err != nil {
			return err
		}
	}
	return nil
}
