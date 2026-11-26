package scim

import (
	"maps"
	"slices"
	"strings"
)

func patchOperations(input any) ([]any, error) {
	m, err := object(input, []string{"schemas", "Operations"})
	if err != nil {
		return nil, err
	}
	schemas, ok := m["schemas"].([]any)
	if !ok || len(schemas) != 1 || schemas[0] != PatchSchema {
		return nil, invalid("invalidSyntax", "The PatchOp schema is required")
	}
	// An empty Operations array is a valid no-op; the request body limit
	// bounds a long one.
	ops, ok := m["Operations"].([]any)
	if !ok {
		return nil, invalid("invalidSyntax", "Operations must be an array")
	}
	return ops, nil
}
func patchProfile(r Record, raw []any) (Profile, error) {
	ops, err := userOps(raw)
	if err != nil {
		return Profile{}, err
	}
	if ops, err = expandNulls(ops); err != nil {
		return Profile{}, err
	}
	m := profileObject(r.Profile)
	for _, o := range ops {
		switch {
		case o.path == "" && o.op == "remove":
			return Profile{}, invalid("noTarget", "A pathless remove has no target")
		case o.op != "remove" && !o.hasValue:
			// Refuse a missing value; another runtime treats some such
			// operations as removals.
			return Profile{}, invalid("invalidValue", "Patch value is required")
		case o.path != "":
			err = patchValue(m, o.path, o.op, o.value)
		default:
			// An empty map is a no-op.
			fields, ok := o.value.(map[string]any)
			if !ok {
				return Profile{}, invalid("invalidValue", "Expected an attribute map")
			}
			if _, err = object(fields, userFields); err != nil {
				return Profile{}, err
			}
			// Go decodes a JSON object into a map, so apply its keys in sorted
			// order to stay deterministic; another runtime applies them in
			// request order.
			for _, name := range slices.Sorted(maps.Keys(fields)) {
				if err = patchValue(m, name, o.op, fields[name]); err != nil {
					break
				}
			}
		}
		if err != nil {
			return Profile{}, err
		}
	}
	return normalize(m)
}

// userOps parses PATCH operations; an omitted op means replace.
func userOps(raw []any) ([]patchOp, error) {
	ops := make([]patchOp, 0, len(raw))
	for _, item := range raw {
		v, err := object(item, []string{"op", "path", "value"})
		if err != nil {
			return nil, err
		}
		o := patchOp{op: "replace", value: v["value"]}
		for key := range item.(map[string]any) {
			o.hasValue = o.hasValue || strings.EqualFold(key, "value")
		}
		if v["op"] != nil {
			name, ok := v["op"].(string)
			if !ok {
				return nil, invalid("invalidSyntax", "Expected a patch operation")
			}
			o.op = strings.ToLower(name)
		}
		if o.op != "add" && o.op != "replace" && o.op != "remove" {
			return nil, invalid("invalidSyntax", "Unsupported patch operation")
		}
		if v["path"] != nil {
			path, ok := v["path"].(string)
			if !ok {
				return nil, invalid("invalidPath", "Expected an attribute path")
			}
			o.path = strings.TrimSpace(path)
		}
		// Check the names before null keys become removals, which would hide a
		// null second spelling.
		if err := userPatchDuplicates(o.path, o.value); err != nil {
			return nil, err
		}
		ops = append(ops, o)
	}
	return ops, nil
}

// readOnlyUserPath reports id, schemas and meta, which a PATCH cannot change.
func readOnlyUserPath(path string) bool {
	head, _, _ := strings.Cut(path, ".")
	head, _, _ = strings.Cut(head, "[")
	return strings.EqualFold(head, "id") || strings.EqualFold(head, "schemas") || strings.EqualFold(head, "meta")
}

func patchValue(m map[string]any, path, op string, value any) error {
	prefixed := len(path) > len(UserSchema) && strings.EqualFold(path[:len(UserSchema)+1], UserSchema+":")
	if prefixed {
		path = path[len(UserSchema)+1:]
	}
	if readOnlyUserPath(strings.TrimSpace(path)) {
		return invalid("mutability", "The targeted User attribute is read-only")
	}
	// The Enterprise forms and the manager alias are not core attributes, so
	// the core schema prefix does not reach them.
	if attr, sub, ok, err := enterprisePath(path); ok && !prefixed {
		if err != nil {
			return err
		}
		return patchEnterprise(m, attr, sub, op, value)
	}
	if a, ok := multiValuedPathName(path); ok {
		return patchMultiValued(m, a, path, op, value)
	}
	if isEmailPath(path) {
		return patchEmails(m, strings.TrimSpace(path), op, value)
	}
	parts := strings.Split(path, ".")
	name := field(parts[0], userFields)
	if name == "" || name == "schemas" || len(parts) > 2 {
		return invalid("invalidPath", "Unsupported User attribute path")
	}
	target := m
	if len(parts) == 2 {
		if name != "name" {
			return invalid("invalidPath", "Unsupported User subattribute")
		}
		sub := field(parts[1], nameFields)
		if sub == "" {
			return invalid("invalidPath", "Unsupported name subattribute")
		}
		current, _ := m[name].(map[string]any)
		target = maps.Clone(current)
		if target == nil {
			target = map[string]any{}
		}
		m[name] = target
		name = sub
		if op == "remove" && sub == "formatted" {
			// Removing the formatted name composes it from the given and
			// family names; without them normalize derives it from the
			// display name, then the primary email.
			given, _ := target["givenName"].(string)
			family, _ := target["familyName"].(string)
			fallback := strings.TrimSpace(given + " " + family)
			if fallback == "" {
				fallback, _ = m["displayName"].(string)
			}
			if fallback == "" {
				fallback = primaryEmail(m)
			}
			if fallback != "" {
				setFormatted(m, target, fallback)
				target["formatted"] = fallback
				return nil
			}
		}
		value = single(value)
		if sub == "formatted" && op != "remove" {
			setFormatted(m, target, value)
		}
	}
	if op == "remove" {
		// The fallbacks apply at once, as another runtime applies them, so a
		// later operation in the request sees them.
		stored, _ := m["name"].(map[string]any)
		formatted, _ := stored["formatted"].(string)
		display, _ := m["displayName"].(string)
		switch {
		case name == "userName":
			return invalid("mutability", "userName is required")
		case len(parts) == 1 && name == "displayName" && formatted != "":
			m["displayName"] = formatted
			return nil
		case len(parts) == 1 && name == "name":
			if display == "" {
				display = primaryEmail(m)
			}
			if display != "" {
				m["name"] = map[string]any{"formatted": display}
				return nil
			}
		}
		delete(target, name)
		return nil
	}
	if value == nil {
		return invalid("invalidValue", "Patch value is required")
	}
	switch name {
	case "userName", "externalId", "displayName":
		value = single(value)
	case "active":
		// Only a JSON Boolean is unwrapped; a string Boolean must be bare.
		if list, ok := value.([]any); ok && len(list) == 1 {
			if b, ok := list[0].(bool); ok {
				value = b
			}
		}
	}
	if name == "name" && len(parts) == 1 {
		// name add and replace both merge into the stored name; unspecified
		// parts stay.
		parts, ok := value.(map[string]any)
		if !ok {
			return invalid("invalidValue", "name must be an object")
		}
		for key := range parts {
			if field(key, nameFields) == "" {
				return invalid("invalidPath", "Unsupported name subattribute "+key)
			}
		}
		newFields, err := object(parts, nameFields)
		if err != nil {
			return err
		}
		old, _ := m["name"].(map[string]any)
		merged := maps.Clone(old)
		if merged == nil {
			merged = map[string]any{}
		}
		for key, v := range newFields {
			newFields[key] = single(v)
		}
		if formatted, ok := newFields["formatted"]; ok {
			setFormatted(m, merged, formatted)
		}
		maps.Copy(merged, newFields)
		value = merged
	}
	target[name] = value
	return nil
}

// single unwraps a one-element array; Entra sends single-valued PATCH
// values that way.
func single(v any) any {
	if list, ok := v.([]any); ok && len(list) == 1 {
		return list[0]
	}
	return v
}

// primaryEmail returns the primary email address of a User document, or the
// first one.
func primaryEmail(m map[string]any) string {
	list, _ := m["emails"].([]any)
	first := ""
	for i, item := range list {
		e, _ := item.(map[string]any)
		value, _ := e["value"].(string)
		if e["primary"] == true {
			return value
		}
		if i == 0 {
			first = value
		}
	}
	return first
}

// setFormatted runs before a new formatted name is stored in name. A display
// name equal to the old formatted name was derived from it and follows the
// new one.
func setFormatted(m, name map[string]any, formatted any) {
	old, _ := name["formatted"].(string)
	if display, _ := m["displayName"].(string); old != "" && display == old {
		m["displayName"] = formatted
	}
}
