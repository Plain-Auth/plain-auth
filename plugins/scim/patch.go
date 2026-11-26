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
	if len(path) > len(UserSchema) && strings.EqualFold(path[:len(UserSchema)+1], UserSchema+":") {
		path = path[len(UserSchema)+1:]
	}
	if readOnlyUserPath(strings.TrimSpace(path)) {
		return invalid("mutability", "The targeted User attribute is read-only")
	}
	if isRolePath(path) {
		return patchRole(m, path, op, value)
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
			if joined := strings.TrimSpace(given + " " + family); joined != "" {
				setFormatted(m, target, joined)
				target["formatted"] = joined
				return nil
			}
		}
		value = single(value)
		if sub == "formatted" && op != "remove" {
			setFormatted(m, target, value)
		}
	}
	if op == "remove" {
		if name == "userName" {
			return invalid("mutability", "userName is required")
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

// setFormatted runs before a new formatted name is stored in name. A display
// name equal to the old formatted name was derived from it and follows the
// new one.
func setFormatted(m, name map[string]any, formatted any) {
	old, _ := name["formatted"].(string)
	if display, _ := m["displayName"].(string); old != "" && display == old {
		m["displayName"] = formatted
	}
}
