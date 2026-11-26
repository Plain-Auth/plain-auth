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
func patchProfile(r Record, ops []any) (Profile, error) {
	m := profileObject(r.Profile)
	for _, raw := range ops {
		v, err := object(raw, []string{"op", "path", "value"})
		if err != nil {
			return Profile{}, err
		}
		op := "replace"
		if v["op"] != nil {
			o, ok := v["op"].(string)
			if !ok {
				return Profile{}, invalid("invalidSyntax", "Expected a patch operation")
			}
			op = strings.ToLower(o)
		}
		if op != "add" && op != "replace" && op != "remove" {
			return Profile{}, invalid("invalidSyntax", "Unsupported patch operation")
		}
		path := ""
		if v["path"] != nil {
			var ok bool
			path, ok = v["path"].(string)
			if !ok {
				return Profile{}, invalid("invalidPath", "Expected an attribute path")
			}
			path = strings.TrimSpace(path)
		}
		if path == "" && op == "remove" {
			return Profile{}, invalid("noTarget", "A pathless remove has no target")
		}
		if path == "" {
			// An empty map is a no-op.
			fields, ok := v["value"].(map[string]any)
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
				if err = patchValue(m, name, op, fields[name]); err != nil {
					return Profile{}, err
				}
			}
		} else if op != "remove" && v["value"] == nil && isRolePath(withoutSchema(path, UserSchema)) {
			// object drops null fields. An explicit null unassigns this role path,
			// while a write with a missing value is invalid.
			fields, _ := raw.(map[string]any)
			if !hasRolePatchValue(fields) {
				return Profile{}, invalid("invalidValue", "Patch value is required")
			}
			if err = patchValue(m, path, "remove", nil); err != nil {
				return Profile{}, err
			}
		} else if err = patchValue(m, path, op, v["value"]); err != nil {
			return Profile{}, err
		}
	}
	return normalize(m)
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
		if value == nil {
			op = "remove"
		}
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

func hasRolePatchValue(fields map[string]any) bool {
	for k := range fields {
		if strings.EqualFold(k, "value") {
			return true
		}
	}
	return false
}
