package scim

var (
	enterpriseFields = []string{"employeeNumber", "costCenter", "organization", "division", "department", "manager"}
	enterpriseLimits = map[string]int{"employeeNumber": 256, "costCenter": 256, "organization": 1024, "division": 1024, "department": 1024}
	managerFields    = []string{"value", "$ref", "displayName"}
)

// userSchemas checks a User's schema URIs: the core schema once, the
// Enterprise extension at most once and nothing else, returned in that
// order. declared reports the extension.
func userSchemas(raw any) (schemas []any, declared bool, err error) {
	list, ok := raw.([]any)
	if !ok || len(list) == 0 || len(list) > 2 {
		return nil, false, invalid("invalidValue", "The core User schema is required")
	}
	core := false
	for _, s := range list {
		switch {
		case s == UserSchema && !core:
			core = true
		case s == EnterpriseUserSchema && !declared:
			declared = true
		case s == UserSchema || s == EnterpriseUserSchema:
			return nil, false, invalid("invalidValue", "A SCIM User schema must not be duplicated")
		default:
			return nil, false, invalid("invalidValue", "Unsupported SCIM User schema")
		}
	}
	if !core {
		return nil, false, invalid("invalidValue", "The core User schema is required")
	}
	schemas = []any{UserSchema}
	if declared {
		schemas = append(schemas, EnterpriseUserSchema)
	}
	return schemas, declared, nil
}

// enterpriseUser validates the Enterprise extension object of a POST, PUT
// or merged PATCH document and returns its canonical form. Scalars may be
// one-element arrays; unknown keys are ignored.
func enterpriseUser(raw any) (map[string]any, error) {
	v, err := object(raw, enterpriseFields)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for key, limit := range enterpriseLimits {
		if x, ok := v[key]; ok {
			if out[key], err = stringValue(single(x), limit); err != nil {
				return nil, err
			}
		}
	}
	if x, ok := v["manager"]; ok {
		manager, found, err := managerValue(x)
		if err != nil {
			return nil, err
		}
		if found {
			out["manager"] = manager
		}
	}
	return out, nil
}

// managerValue accepts an identifier string, an object with value or $ref,
// or a one-element array holding that object. A client-supplied displayName
// is read-only: it is checked and discarded. found is false when neither
// value nor $ref remains.
func managerValue(raw any) (manager map[string]any, found bool, err error) {
	if s, ok := raw.(string); ok {
		value, err := stringValue(s, 256)
		if err != nil {
			return nil, false, err
		}
		return map[string]any{"value": value}, true, nil
	}
	if list, ok := raw.([]any); ok {
		if len(list) != 1 {
			return nil, false, invalid("invalidValue", "manager must be one value")
		}
		raw = list[0]
	}
	v, err := object(raw, managerFields)
	if err != nil {
		return nil, false, err
	}
	manager = map[string]any{}
	for key, limit := range map[string]int{"value": 256, "$ref": 2048} {
		if x, ok := v[key]; ok {
			if manager[key], err = stringValue(x, limit); err != nil {
				return nil, false, err
			}
		}
	}
	if x, ok := v["displayName"]; ok {
		if _, err = stringValue(x, 1024); err != nil {
			return nil, false, err
		}
	}
	return manager, len(manager) > 0, nil
}

// allNull reports whether a nonempty object holds only nulls, directly or in
// nested objects. Such a complex attribute is unassigned like an omitted one.
func allNull(v any) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return false
	}
	for _, x := range m {
		if x != nil && !allNull(x) {
			return false
		}
	}
	return true
}
