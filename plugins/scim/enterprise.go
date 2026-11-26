package scim

import (
	"maps"
	"strings"
)

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

// enterprisePath resolves a schema-relative User PATCH path to the
// Enterprise extension: the URN, a URN-qualified attribute, the enterprise
// alias or the classic manager aliases. attr and sub are canonical names;
// attr is empty for the extension root. ok is false for another path.
func enterprisePath(path string) (attr, sub string, ok bool, err error) {
	path = strings.TrimSpace(path)
	lower := strings.ToLower(path)
	urn := strings.ToLower(EnterpriseUserSchema)
	var rel string
	switch {
	case lower == urn || lower == "enterprise":
		return "", "", true, nil
	case strings.HasPrefix(lower, urn+":"):
		rel = path[len(urn)+1:]
	case strings.HasPrefix(lower, "enterprise."):
		rel = path[len("enterprise."):]
	case lower == "manager" || strings.HasPrefix(lower, "manager."):
		rel = path
	default:
		return "", "", false, nil
	}
	unsupported := invalid("invalidPath", "User PATCH path "+path+" is not supported")
	parts := strings.Split(rel, ".")
	if attr = field(parts[0], enterpriseFields); attr == "" || len(parts) > 2 {
		return "", "", true, unsupported
	}
	if len(parts) == 2 {
		if sub = field(parts[1], managerFields); attr != "manager" || sub == "" {
			return "", "", true, unsupported
		}
	}
	return attr, sub, true, nil
}

// enterpriseReachable reports whether an Enterprise form applies to a User
// path. Behind the core User schema prefix only the enterprise alias does, as
// in another runtime; the URN forms and the manager alias do not.
func enterpriseReachable(path string, prefixed bool) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	return !prefixed || lower == "enterprise" || strings.HasPrefix(lower, "enterprise.")
}

// patchEnterprise applies an Enterprise path to the URN-keyed extension in m.
// Writes declare the URI in schemas; removing the last field removes the
// extension and its declaration. normalize then checks the values.
func patchEnterprise(m map[string]any, attr, sub, op string, value any) error {
	if sub == "displayName" {
		return invalid("mutability", "manager.displayName is read-only")
	}
	current, _ := m[EnterpriseUserSchema].(map[string]any)
	extension := maps.Clone(current)
	if attr == "" {
		if op == "remove" {
			delete(m, EnterpriseUserSchema)
			declareEnterprise(m, false)
			return nil
		}
		fields, ok := value.(map[string]any)
		if !ok {
			return invalid("invalidValue", EnterpriseUserSchema+" must be an object")
		}
		for key := range fields {
			if field(key, enterpriseFields) == "" {
				return invalid("invalidPath", "User PATCH path "+EnterpriseUserSchema+":"+key+" is not supported")
			}
		}
		patch, err := enterpriseUser(fields)
		if err != nil {
			return err
		}
		if extension == nil {
			extension = map[string]any{}
		}
		if manager, ok := patch["manager"].(map[string]any); ok {
			patch["manager"] = mergeManager(extension["manager"], manager)
		}
		maps.Copy(extension, patch)
		m[EnterpriseUserSchema] = extension
		declareEnterprise(m, true)
		return nil
	}
	if extension == nil {
		if op == "remove" {
			return nil
		}
		extension = map[string]any{}
	}
	switch {
	case sub != "":
		manager, _ := extension["manager"].(map[string]any)
		manager = maps.Clone(manager)
		switch {
		case manager == nil && op == "remove":
			return nil
		case op == "remove":
			delete(manager, sub)
		case manager == nil:
			manager = map[string]any{sub: value}
		default:
			manager[sub] = value
		}
		extension["manager"] = manager
		if len(manager) == 0 {
			delete(extension, "manager")
		}
	case op == "remove":
		delete(extension, attr)
	case attr == "manager" && value == "":
		// Entra clears the manager with an empty replace instead of a remove.
		delete(extension, "manager")
	case attr == "manager":
		manager, found, err := managerValue(value)
		if err != nil {
			return err
		}
		if !found {
			return invalid("invalidValue", "manager must contain value or $ref")
		}
		extension["manager"] = mergeManager(extension["manager"], manager)
	default:
		extension[attr] = value
	}
	if len(extension) == 0 {
		delete(m, EnterpriseUserSchema)
		declareEnterprise(m, false)
		return nil
	}
	m[EnterpriseUserSchema] = extension
	if op != "remove" {
		declareEnterprise(m, true)
	}
	return nil
}

func mergeManager(current any, patch map[string]any) map[string]any {
	stored, _ := current.(map[string]any)
	merged := maps.Clone(stored)
	if merged == nil {
		merged = map[string]any{}
	}
	maps.Copy(merged, patch)
	return merged
}

func declareEnterprise(m map[string]any, declared bool) {
	schemas := []any{UserSchema}
	if declared {
		schemas = append(schemas, EnterpriseUserSchema)
	}
	m["schemas"] = schemas
}
