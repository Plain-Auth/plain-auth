package scim

import (
	"maps"
	"net/mail"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Plain-Org/plain-auth/internal/jsjson"
)

var userFields = append(strings.Fields("schemas userName displayName externalId name emails active title userType preferredLanguage locale timezone phoneNumbers addresses roles entitlements"), EnterpriseUserSchema)
var nameFields = strings.Fields("formatted givenName familyName middleName honorificPrefix honorificSuffix")
var emailFields = strings.Fields("type primary value")

func field(name string, allowed []string) string {
	for _, v := range allowed {
		if strings.EqualFold(name, v) {
			return v
		}
	}
	return ""
}

func object(input any, allowed []string) (map[string]any, error) {
	m, ok := input.(map[string]any)
	if !ok {
		return nil, invalid("invalidValue", "Expected an object")
	}
	out := make(map[string]any, len(m))
	seen := make(map[string]bool, len(m))
	for k, v := range m {
		name := field(k, allowed)
		if name == "" {
			continue
		}
		// RFC 7643 names are case-insensitive, so two spellings name one
		// attribute, null or not.
		if seen[name] {
			return nil, invalid("invalidSyntax", "Duplicate attribute "+name)
		}
		seen[name] = true
		if v != nil {
			out[name] = v
		}
	}
	return out, nil
}

// stringValue trims a string like JavaScript and bounds it in code points,
// as another runtime counts its limits.
func stringValue(v any, maxRunes int) (string, error) {
	str, ok := v.(string)
	str = jsjson.TrimSpace(str)
	if !ok || str == "" || utf8.RuneCountInString(str) > maxRunes {
		return "", invalid("invalidValue", "Invalid string attribute")
	}
	return str, nil
}
func boolValue(v any) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case string:
		if strings.EqualFold(x, "true") {
			return true, nil
		}
		if strings.EqualFold(x, "false") {
			return false, nil
		}
	}
	return false, invalid("invalidValue", "Expected a Boolean")
}

// emailEntry checks one email value and returns it with its value and type
// lowercased, its type and value pair, and whether it claims primary.
func emailEntry(item any) (map[string]any, [2]string, bool, error) {
	v, err := object(item, emailFields)
	if err != nil {
		return nil, [2]string{}, false, err
	}
	address, err := stringValue(v["value"], 254)
	if err != nil {
		return nil, [2]string{}, false, err
	}
	address = strings.ToLower(address)
	parsed, parseErr := mail.ParseAddress(address)
	_, domain, hasAt := strings.Cut(address, "@")
	if parseErr != nil || parsed.Address != address || !hasAt || !strings.Contains(domain, ".") {
		return nil, [2]string{}, false, invalid("invalidValue", "Invalid email address")
	}
	v["value"] = address
	var typ string
	if v["type"] != nil {
		if typ, err = stringValue(v["type"], 256); err != nil {
			return nil, [2]string{}, false, err
		}
		typ = strings.ToLower(typ)
		v["type"] = typ
	}
	primary := false
	if v["primary"] != nil {
		if primary, err = boolValue(v["primary"]); err != nil {
			return nil, [2]string{}, false, err
		}
	}
	return v, [2]string{typ, address}, primary, nil
}

func emailValues(raw any, user string) ([]any, string, error) {
	items, ok := raw.([]any)
	if raw != nil && !ok || len(items) > 20 {
		return nil, "", invalid("invalidValue", "Invalid emails")
	}
	if len(items) == 0 {
		items = []any{map[string]any{"value": user}}
	}
	out := make([]any, 0, len(items))
	pairs, types := map[[2]string]bool{}, map[string]bool{}
	primary, work := -1, -1
	for i, item := range items {
		v, key, first, err := emailEntry(item)
		if err != nil {
			return nil, "", err
		}
		if typ := key[0]; v["type"] != nil {
			if types[typ] {
				return nil, "", invalid("invalidValue", "Duplicate email type")
			}
			types[typ] = true
			if typ == "work" {
				work = i
			}
		}
		if pairs[key] {
			return nil, "", invalid("invalidValue", "Duplicate email")
		}
		pairs[key] = true
		if first {
			if primary >= 0 {
				return nil, "", invalid("invalidValue", "Multiple primary emails")
			}
			primary = i
		}
		v["primary"] = false
		out = append(out, v)
	}
	if primary < 0 {
		primary = max(0, work)
	}
	chosen := out[primary].(map[string]any)
	chosen["primary"] = true
	return out, chosen["value"].(string), nil
}

func normalize(input any) (p Profile, err error) {
	m, err := object(input, userFields)
	if err != nil {
		return p, err
	}
	if m, ok := input.(map[string]any); ok {
		for key, value := range m {
			if strings.EqualFold(key, "active") && value == nil {
				return p, invalid("invalidValue", "active cannot be null")
			}
		}
	}
	schemas, declared, err := userSchemas(m["schemas"])
	if err != nil {
		return p, err
	}
	p.UserName, err = stringValue(m["userName"], 512)
	if err != nil {
		return p, err
	}
	// parsed holds the submitted attributes after parsing, without derived
	// values, as another runtime bounds them.
	parsed := map[string]any{"schemas": schemas, "userName": p.UserName}
	var emails []any
	emails, p.PrimaryEmail, err = emailValues(m["emails"], p.UserName)
	if err != nil {
		return p, err
	}
	if m["emails"] != nil {
		parsed["emails"] = emails
	}
	name := map[string]any{}
	if m["name"] != nil {
		name, err = object(m["name"], nameFields)
		if err != nil {
			return p, err
		}
		for k, v := range name {
			limit := 256
			if k == "formatted" {
				limit = 1024
			}
			name[k], err = stringValue(v, limit)
			if err != nil {
				return p, err
			}
		}
		parsed["name"] = maps.Clone(name)
	}
	if m["displayName"] != nil {
		p.DisplayName, err = stringValue(m["displayName"], 1024)
		if err != nil {
			return p, err
		}
		parsed["displayName"] = p.DisplayName
	}
	if m["externalId"] != nil {
		p.ExternalID, err = stringValue(m["externalId"], 1024)
		if err != nil {
			return p, err
		}
		parsed["externalId"] = p.ExternalID
	}
	if name["formatted"] == nil {
		label := p.DisplayName
		if label == "" {
			given, _ := name["givenName"].(string)
			family, _ := name["familyName"].(string)
			label = strings.TrimSpace(given + " " + family)
		}
		if label == "" {
			label = p.PrimaryEmail
		}
		name["formatted"] = label
	}
	if p.DisplayName == "" {
		p.DisplayName = name["formatted"].(string)
	}
	p.Active = true
	if m["active"] != nil {
		p.Active, err = boolValue(m["active"])
		if err != nil {
			return p, err
		}
		parsed["active"] = p.Active
	}
	p.Attributes = map[string]any{"schemas": schemas, "name": name, "emails": emails}
	if raw, ok := m[EnterpriseUserSchema]; ok {
		// Read even an all-null object, so two spellings of one field are
		// refused, null or not.
		extension, err := enterpriseUser(raw)
		if err != nil {
			return p, err
		}
		if !allNull(raw) {
			if !declared {
				return p, invalid("invalidValue", "The Enterprise User extension requires its schema URI")
			}
			p.Attributes["enterprise"] = extension
			parsed[EnterpriseUserSchema] = extension
		}
	}
	for _, a := range multiValuedAttributes {
		if raw, provided := m[a.name]; provided {
			values, err := a.normalize(raw)
			if err != nil {
				return p, err
			}
			p.Attributes[a.name] = values
			parsed[a.name] = values
		}
	}
	for _, k := range []string{"title", "userType", "preferredLanguage", "locale", "timezone"} {
		if v := m[k]; v != nil {
			if a, ok := v.([]any); ok && len(a) == 1 {
				v = a[0]
			}
			limit := 256
			if k == "title" {
				limit = 1024
			}
			p.Attributes[k], err = stringValue(v, limit)
			if err != nil {
				return p, err
			}
			parsed[k] = p.Attributes[k]
		}
	}
	// Bound both the parsed document and the canonical payload a second
	// directory server will read from serializedAttributes.
	for _, document := range []map[string]any{parsed, p.Attributes} {
		encoded, err := jsjson.Marshal(document)
		if err != nil || len(utf16.Encode([]rune(string(encoded)))) > 65_535 {
			return p, invalid("invalidValue", "SCIM User attributes exceed the supported serialized size")
		}
	}
	return p, nil
}

// profileObject returns a profile as a User document; the Enterprise
// extension stored under its canonical key is sent under its URN.
func profileObject(p Profile) map[string]any {
	m := maps.Clone(p.Attributes)
	if extension, ok := m["enterprise"]; ok {
		delete(m, "enterprise")
		m[EnterpriseUserSchema] = extension
	}
	m["userName"], m["displayName"], m["active"] = p.UserName, p.DisplayName, p.Active
	if p.ExternalID != "" {
		m["externalId"] = p.ExternalID
	}
	return m
}
