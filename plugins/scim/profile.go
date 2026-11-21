package scim

import (
	"maps"
	"net/mail"
	"strings"
	"unicode/utf16"

	"github.com/Stonewrit/stonewrit-auth/internal/jsjson"
)

var userFields = strings.Fields("schemas userName displayName externalId name emails active title userType preferredLanguage locale timezone roles")
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
	for k, v := range m {
		if v == nil {
			continue
		}
		name := field(k, allowed)
		if name == "" {
			continue
		}
		if _, ok := out[name]; ok {
			return nil, invalid("invalidValue", "Duplicate attribute "+name)
		}
		out[name] = v
	}
	return out, nil
}
func stringValue(v any, max int) (string, error) {
	str, ok := v.(string)
	str = strings.TrimSpace(str)
	if !ok || str == "" || len(utf16.Encode([]rune(str))) > max {
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
		v, err := object(item, emailFields)
		if err != nil {
			return nil, "", err
		}
		address, err := stringValue(v["value"], 254)
		if err != nil {
			return nil, "", err
		}
		address = strings.ToLower(address)
		parsed, parseErr := mail.ParseAddress(address)
		_, domain, hasAt := strings.Cut(address, "@")
		if parseErr != nil || parsed.Address != address || !hasAt || !strings.Contains(domain, ".") {
			return nil, "", invalid("invalidValue", "Invalid email address")
		}
		v["value"] = address
		var typ string
		if v["type"] != nil {
			typ, err = stringValue(v["type"], 256)
			if err != nil {
				return nil, "", err
			}
			typ = strings.ToLower(typ)
			if types[typ] {
				return nil, "", invalid("invalidValue", "Duplicate email type")
			}
			types[typ] = true
			v["type"] = typ
			if typ == "work" {
				work = i
			}
		}
		key := [2]string{typ, address}
		if pairs[key] {
			return nil, "", invalid("invalidValue", "Duplicate email")
		}
		pairs[key] = true
		if v["primary"] != nil {
			b, err := boolValue(v["primary"])
			if err != nil {
				return nil, "", err
			}
			if b {
				if primary >= 0 {
					return nil, "", invalid("invalidValue", "Multiple primary emails")
				}
				primary = i
			}
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
	if m, ok := input.(map[string]any); ok {
		for key, value := range m {
			if strings.EqualFold(key, "active") && value == nil {
				return p, invalid("invalidValue", "active cannot be null")
			}
			if value != nil && field(key, []string{"phoneNumbers", "addresses", "entitlements", "enterprise"}) != "" {
				return p, invalid("invalidValue", "Unsupported User attribute "+key)
			}
		}
	}
	m, err := object(input, userFields)
	if err != nil {
		return p, err
	}
	schemas, ok := m["schemas"].([]any)
	if !ok || len(schemas) != 1 || schemas[0] != UserSchema {
		return p, invalid("invalidValue", "The core User schema is required")
	}
	p.UserName, err = stringValue(m["userName"], 512)
	if err != nil {
		return p, err
	}
	var emails []any
	emails, p.PrimaryEmail, err = emailValues(m["emails"], p.UserName)
	if err != nil {
		return p, err
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
	}
	if m["displayName"] != nil {
		p.DisplayName, err = stringValue(m["displayName"], 1024)
		if err != nil {
			return p, err
		}
	}
	if m["externalId"] != nil {
		p.ExternalID, err = stringValue(m["externalId"], 1024)
		if err != nil {
			return p, err
		}
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
	}
	p.Attributes = map[string]any{"schemas": schemas, "name": name, "emails": emails}
	if raw, provided := m["roles"]; provided {
		roles, err := normalizeRoles(raw)
		if err != nil {
			return p, err
		}
		p.Attributes["roles"] = roles
		m["roles"] = roles
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
		}
	}
	if _, hasRoles := p.Attributes["roles"]; hasRoles {
		// Bound both the normalized wire document and the canonical payload a
		// second directory server will read from serializedAttributes.
		for _, document := range []map[string]any{m, p.Attributes} {
			encoded, err := jsjson.Marshal(document)
			if err != nil || len(utf16.Encode([]rune(string(encoded)))) > 65_535 {
				return p, invalid("invalidValue", "SCIM User attributes exceed the supported serialized size")
			}
		}
	}
	return p, nil
}
func profileObject(p Profile) map[string]any {
	m := maps.Clone(p.Attributes)
	m["userName"], m["displayName"], m["active"] = p.UserName, p.DisplayName, p.Active
	if p.ExternalID != "" {
		m["externalId"] = p.ExternalID
	}
	return m
}
