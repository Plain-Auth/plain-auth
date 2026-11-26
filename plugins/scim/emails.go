package scim

import (
	"maps"
	"regexp"
	"strings"
)

var (
	emailTypePath    = regexp.MustCompile(`(?i)^emails\s*\[\s*type\s+eq\s+"([^"]+)"\s*\]\s*\.\s*value$`)
	emailPrimaryPath = regexp.MustCompile(`(?i)^emails\s*\[\s*primary\s+eq\s+"?true"?\s*\]\s*\.\s*value$`)
)

// isEmailPath reports a schema-relative path under emails.
func isEmailPath(path string) bool {
	path = strings.TrimSpace(path)
	if len(path) < len("emails") || !strings.EqualFold(path[:len("emails")], "emails") {
		return false
	}
	rest := path[len("emails"):]
	return rest == "" || strings.ContainsAny(rest[:1], ".[ \t")
}

// patchEmails applies the supported email paths: the collection,
// emails.value, a type-selected value and the primary value. Other email
// paths return invalidPath. Each operation leaves the emails normalized, with
// a primary chosen, so the next operation in the request selects from them.
func patchEmails(m map[string]any, path, op string, value any) error {
	stored := storedEmails(m)
	switch {
	case strings.EqualFold(path, "emails"):
		if op == "remove" {
			return invalid("invalidValue", "emails cannot be removed")
		}
		list, ok := value.([]any)
		if !ok || len(list) == 0 || len(list) > 20 {
			// A bare object is refused too; another runtime needs an array.
			return invalid("invalidValue", "emails must contain between 1 and 20 valid emails")
		}
		if op == "replace" {
			return setEmails(m, list)
		}
		return addEmails(m, stored, list)
	case strings.EqualFold(path, "emails.value"):
		if op == "remove" {
			return invalid("invalidValue", "emails.value cannot be removed")
		}
		for _, e := range stored {
			e["value"] = value
		}
	case emailPrimaryPath.MatchString(path):
		if op == "remove" {
			return invalid("invalidValue", "emails.value cannot be removed")
		}
		found := false
		for _, e := range stored {
			if e["primary"] == true {
				e["value"], found = value, true
			}
		}
		if !found {
			return invalid("noTarget", "No primary email matches the PATCH path")
		}
	default:
		match := emailTypePath.FindStringSubmatch(path)
		if match == nil {
			return invalid("invalidPath", "User PATCH path "+path+" is not supported")
		}
		selector := strings.ToLower(strings.TrimSpace(match[1]))
		kept, found := stored[:0:0], false
		for _, e := range stored {
			if e["type"] != selector {
				kept = append(kept, e)
				continue
			}
			found = true
			if op != "remove" {
				e["value"] = value
				kept = append(kept, e)
			}
		}
		switch {
		case op == "remove" && !found:
			return nil
		case op == "remove" && len(kept) == 0:
			return invalid("invalidValue", "emails must contain at least one value")
		case !found:
			// A selector miss appends the email: Entra replaces addresses it
			// has not created yet.
			kept = append(kept, map[string]any{"value": value, "type": selector, "primary": false})
		}
		stored = kept
	}
	if op != "remove" {
		if _, ok := value.(string); !ok {
			return invalid("invalidValue", "emails.value must be an email")
		}
	}
	return setEmails(m, entries(stored))
}

// addEmails appends the type and value pairs not stored yet. Added
// duplicates coalesce, and an added primary clears primary on the stored
// emails.
func addEmails(m map[string]any, stored []map[string]any, list []any) error {
	seen := map[[2]string]bool{}
	for _, e := range stored {
		typ, _ := e["type"].(string)
		address, _ := e["value"].(string)
		seen[[2]string{typ, address}] = true
	}
	var added []map[string]any
	at := map[[2]string]int{}
	primaries := 0
	for _, item := range list {
		v, key, primary, err := emailEntry(item)
		if err != nil {
			return err
		}
		v["primary"] = primary
		if i, ok := at[key]; ok {
			if primary && added[i]["primary"] != true {
				added[i]["primary"] = true
				primaries++
			}
			continue
		}
		at[key] = len(added)
		added = append(added, v)
		if primary {
			primaries++
		}
	}
	if primaries > 1 {
		return invalid("invalidValue", "emails cannot contain multiple primary values")
	}
	fresh := added[:0:0]
	demote := false
	for _, v := range added {
		typ, _ := v["type"].(string)
		if !seen[[2]string{typ, v["value"].(string)}] {
			fresh = append(fresh, v)
			demote = demote || v["primary"] == true
		}
	}
	if len(fresh) == 0 {
		return nil
	}
	if demote {
		for _, e := range stored {
			e["primary"] = false
		}
	}
	return setEmails(m, entries(append(stored, fresh...)))
}

// storedEmails copies the stored entries, so a PATCH never writes into the
// record it started from.
func storedEmails(m map[string]any) []map[string]any {
	list, _ := m["emails"].([]any)
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if e, ok := item.(map[string]any); ok {
			out = append(out, maps.Clone(e))
		}
	}
	return out
}

// setEmails stores a nonempty email list normalized as normalize stores it:
// lowercased values and types, checked pairs and types, one primary.
func setEmails(m map[string]any, list []any) error {
	emails, _, err := emailValues(list, "")
	if err != nil {
		return err
	}
	m["emails"] = emails
	return nil
}

func entries(emails []map[string]any) []any {
	list := make([]any, len(emails))
	for i, e := range emails {
		list[i] = e
	}
	return list
}
