package scim

import (
	"context"
	"encoding/json"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	GroupSchema       = "urn:ietf:params:scim:schemas:core:2.0:Group"
	GroupsRead        = "scim.groups.read"
	GroupsWrite       = "scim.groups.write"
	MaxGroupMembers   = 1000
	legacyGroupSchema = "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"
)

type GroupProfile struct {
	DisplayName, ExternalID string
	MemberIDs               []string
}

// GroupChange describes the desired resource at the end of a transaction.
// ValidateIDs includes every added User in a PATCH, even a later removal.
// PreserveUnchanged leaves the modification time intact for an idempotent PATCH.
type GroupChange struct {
	GroupProfile
	ValidateIDs       []string
	PreserveUnchanged bool
}
type GroupMember struct{ ID, DisplayName string }
type Group struct {
	ID, DisplayName, ExternalID string
	CreatedAt, UpdatedAt        time.Time
	Members                     []GroupMember
}

// GroupStore adds Groups to a directory store. When absent, discovery lists
// only Users. Implementations must validate member ownership in the write transaction.
type GroupStore interface {
	SCIMGetGroup(context.Context, Directory, string, bool) (Group, error)
	SCIMListGroups(context.Context, Directory, Query, bool) ([]Group, int, error)
	SCIMCreateGroup(context.Context, Directory, GroupProfile) (Group, error)
	SCIMUpdateGroup(context.Context, Directory, string, func(Group) (GroupChange, error)) (Group, error)
	SCIMDeleteGroup(context.Context, Directory, string) error
}

var ErrGroupNotFound = &Error{Status: 404, Detail: "SCIM Group not found"}
var ErrInvalidMember = &Error{Status: 400, Type: "invalidValue", Detail: "One or more Group members are invalid"}

var groupFields = strings.Fields("schemas id meta displayName externalId members")
var memberPath = regexp.MustCompile(`(?i)^members\s*\[\s*value\s+eq\s+("(?:\\.|[^"\\])*")\s*\]$`)

func members(raw any) ([]string, error) {
	items, ok := raw.([]any)
	if !ok || len(items) > MaxGroupMembers {
		return nil, invalid("invalidValue", "Expected an array of up to 1000 direct User members")
	}
	result := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, raw := range items {
		m, e := object(raw, []string{"value", "type"})
		if e != nil {
			return nil, e
		}
		id, ok := m["value"].(string)
		if !ok || strings.TrimSpace(id) == "" {
			return nil, ErrInvalidMember
		}
		if m["type"] != nil {
			kind, ok := m["type"].(string)
			if !ok || !strings.EqualFold(kind, "User") {
				return nil, ErrInvalidMember
			}
		}
		if !seen[id] {
			result = append(result, id)
			seen[id] = true
		}
	}
	return result, nil
}
func parseGroup(input map[string]any, allowLegacy bool) (GroupProfile, error) {
	var p GroupProfile
	if _, ok := input[legacyGroupSchema]; ok {
		return p, invalid("invalidValue", "The compatibility schema cannot contain attributes")
	}
	m, e := object(input, groupFields)
	if e != nil {
		return p, e
	}
	schemas, ok := m["schemas"].([]any)
	if !ok {
		return p, invalid("invalidValue", "The core Group schema is required")
	}
	core, legacy := 0, 0
	for _, schema := range schemas {
		switch schema {
		case GroupSchema:
			core++
		case legacyGroupSchema:
			legacy++
		default:
			return p, invalid("invalidValue", "Unsupported Group schema")
		}
	}
	if core != 1 || legacy > 1 || legacy > 0 && !allowLegacy {
		return p, invalid("invalidValue", "Invalid Group schema list")
	}
	if str, ok := m["displayName"].(string); ok {
		p.DisplayName = strings.TrimSpace(str)
	}
	if p.DisplayName == "" {
		return p, invalid("invalidValue", "displayName is required")
	}
	if m["externalId"] != nil {
		var ok bool
		p.ExternalID, ok = m["externalId"].(string)
		if !ok || p.ExternalID == "" {
			return p, invalid("invalidValue", "Invalid externalId")
		}
	}
	if m["members"] != nil {
		p.MemberIDs, e = members(m["members"])
	}
	return p, e
}

func groupOperations(raw map[string]any) ([]any, error) {
	// The Entra marker is honoured only on Group creation.
	for key := range raw {
		if strings.EqualFold(key, legacyGroupSchema) {
			return nil, invalid("invalidValue", "The compatibility schema cannot contain attributes")
		}
	}
	m, e := object(raw, []string{"schemas", "Operations"})
	if e != nil {
		return nil, e
	}
	schemas, ok := m["schemas"].([]any)
	if !ok || len(schemas) != 1 || schemas[0] != PatchSchema {
		return nil, invalid("invalidSyntax", "The PatchOp schema is required")
	}
	ops, ok := m["Operations"].([]any)
	if !ok {
		return nil, invalid("invalidSyntax", "Operations must be an array")
	}
	return ops, nil
}
func withoutSchema(path, urn string) string {
	path = strings.TrimSpace(path)
	if len(path) > len(urn) && strings.EqualFold(path[:len(urn)+1], urn+":") {
		return path[len(urn)+1:]
	}
	return path
}

type groupPatch struct {
	group         GroupProfile
	ids, validate map[string]bool
}

func (g *groupPatch) attribute(path, op string, val any, provided bool) error {
	path = withoutSchema(path, GroupSchema)
	if sel := memberPath.FindStringSubmatch(path); len(sel) > 0 && op == "remove" {
		var id string
		if json.Unmarshal([]byte(sel[1]), &id) != nil || id == "" {
			return invalid("invalidPath", "Invalid member selector")
		}
		delete(g.ids, id)
		return nil
	}
	if strings.EqualFold(path, "members") {
		if op == "remove" && !provided {
			clear(g.ids)
			return nil
		}
		entries, e := members(val)
		if e != nil {
			return e
		}
		if op == "replace" {
			clear(g.ids)
		}
		for _, id := range entries {
			if op == "remove" {
				delete(g.ids, id)
			} else {
				g.ids[id] = true
				g.validate[id] = true
			}
		}
		return nil
	}
	if strings.HasPrefix(strings.ToLower(path), "meta.") || strings.EqualFold(path, "meta") || strings.EqualFold(path, "id") || strings.EqualFold(path, "schemas") {
		return invalid("mutability", "The targeted Group attribute is read-only")
	}
	if !strings.EqualFold(path, "displayName") && !strings.EqualFold(path, "externalId") {
		return invalid("invalidPath", "Unsupported Group PATCH path")
	}
	if op == "remove" {
		if strings.EqualFold(path, "displayName") {
			return invalid("mutability", "displayName is required")
		}
		g.group.ExternalID = ""
		return nil
	}
	if a, ok := val.([]any); ok && len(a) == 1 {
		val = a[0]
	}
	str, ok := val.(string)
	str = strings.TrimSpace(str)
	if !ok || str == "" {
		return invalid("invalidValue", "Expected a non-empty Group attribute")
	}
	if strings.EqualFold(path, "displayName") {
		g.group.DisplayName = str
	} else {
		g.group.ExternalID = str
	}
	return nil
}
func applyGroupPatch(current Group, ops []any) (GroupChange, error) {
	g := groupPatch{group: GroupProfile{DisplayName: current.DisplayName, ExternalID: current.ExternalID}, ids: map[string]bool{}, validate: map[string]bool{}}
	for _, m := range current.Members {
		g.ids[m.ID] = true
	}
	for _, raw := range ops {
		record, ok := raw.(map[string]any)
		if !ok {
			return GroupChange{}, invalid("invalidSyntax", "Expected a Group patch operation")
		}
		m, e := object(record, []string{"op", "path", "value"})
		if e != nil {
			return GroupChange{}, e
		}
		op := "replace"
		if m["op"] != nil {
			str, _ := m["op"].(string)
			op = strings.ToLower(str)
		}
		if op != "remove" && op != "replace" && op != "add" {
			return GroupChange{}, invalid("invalidSyntax", "Unknown Group patch operation")
		}
		path := ""
		if m["path"] != nil {
			var ok bool
			path, ok = m["path"].(string)
			if !ok {
				return GroupChange{}, invalid("invalidPath", "Expected a Group attribute path")
			}
			path = strings.TrimSpace(path)
		}
		var val any
		provided := false
		for k, v := range record {
			if strings.EqualFold(k, "value") {
				val = v
				provided = true
			}
		}
		if path != "" {
			if provided && val == nil {
				op = "remove"
				provided = false
			}
			if e = g.attribute(path, op, val, provided); e != nil {
				return GroupChange{}, e
			}
			continue
		}
		if op == "remove" {
			return GroupChange{}, invalid("noTarget", "A pathless remove has no target")
		}
		values, ok := val.(map[string]any)
		if !ok {
			return GroupChange{}, invalid("invalidValue", "Expected a pathless Group attribute map")
		}
		for k, v := range values {
			switch strings.ToLower(k) {
			case "id":
				if v != current.ID {
					return GroupChange{}, invalid("mutability", "Cannot change Group id")
				}
				continue
			case "schemas", "meta":
				continue
			}
			action := op
			if v == nil {
				action = "remove"
			}
			if e = g.attribute(k, action, v, v != nil); e != nil {
				return GroupChange{}, e
			}
		}
	}
	if len(g.ids) > MaxGroupMembers {
		return GroupChange{}, invalid("invalidValue", "Too many direct Group members")
	}
	g.group.MemberIDs = slices.Sorted(maps.Keys(g.ids))
	return GroupChange{GroupProfile: g.group, ValidateIDs: slices.Sorted(maps.Keys(g.validate)), PreserveUnchanged: true}, nil
}
