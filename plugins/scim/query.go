package scim

import (
	"encoding/json"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Plain-Org/plain-auth/internal/jsjson"
)

var equality = regexp.MustCompile(`(?i)^(?:urn:ietf:params:scim:schemas:core:2\.0:user:)?(id|userName|externalId|emails\.value|emails\[\s*type\s+eq\s+"work"\s*\]\.value)\s+eq\s+("(?:[^"\\]|\\.)*")(?:\s+(and)\s+|$)`)

var groupEquality = regexp.MustCompile(`(?i)^(?:urn:ietf:params:scim:schemas:core:2\.0:group:)?(id|displayName|externalId)\s+eq\s+("(?:[^"\\]|\\.)*")(?:\s+(and)\s+|$)`)

func query(values url.Values, equality *regexp.Regexp) (Query, error) {
	var q Query
	page := map[string]int{"startIndex": 1, "count": 100}
	for k := range page {
		if list, ok := values[k]; ok {
			if len(list) != 1 {
				return q, invalid("invalidValue", "Expected one "+k)
			}
			n, err := strconv.ParseInt(strings.TrimSpace(list[0]), 10, 53)
			if err != nil {
				return q, invalid("invalidValue", k+" must be an integer")
			}
			page[k] = int(n)
		}
	}
	q.Offset = max(1, page["startIndex"]) - 1
	q.Count = min(100, max(0, page["count"]))
	f := strings.TrimSpace(values.Get("filter"))
	for f != "" {
		match := equality.FindStringSubmatch(f)
		if match == nil || len(q.Filters) >= 10 {
			return q, invalid("invalidFilter", "Expected a supported equality filter")
		}
		k := strings.ToLower(match[1])
		if strings.HasPrefix(k, "emails[") {
			k = "emails.work.value"
		}
		var v string
		if err := json.Unmarshal([]byte(match[2]), &v); err != nil || strings.TrimSpace(v) == "" {
			return q, invalid("invalidFilter", "Invalid filter value")
		}
		q.Filters = append(q.Filters, Filter{k, strings.TrimSpace(v)})
		f = f[len(match[0]):]
		if match[3] != "" && f == "" {
			return q, invalid("invalidFilter", "Missing equality expression")
		}
	}
	return q, nil
}

// selection holds an attributes or excludedAttributes parameter as
// lowercased response paths. schemas and id are always returned, and an
// unknown path selects nothing. A nil paths slice returns the whole resource.
type selection struct {
	include bool
	paths   []string
}

// selectionQuery reads the two mutually exclusive selection parameters. An
// empty value counts as absent.
func selectionQuery(q url.Values, schema string) (selection, error) {
	include, err := selectionParam(q, "attributes", schema)
	if err != nil {
		return selection{}, err
	}
	exclude, err := selectionParam(q, "excludedAttributes", schema)
	if err != nil {
		return selection{}, err
	}
	if include != nil && exclude != nil {
		return selection{}, invalid("invalidValue", "attributes and excludedAttributes cannot be used together")
	}
	if include != nil {
		return selection{include: true, paths: include}, nil
	}
	return selection{paths: exclude}, nil
}

func selectionParam(q url.Values, key, schema string) ([]string, error) {
	var paths []string
	for _, value := range q[key] {
		if jsjson.TrimSpace(value) == "" {
			continue
		}
		for _, part := range strings.Split(value, ",") {
			part = jsjson.TrimSpace(part)
			if part == "" || strings.ContainsFunc(part, jsjson.IsSpace) {
				return nil, invalid("invalidValue", key+" must be a comma-separated list of attribute paths")
			}
			paths = append(paths, responsePath(part, schema))
		}
	}
	return paths, nil
}

// responsePath lowercases a selection path relative to the resource. An
// Enterprise path is the URN, a dot and the attribute path, and the classic
// manager alias selects the Enterprise manager.
func responsePath(part, schema string) string {
	lower := strings.ToLower(part)
	if schema == UserSchema {
		urn := strings.ToLower(EnterpriseUserSchema)
		switch {
		case lower == "manager" || strings.HasPrefix(lower, "manager."):
			return urn + "." + lower
		case lower == urn:
			return urn
		case strings.HasPrefix(lower, urn+":"):
			return urn + "." + lower[len(urn)+1:]
		}
	}
	return strings.ToLower(withoutSchema(part, schema))
}

// returns reports whether the selection can return any part of a top-level
// attribute, so a store can skip loading it.
func (s selection) returns(attribute string) bool {
	if s.paths == nil {
		return true
	}
	attribute = strings.ToLower(attribute)
	for _, p := range s.paths {
		if s.include && (p == attribute || strings.HasPrefix(p, attribute+".")) {
			return true
		}
		if !s.include && p == attribute {
			return false
		}
	}
	return !s.include
}

type pathNode struct {
	selected bool
	children map[string]*pathNode
}

func (n *pathNode) child(key string) *pathNode {
	if n.children == nil {
		n.children = map[string]*pathNode{}
	}
	c := n.children[key]
	if c == nil {
		c = &pathNode{}
		n.children[key] = c
	}
	return c
}

// pathTree splits each path into segments. A path's first segment is the
// longest resource attribute it starts with, since an attribute name such as
// a schema URN can contain dots.
func pathTree(paths []string, names []string) *pathNode {
	slices.SortFunc(names, func(a, b string) int { return len(b) - len(a) })
	root := &pathNode{}
	for _, path := range paths {
		var segments []string
		for _, name := range names {
			lower := strings.ToLower(name)
			if path == lower || strings.HasPrefix(path, lower+".") {
				segments = []string{lower}
				path = strings.TrimPrefix(path[len(lower):], ".")
				break
			}
		}
		if path != "" {
			segments = append(segments, strings.Split(path, ".")...)
		}
		node := root
		for _, segment := range segments {
			node = node.child(segment)
		}
		node.selected = true
	}
	return root
}

// apply returns the selected parts of a resource; keys match
// case-insensitively and keep their spelling.
func (s selection) apply(resource map[string]any) map[string]any {
	if s.paths == nil {
		return resource
	}
	root := pathTree(s.paths, slices.Collect(maps.Keys(resource)))
	out := map[string]any{"schemas": resource["schemas"], "id": resource["id"]}
	for key, value := range resource {
		lower := strings.ToLower(key)
		if lower == "schemas" || lower == "id" {
			continue
		}
		node := root.children[lower]
		switch {
		case node == nil && !s.include:
			out[key] = value
		case node == nil:
		case s.include:
			if v, ok := pick(value, node); ok {
				out[key] = v
			}
		default:
			if v, ok := omit(value, node); ok {
				out[key] = v
			}
		}
	}
	return out
}

// pick keeps the selected parts of a value; arrays select per entry.
func pick(value any, node *pathNode) (any, bool) {
	if node.selected {
		return value, true
	}
	switch v := value.(type) {
	case []any:
		var out []any
		for _, item := range v {
			if x, ok := pick(item, node); ok {
				out = append(out, x)
			}
		}
		return out, len(out) > 0
	case map[string]any:
		out := map[string]any{}
		for key, child := range v {
			if n := node.children[strings.ToLower(key)]; n != nil {
				if x, ok := pick(child, n); ok {
					out[key] = x
				}
			}
		}
		return out, len(out) > 0
	}
	return nil, false
}

// omit drops the selected parts of a value; arrays keep their entries.
func omit(value any, node *pathNode) (any, bool) {
	if node.selected {
		return nil, false
	}
	switch v := value.(type) {
	case []any:
		out := []any{}
		for _, item := range v {
			if x, ok := omit(item, node); ok {
				out = append(out, x)
			}
		}
		return out, true
	case map[string]any:
		out := map[string]any{}
		for key, child := range v {
			n := node.children[strings.ToLower(key)]
			if n == nil {
				out[key] = child
				continue
			}
			if x, ok := omit(child, n); ok {
				out[key] = x
			}
		}
		return out, true
	}
	return value, true
}
