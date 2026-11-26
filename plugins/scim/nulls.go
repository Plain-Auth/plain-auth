package scim

import (
	"maps"
	"slices"
	"strings"
)

// RFC 7643 section 2.5 makes a JSON null an unassigned attribute. A PATCH
// leaves an omitted attribute unchanged, so a null add or replace value
// becomes an explicit removal instead.

// patchOp is one parsed PATCH operation. hasValue tells a null value, which
// removes its target, from a missing one.
type patchOp struct {
	op, path string
	value    any
	hasValue bool
}

// nullKind says how a null PATCH value at a path applies.
type nullKind int

const (
	nullRemove  nullKind = iota // the null removes its target
	nullInvalid                 // the attribute cannot be null
	nullEntries                 // whole multi-valued entries; null subattributes are dropped
	nullMerge                   // a complex value merged into the stored one
	nullIgnored                 // a read-only attribute; the null is ignored
)

// userNullTarget says how a null at a User path applies, and for a merged
// value the prefix of its subattribute paths. An unsupported path removes,
// so its operation still reports the path error.
func userNullTarget(path string) (nullKind, string) {
	relative := withoutSchema(path, UserSchema)
	if attr, sub, ok, err := enterprisePath(relative); ok && err == nil && enterpriseReachable(relative, relative != strings.TrimSpace(path)) {
		// Only the bare enterprise alias joins its attributes with "."; the
		// URN and a core-prefixed alias use ":", as in another runtime.
		separator := ":"
		if strings.EqualFold(strings.TrimSpace(path), "enterprise") {
			separator = "."
		}
		switch {
		case attr == "":
			return nullMerge, strings.TrimSpace(path) + separator
		case sub == "displayName":
			return nullIgnored, ""
		case attr == "manager" && sub == "":
			return nullMerge, strings.TrimSpace(path) + "."
		}
		return nullRemove, ""
	}
	switch {
	case strings.EqualFold(relative, "active"):
		return nullInvalid, ""
	case strings.EqualFold(relative, "name"):
		return nullMerge, strings.TrimSpace(path) + "."
	case strings.EqualFold(relative, "emails"):
		return nullEntries, ""
	}
	if _, ok := multiValuedNamed(relative); ok {
		return nullEntries, ""
	}
	return nullRemove, ""
}

// expandNulls turns null add and replace values into removals that run after
// the operation's other keys, and drops null subattributes of whole
// multi-valued values.
func expandNulls(ops []patchOp) ([]patchOp, error) {
	out := make([]patchOp, 0, len(ops))
	for _, o := range ops {
		if o.op == "remove" {
			out = append(out, o)
			continue
		}
		kind, prefix := nullRemove, ""
		if o.path != "" {
			kind, prefix = userNullTarget(o.path)
			switch {
			case o.hasValue && o.value == nil:
				removal, err := nullRemoval(o.path, kind)
				if err != nil {
					return nil, err
				}
				out = append(out, removal...)
				continue
			case kind == nullEntries:
				o.value = stripNulls(o.value, 0)
				out = append(out, o)
				continue
			case kind != nullMerge:
				out = append(out, o)
				continue
			}
		}
		record, _ := o.value.(map[string]any)
		if kind == nullMerge {
			record = singleRecord(o.value)
		}
		if record == nil {
			out = append(out, o)
			continue
		}
		kept, removals, err := splitNulls(record, prefix)
		if err != nil {
			return nil, err
		}
		// Keep an operation whose value was empty to begin with, so it still
		// fails or does nothing as before.
		if len(kept) > 0 || len(record) == 0 {
			o.value = keepShape(o.value, kept)
			out = append(out, o)
		}
		out = append(out, removals...)
	}
	return out, nil
}

// splitNulls separates a merged value's null keys, as removals of prefix plus
// the key, from the keys it keeps. Keys are visited in sorted order, as a
// pathless value applies them, except that a formatted name is removed last
// so the name it composes sees the other removals.
func splitNulls(record map[string]any, prefix string) (map[string]any, []patchOp, error) {
	kept := map[string]any{}
	var removals []patchOp
	keys := slices.SortedFunc(maps.Keys(record), func(a, b string) int {
		if fa, fb := isFormatted(a), isFormatted(b); fa != fb {
			if fa {
				return 1
			}
			return -1
		}
		return strings.Compare(a, b)
	})
	for _, key := range keys {
		entry := record[key]
		switch entry.(type) {
		case nil, map[string]any, []any:
		default:
			kept[key] = entry
			continue
		}
		path := prefix + key
		kind, sub := userNullTarget(path)
		if entry == nil {
			removal, err := nullRemoval(path, kind)
			if err != nil {
				return nil, nil, err
			}
			removals = append(removals, removal...)
			continue
		}
		if nested := singleRecord(entry); kind == nullMerge && nested != nil {
			value, more, err := splitNulls(nested, sub)
			if err != nil {
				return nil, nil, err
			}
			removals = append(removals, more...)
			if len(value) > 0 || len(nested) == 0 {
				kept[key] = keepShape(entry, value)
			}
			continue
		}
		if kind == nullEntries {
			entry = stripNulls(entry, 0)
		}
		kept[key] = entry
	}
	return kept, removals, nil
}

// isFormatted reports a key naming a formatted name, as formatted or
// name.formatted.
func isFormatted(key string) bool {
	i := strings.LastIndexAny(key, ".:")
	return strings.EqualFold(strings.TrimSpace(key[i+1:]), "formatted")
}

func nullRemoval(path string, kind nullKind) ([]patchOp, error) {
	switch kind {
	case nullInvalid:
		return nil, invalid("invalidValue", path+" cannot be null")
	case nullIgnored:
		return nil, nil
	}
	return []patchOp{{op: "remove", path: path}}, nil
}

// singleRecord reads an object, or the one object Entra may wrap in an array.
func singleRecord(v any) map[string]any {
	if list, ok := v.([]any); ok && len(list) == 1 {
		v = list[0]
	}
	m, _ := v.(map[string]any)
	return m
}

// keepShape returns value in the shape of original: wrapped in an array when
// original was a one-element array.
func keepShape(original any, value map[string]any) any {
	if _, ok := original.([]any); ok {
		return []any{value}
	}
	return value
}

// stripNulls removes null object keys to a depth of 32 and drops an object
// that removal emptied.
func stripNulls(v any, depth int) any {
	if depth > 32 {
		return v
	}
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, entry := range x {
			out[i] = stripNulls(entry, depth+1)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for key, entry := range x {
			if entry == nil {
				continue
			}
			stripped := stripNulls(entry, depth+1)
			// A complex attribute whose subattributes were all null is
			// unassigned too.
			if before, ok := entry.(map[string]any); ok && len(before) > 0 && len(stripped.(map[string]any)) == 0 {
				continue
			}
			out[key] = stripped
		}
		return out
	}
	return v
}
