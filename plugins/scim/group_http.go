package scim

import (
	"net/http"
	"net/url"
)

// groupResource builds a Group; members says whether they were loaded.
func (h *Handler) groupResource(g Group, members bool) map[string]any {
	loc := h.base + "/Groups/" + url.PathEscape(g.ID)
	m := map[string]any{"schemas": []string{GroupSchema}, "id": g.ID}
	for field, val := range map[string]string{"displayName": g.DisplayName, "externalId": g.ExternalID} {
		if val != "" {
			m[field] = val
		}
	}
	const iso = "2006-01-02T15:04:05.000Z"
	m["meta"] = map[string]any{"resourceType": "Group", "location": loc, "created": g.CreatedAt.UTC().Format(iso), "lastModified": g.UpdatedAt.UTC().Format(iso)}
	if members {
		rows := make([]any, 0, len(g.Members))
		for _, v := range g.Members {
			rows = append(rows, map[string]any{"value": v.ID, "display": v.DisplayName, "type": "User", "$ref": h.base + "/Users/" + url.PathEscape(v.ID)})
		}
		m["members"] = rows
	}
	return m
}
func (h *Handler) serveGroups(w http.ResponseWriter, r *http.Request, d Directory, id string, single bool) {
	// A read checks its projection last, after the Group lookup or the page
	// and filter, a write after its body and binding, and a deletion takes
	// none, as in another runtime.
	p, selectErr := selectionQuery(r.URL.Query(), GroupSchema)
	var e error
	ctx := r.Context()
	var g Group
	switch r.Method {
	case http.MethodGet:
		if !single {
			q, e := query(r.URL.Query(), groupEquality)
			if e == nil {
				e = selectErr
			}
			if e != nil {
				writeError(w, e)
				return
			}
			rows, total, e := h.groups.SCIMListGroups(ctx, d, q, p.returns("members"))
			if e != nil {
				writeError(w, e)
				return
			}
			items := make([]map[string]any, 0, len(rows))
			for _, v := range rows {
				items = append(items, p.apply(h.groupResource(v, p.returns("members"))))
			}
			write(w, 200, list(items, total, q.Offset+1))
			return
		}
		if g, e = h.groups.SCIMGetGroup(ctx, d, id, selectErr != nil || p.returns("members")); e == nil {
			e = selectErr
		}
	case http.MethodDelete:
		e = h.groups.SCIMDeleteGroup(ctx, d, id)
		if e == nil {
			w.WriteHeader(204)
			return
		}
	default:
		var input map[string]any
		input, e = body(w, r)
		if e != nil {
			break
		}
		if r.Method == http.MethodPatch {
			var ops []any
			ops, e = groupOperations(input)
			if e == nil {
				// Two spellings are refused before the Group is looked up, as
				// another runtime does on the request body.
				e = groupOpsDuplicates(ops)
			}
			if e == nil {
				e = groupOpShapes(ops)
			}
			if e == nil {
				e = h.bound(ctx, d, selectErr)
			}
			if e == nil {
				g, e = h.groups.SCIMUpdateGroup(ctx, d, id, func(current Group) (GroupChange, error) { return applyGroupPatch(current, ops) })
			}
		} else {
			var v GroupProfile
			v, e = parseGroup(input, r.Method == http.MethodPost && h.legacyGroup)
			if e != nil {
				break
			}
			if e = h.bound(ctx, d, selectErr); e != nil {
				break
			}
			if r.Method == http.MethodPost {
				if e = blankMembers(v); e != nil {
					break
				}
				g, e = h.groups.SCIMCreateGroup(ctx, d, v)
			} else {
				g, e = h.groups.SCIMUpdateGroup(ctx, d, id, func(Group) (GroupChange, error) {
					if e := blankMembers(v); e != nil {
						return GroupChange{}, e
					}
					return GroupChange{GroupProfile: v}, nil
				})
			}
		}
	}
	if e != nil {
		writeError(w, e)
		return
	}
	status := 200
	location := h.base + "/Groups/" + url.PathEscape(g.ID)
	if r.Method != http.MethodGet {
		w.Header().Set("Location", location)
	}
	if r.Method == http.MethodPost {
		status = 201
		w.Header().Set("Content-Location", location)
	}
	write(w, status, p.apply(h.groupResource(g, p.returns("members"))))
}
