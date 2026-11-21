package scim

import (
	"net/http"
	"net/url"
	"strings"
)

var groupProjectionFields = append(append([]string{}, groupFields...), strings.Fields("members.value members.display members.type members.$ref meta.resourceType meta.created meta.lastModified meta.location")...)

func (p projection) selectGroupField(parent, child string) bool {
	if p.fields == nil {
		return true
	}
	if p.include {
		return p.fields[parent] || p.fields[parent+"."+child]
	}
	return !p.fields[parent] && !p.fields[parent+"."+child]
}
func (p projection) groupMembers() bool {
	if p.fields == nil || !p.include {
		return !p.fields["members"]
	}
	if p.fields["members"] {
		return true
	}
	for k := range p.fields {
		if strings.HasPrefix(k, "members.") {
			return true
		}
	}
	return false
}
func (h *Handler) groupResource(g Group, p projection) map[string]any {
	loc := h.base + "/Groups/" + url.PathEscape(g.ID)
	m := map[string]any{"schemas": []string{GroupSchema}, "id": g.ID}
	for field, val := range map[string]string{"displayName": g.DisplayName, "externalId": g.ExternalID} {
		if val != "" && (p.fields == nil || p.fields[field] == p.include) {
			m[field] = val
		}
	}
	const iso = "2006-01-02T15:04:05.000Z"
	meta := map[string]any{"resourceType": "Group", "location": loc, "created": g.CreatedAt.UTC().Format(iso), "lastModified": g.UpdatedAt.UTC().Format(iso)}
	for k := range meta {
		if !p.selectGroupField("meta", k) {
			delete(meta, k)
		}
	}
	if len(meta) > 0 || !p.include && !p.fields["meta"] {
		m["meta"] = meta
	}
	if p.groupMembers() {
		rows := make([]map[string]string, 0, len(g.Members))
		for _, v := range g.Members {
			item := map[string]string{"value": v.ID, "display": v.DisplayName, "type": "User", "$ref": h.base + "/Users/" + url.PathEscape(v.ID)}
			for k := range item {
				if !p.selectGroupField("members", k) {
					delete(item, k)
				}
			}
			if len(item) > 0 || !p.include {
				rows = append(rows, item)
			}
		}
		if len(rows) > 0 || !p.include || p.fields["members"] {
			m["members"] = rows
		}
	}
	return m
}
func (h *Handler) serveGroups(w http.ResponseWriter, r *http.Request, d Directory, id string, single bool) {
	p, e := projectQuery(r.URL.Query(), groupProjectionFields, GroupSchema)
	if e != nil {
		writeError(w, e)
		return
	}
	ctx := r.Context()
	var g Group
	switch r.Method {
	case http.MethodGet:
		if !single {
			q, e := query(r.URL.Query(), groupEquality)
			if e != nil {
				writeError(w, e)
				return
			}
			rows, total, e := h.groups.SCIMListGroups(ctx, d, q, p.groupMembers())
			if e != nil {
				writeError(w, e)
				return
			}
			items := make([]map[string]any, 0, len(rows))
			for _, v := range rows {
				items = append(items, h.groupResource(v, p))
			}
			write(w, 200, list(items, total, q.Offset+1))
			return
		}
		g, e = h.groups.SCIMGetGroup(ctx, d, id, p.groupMembers())
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
				g, e = h.groups.SCIMUpdateGroup(ctx, d, id, func(current Group) (GroupChange, error) { return applyGroupPatch(current, ops) })
			}
		} else {
			var v GroupProfile
			v, e = parseGroup(input, r.Method == http.MethodPost && h.legacyGroup)
			if e != nil {
				break
			}
			if r.Method == http.MethodPost {
				g, e = h.groups.SCIMCreateGroup(ctx, d, v)
			} else {
				g, e = h.groups.SCIMUpdateGroup(ctx, d, id, func(Group) (GroupChange, error) { return GroupChange{GroupProfile: v}, nil })
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
	write(w, status, h.groupResource(g, p))
}
