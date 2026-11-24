package scim

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
)

//go:embed discovery.json
var descriptorJSON []byte
var descriptors map[string]map[string]any

func init() {
	if err := json.Unmarshal(descriptorJSON, &descriptors); err != nil {
		panic(err)
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != h.path && !strings.HasPrefix(r.URL.Path, h.path+"/") {
		h.host.ServeHTTP(w, r)
		return
	}
	if h.host.HTTPPathDisabled(r) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", MediaType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	path := strings.TrimPrefix(r.URL.Path, h.path+"/")
	resource, id, single := strings.Cut(path, "/")
	if strings.Contains(id, "/") || strings.Contains(strings.ToLower(r.URL.EscapedPath()), "%2f") || single && id == "" {
		writeError(w, ErrNotFound)
		return
	}
	isGroup := resource == "Groups" && h.groups != nil
	if resource != "Users" && !isGroup {
		if resource != "Schemas" && resource != "ResourceTypes" && resource != "ServiceProviderConfig" {
			writeError(w, &Error{404, "", "Resource not found"})
			return
		}
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			writeError(w, &Error{405, "", "Method not allowed"})
			return
		}
		h.discovery(w, resource, id)
		return
	}
	allowed := "GET, POST"
	if single {
		allowed = "GET, PUT, PATCH, DELETE"
	}
	if !strings.Contains(", "+allowed+", ", ", "+r.Method+", ") {
		w.Header().Set("Allow", allowed)
		writeError(w, &Error{405, "", "Method not allowed"})
		return
	}
	scope := UsersRead
	if r.Method != http.MethodGet {
		scope = UsersWrite
	}
	if isGroup {
		scope = GroupsRead
		if r.Method != http.MethodGet {
			scope = GroupsWrite
		}
	}
	route := "/scim/v2/" + resource
	if single {
		if isGroup {
			route += "/:groupId"
		} else {
			route += "/:userId"
		}
	}
	identity, err := h.authorize(r, scope, route)
	if err != nil {
		writeError(w, err)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), principalKey{}, identity))
	d := identity.Directory
	if isGroup {
		h.serveGroups(w, r, d, id, single)
		return
	}
	pr, err := projectQuery(r.URL.Query(), userProjectionFields, UserSchema)
	if err != nil {
		writeError(w, err)
		return
	}
	ctx := r.Context()
	var rec Record
	switch r.Method {
	case http.MethodGet:
		if !single {
			q, err := query(r.URL.Query(), equality)
			if err != nil {
				writeError(w, err)
				return
			}
			records, total, err := h.store.SCIMList(ctx, d, q)
			if err != nil {
				writeError(w, err)
				return
			}
			items := make([]map[string]any, 0, len(records))
			for _, row := range records {
				items = append(items, pr.apply(h.user(row)))
			}
			write(w, 200, list(items, total, q.Offset+1))
			return
		}
		rec, err = h.store.SCIMGet(ctx, d, id)
	case http.MethodDelete:
		err = h.store.SCIMDelete(ctx, d, id)
		if err == nil {
			w.WriteHeader(204)
			return
		}
	default:
		var input map[string]any
		input, err = body(w, r)
		if err != nil {
			break
		}
		if r.Method == http.MethodPatch {
			var ops []any
			ops, err = patchOperations(input)
			if err == nil {
				rec, err = h.store.SCIMUpdate(ctx, d, id, func(current Record) (Profile, error) { return patchProfile(current, ops) })
			}
		} else {
			var profile Profile
			profile, err = normalize(input)
			if err != nil {
				break
			}
			if r.Method == http.MethodPost {
				// The gate sees every provisioned user, also one the directory
				// reactivates or links again, outside the store's transaction.
				check := auth.UserInfoValidation{Action: auth.UserInfoCreateUser, Method: "scim", Request: r,
					User: auth.UserRecord{User: auth.User{Name: profile.DisplayName, Email: profile.PrimaryEmail}}}
				if err = h.host.ValidateUserInfo(ctx, check); err != nil {
					break
				}
				rec, err = h.store.SCIMCreate(ctx, d, profile)
			} else {
				rec, err = h.store.SCIMUpdate(ctx, d, id, func(Record) (Profile, error) { return profile, nil })
			}
		}
	}
	if err != nil {
		writeError(w, err)
		return
	}
	location := h.base + "/Users/" + url.PathEscape(rec.ID)
	if r.Method != http.MethodGet {
		w.Header().Set("Location", location)
	}
	status := 200
	if r.Method == http.MethodPost {
		status = 201
		w.Header().Set("Content-Location", location)
	}
	write(w, status, pr.apply(h.user(rec)))
}
func body(w http.ResponseWriter, r *http.Request) (map[string]any, error) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" && media != MediaType {
		return nil, &Error{415, "", "Expected a SCIM JSON request"}
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	var result map[string]any
	if err = dec.Decode(&result); err != nil || result == nil || dec.Decode(new(any)) != io.EOF {
		return nil, invalid("invalidSyntax", "Invalid JSON request body")
	}
	return result, nil
}
func (h *Handler) user(r Record) map[string]any {
	m := profileObject(r.Profile)
	m["id"] = r.ID
	const iso = "2006-01-02T15:04:05.000Z"
	m["meta"] = map[string]any{"resourceType": "User", "location": h.base + "/Users/" + url.PathEscape(r.ID), "created": r.CreatedAt.UTC().Format(iso), "lastModified": r.UpdatedAt.UTC().Format(iso)}
	return m
}
func (h *Handler) discovery(w http.ResponseWriter, resource, id string) {
	location := h.base + "/" + resource
	if resource == "ServiceProviderConfig" {
		if id != "" {
			writeError(w, &Error{404, "", "Unknown discovery resource"})
			return
		}
		data := maps.Clone(descriptors[resource])
		data["meta"] = map[string]any{"resourceType": resource, "location": location}
		write(w, 200, data)
		return
	}
	kind, groupKey := "Schema", "GroupSchema"
	if resource == "ResourceTypes" {
		kind, groupKey = "ResourceType", "GroupResourceType"
	}
	keys := []string{resource}
	if h.groups != nil {
		keys = append(keys, groupKey)
	}
	items := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		data := maps.Clone(descriptors[k])
		key := data["id"].(string)
		data["meta"] = map[string]any{"resourceType": kind, "location": location + "/" + url.PathEscape(key)}
		if id == key {
			write(w, 200, data)
			return
		}
		items = append(items, data)
	}
	if id != "" {
		writeError(w, &Error{404, "", "Unknown discovery resource"})
		return
	}
	write(w, 200, list(items, len(items), 1))
}
func list(items []map[string]any, total, start int) map[string]any {
	return map[string]any{"schemas": []string{listSchema}, "Resources": items, "startIndex": start, "totalResults": total, "itemsPerPage": len(items)}
}
func write(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, err error) {
	var e *Error
	if refused := auth.UserInfoRefusal(err); refused != nil {
		// A SCIM error carries the refusal's message, not its code.
		e = &Error{403, "", refused.Message}
	} else if !errors.As(err, &e) {
		e = &Error{500, "", "Directory operation failed"}
	}
	if e.Status == 401 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="SCIM"`)
	}
	v := map[string]any{"schemas": []string{errorSchema}, "status": strconv.Itoa(e.Status), "detail": e.Detail}
	if e.Type != "" {
		v["scimType"] = e.Type
	}
	write(w, e.Status, v)
}
