package apikey

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	stonewrit "github.com/Stonewrit/stonewrit-auth"
)

// Plugin exposes session-authorized management routes. Verification and
// expired-key cleanup are trusted Go methods on the Service.
func (s *Service) Plugin() stonewrit.Plugin {
	p := stonewrit.Plugin{ID: "api-key", ValidateStore: func(store stonewrit.Store) error {
		return s.opts.Store.CheckAPIKeySchema(context.Background())
	}}
	for _, r := range []struct{ method, path string }{{"POST", "create"}, {"POST", "update"}, {"GET", "get"}, {"GET", "list"}, {"POST", "delete"}} {
		p.Endpoints = append(p.Endpoints, stonewrit.Endpoint{Method: r.method, Path: "/api-key/" + r.path, Handler: func(c stonewrit.EndpointContext) (any, error) { return s.handle(c, r.path) }})
	}
	return p
}
func invalidField(k string) error { return problem(400, "VALIDATION_ERROR", "Invalid "+k) }
func stringValue(body map[string]any, k string) (string, error) {
	v, ok := body[k]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", invalidField(k)
	}
	return s, nil
}
func (s *Service) handle(c stonewrit.EndpointContext, action string) (any, error) {
	r, ctx := c.Request, c.Request.Context()
	session, err := c.Auth.GetSession(ctx, r.Header)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, ErrSession
	}
	if err = session.Session.RequireOwner(); err != nil {
		return nil, err
	}
	owner := Owner{UserID: session.User.ID, SessionToken: session.Session.Token}
	q := r.URL.Query()
	body := c.Body
	config := q.Get("configId")
	if r.Method == http.MethodPost {
		config, err = stringValue(body, "configId")
		if err != nil {
			return nil, err
		}
	}
	if config != "" && config != s.opts.ConfigID {
		return nil, ErrMissing
	}
	if q.Has("organizationId") {
		return nil, invalidField("organizationId")
	}
	for k := range body {
		switch k {
		case "userId":
			if action != "update" || body[k] != owner.UserID {
				return nil, ErrSession
			}
		case "permissions", "refillAmount", "refillInterval", "rateLimitMax", "rateLimitTimeWindow", "rateLimitEnabled", "remaining":
			return nil, problem(400, "SERVER_ONLY_PROPERTY", "This property is restricted to server code")
		case "organizationId":
			return nil, invalidField(k)
		}
	}
	switch action {
	case "get":
		return s.manage(ctx, owner, q.Get("id"), Read, UpdateInput{})
	case "list":
		o := PageOptions{SortBy: q.Get("sortBy"), SortDirection: q.Get("sortDirection")}
		for k, dst := range map[string]**int{"limit": &o.Limit, "offset": &o.Offset} {
			if q.Has(k) {
				v, e := strconv.Atoi(q.Get(k))
				if e != nil || v < 0 {
					return nil, invalidField(k)
				}
				*dst = &v
			}
		}
		return s.list(ctx, owner, o)
	case "delete":
		id, e := stringValue(body, "keyId")
		if e != nil {
			return nil, e
		}
		_, e = s.manage(ctx, owner, id, Remove, UpdateInput{})
		return map[string]bool{"success": true}, e
	}
	up := UpdateInput{}
	if _, ok := body["name"]; ok {
		name, e := stringValue(body, "name")
		if e != nil {
			return nil, e
		}
		up.Name = &name
	}
	if val, ok := body["expiresIn"]; ok {
		var d time.Duration
		if val != nil {
			n, ok := val.(json.Number)
			if !ok {
				return nil, invalidField("expiresIn")
			}
			secs, e := n.Int64()
			if e != nil || secs < 1 || secs > int64((1<<63-1)/time.Second) {
				return nil, invalidField("expiresIn")
			}
			d = time.Duration(secs) * time.Second
		}
		up.ExpiresIn = &d
	}
	if val, ok := body["metadata"]; ok && val != nil {
		data, ok := val.(map[string]any)
		if !ok {
			return nil, problem(400, "INVALID_METADATA_TYPE", "Metadata must be an object")
		}
		up.Metadata = data
	}
	if action == "create" {
		prefix, e := stringValue(body, "prefix")
		if e != nil {
			return nil, e
		}
		in := CreateInput{Prefix: prefix, Metadata: up.Metadata}
		if up.Name != nil {
			in.Name = *up.Name
		}
		if up.ExpiresIn != nil {
			in.ExpiresIn = *up.ExpiresIn
		}
		return s.create(ctx, owner, in)
	}
	id, e := stringValue(body, "keyId")
	if e != nil {
		return nil, e
	}
	if val, ok := body["enabled"]; ok {
		enabled, ok := val.(bool)
		if !ok {
			return nil, invalidField("enabled")
		}
		up.Policy.Enabled = &enabled
	}
	return s.manage(ctx, owner, id, Save, up)
}
