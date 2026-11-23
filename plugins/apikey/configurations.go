package apikey

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"time"

	plainauth "github.com/Plain-Org/plain-auth"
)

// NewPlugin shares management routes among independently configured key types.
func NewPlugin(services ...*Service) (plainauth.Plugin, error) {
	if len(services) == 0 {
		return plainauth.Plugin{}, errors.New("apikey: at least one configuration is required")
	}
	services = slices.Clone(services)
	byID := map[string]*Service{}
	for _, s := range services {
		if s == nil || byID[s.opts.ConfigID] != nil {
			return plainauth.Plugin{}, errors.New("apikey: nil or duplicate configuration")
		}
		byID[s.opts.ConfigID] = s
	}
	p := plainauth.Plugin{ID: "api-key", CredentialSessions: sessionResolver(services), ValidateStore: func(host plainauth.Store) error {
		for _, s := range services {
			if s.opts.EnableSession && (!reflect.ValueOf(s.opts.Store).Comparable() || any(host) != any(s.opts.Store)) {
				return errors.New("apikey: session authentication requires the host's own store")
			}
			if err := s.opts.Store.CheckAPIKeySchema(context.Background()); err != nil {
				return err
			}
		}
		return nil
	}}
	for _, r := range []struct{ method, path string }{{"POST", "create"}, {"POST", "update"}, {"GET", "get"}, {"GET", "list"}, {"POST", "delete"}} {
		p.Endpoints = append(p.Endpoints, plainauth.Endpoint{Method: r.method, Path: "/api-key/" + r.path, Handler: func(c plainauth.EndpointContext) (any, error) {
			id := c.Request.URL.Query().Get("configId")
			if c.Request.Method == http.MethodPost {
				var e error
				id, e = stringValue(c.Body, "configId")
				if e != nil {
					return nil, e
				}
			}
			if id == "" && r.path == "list" && len(services) > 1 {
				return listConfigurations(c, services)
			}
			s := byID[id]
			if id == "" {
				s = byID["default"]
				if len(services) == 1 {
					s = services[0]
				}
			}
			if s == nil {
				return nil, ErrMissing
			}
			if s.opts.Organization != nil && !c.Auth.HasPlugin("organization") {
				return nil, ErrOrgPlugin
			}
			return s.handle(c, r.path)
		}})
	}
	return p, nil
}
func listConfigurations(c plainauth.EndpointContext, services []*Service) (*Page, error) {
	session, e := c.Auth.GetSession(c.Request.Context(), c.Request.Header)
	if e != nil {
		return nil, e
	}
	if session == nil {
		return nil, ErrSession
	}
	if e = session.Session.RequireOwner(); e != nil {
		return nil, e
	}
	q := c.Request.URL.Query()
	o := PageOptions{OrganizationID: q.Get("organizationId"), SortBy: q.Get("sortBy"), SortDirection: q.Get("sortDirection")}
	out := Page{Keys: []Key{}}
	for name, dst := range map[string]**int{"limit": &out.Limit, "offset": &out.Offset} {
		if q.Has(name) {
			n, e := strconv.Atoi(q.Get(name))
			if e != nil || n < 0 {
				return nil, invalidField(name)
			}
			*dst = &n
		}
	}
	for _, s := range services {
		if (s.opts.Organization != nil) != (o.OrganizationID != "") {
			continue
		}
		if s.opts.Organization != nil && !c.Auth.HasPlugin("organization") {
			return nil, ErrOrgPlugin
		}
		p, e := s.list(c.Request.Context(), Owner{UserID: session.User.ID, SessionToken: session.Session.Token}, o)
		if e != nil {
			return nil, e
		}
		out.Keys = append(out.Keys, p.Keys...)
		out.Total += p.Total
	}
	slices.SortStableFunc(out.Keys, func(a, b Key) int {
		c := compareKey(a, b, o.SortBy)
		if o.SortDirection == "desc" {
			c = -c
		}
		if c == 0 {
			c = cmp.Compare(a.ID, b.ID)
		}
		return c
	})
	if out.Offset != nil {
		out.Keys = out.Keys[min(*out.Offset, len(out.Keys)):]
	}
	if out.Limit != nil {
		out.Keys = out.Keys[:min(*out.Limit, len(out.Keys))]
	}
	return &out, nil
}
func compareKey(a, b Key, field string) int {
	date := func(v *time.Time) time.Time {
		if v != nil {
			return *v
		}
		return time.Time{}
	}
	switch field {
	case "name":
		var x, y string
		if a.Name != nil {
			x = *a.Name
		}
		if b.Name != nil {
			y = *b.Name
		}
		return cmp.Compare(x, y)
	case "id":
		return cmp.Compare(a.ID, b.ID)
	case "updatedAt":
		return a.UpdatedAt.Compare(b.UpdatedAt)
	case "expiresAt":
		return date(a.ExpiresAt).Compare(date(b.ExpiresAt))
	case "lastRequest":
		return date(a.LastRequest).Compare(date(b.LastRequest))
	case "requestCount":
		return cmp.Compare(a.RequestCount, b.RequestCount)
	case "remaining":
		var x, y int64 = -1, -1
		if a.Remaining != nil {
			x = *a.Remaining
		}
		if b.Remaining != nil {
			y = *b.Remaining
		}
		return cmp.Compare(x, y)
	case "enabled":
		if a.Enabled == b.Enabled {
			return 0
		}
		if a.Enabled {
			return 1
		}
		return -1
	default:
		return a.CreatedAt.Compare(b.CreatedAt)
	}
}
