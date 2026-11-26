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

// VerifyAny verifies secret with the one listed service whose configuration
// issued it, applying that configuration's validator, permissions, budget and
// rate limit as Verify does. The services must share one store that finds a
// key's configuration by digest, as the SQL store does. A secret that none of
// them issued, or whose digest is held more than once across their
// configurations, is INVALID_API_KEY and uses nothing.
func VerifyAny(ctx context.Context, secret string, required Permissions, services ...*Service) (Verification, error) {
	if len(services) == 0 {
		return Verification{}, errors.New("apikey: at least one configuration is required")
	}
	byID := map[string]*Service{}
	var ids []string
	first := services[0]
	for _, s := range services {
		if s == nil || byID[s.opts.ConfigID] != nil {
			return Verification{}, errors.New("apikey: nil or duplicate configuration")
		}
		if !reflect.ValueOf(s.opts.Store).Comparable() || any(s.opts.Store) != any(first.opts.Store) {
			return Verification{}, errors.New("apikey: unscoped verification requires services that share one store")
		}
		byID[s.opts.ConfigID] = s
		ids = append(ids, s.opts.ConfigID)
	}
	finder, ok := first.opts.Store.(configurationStore)
	if !ok {
		return Verification{}, errors.New("apikey: unscoped verification requires a store that finds a key's configuration")
	}
	unknown := Verification{Error: &VerifyError{Code: "INVALID_API_KEY", Message: "Invalid API key."}}
	if secret == "" || len(secret) > 4096 {
		return unknown, nil
	}
	id, err := finder.UniqueSessionKeyConfiguration(ctx, Digest(secret), ids)
	if err != nil {
		return Verification{}, err
	}
	// No match, or a digest held more than once, fails closed before any
	// validator runs.
	if id == "" {
		return unknown, nil
	}
	return byID[id].Verify(ctx, secret, required)
}

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
			// A list without configId merges every configuration, so it
			// needs no default one.
			if id == "" && r.path == "list" {
				return listConfigurations(c, services)
			}
			s := byID[id]
			if id == "" {
				if s = byID["default"]; s == nil {
					return nil, ErrNoDefaultConfiguration
				}
			}
			// An unknown configId answers KEY_NOT_FOUND, where the other
			// runtime falls back to the default configuration, so a request
			// never acts on a configuration it did not name.
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
		return nil, errSignIn
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
	var applicable []*Service
	for _, s := range services {
		if (s.opts.Organization != nil) != (o.OrganizationID != "") {
			continue
		}
		if s.opts.Organization != nil && !c.Auth.HasPlugin("organization") {
			return nil, ErrOrgPlugin
		}
		applicable = append(applicable, s)
	}
	ctx, owner := c.Request.Context(), Owner{UserID: session.User.ID, SessionToken: session.Session.Token}
	switch len(applicable) {
	case 0:
		// No configuration owns keys of the requested kind. An organization
		// filter is refused as it is under a named personal configuration.
		if o.OrganizationID != "" {
			return nil, invalidField("organizationId")
		}
		return &out, nil
	case 1:
		// One configuration pages in the store, in the database's order.
		o.Limit, o.Offset = out.Limit, out.Offset
		p, e := applicable[0].list(ctx, owner, o)
		if e != nil {
			return nil, e
		}
		return &p, nil
	}
	for _, s := range applicable {
		p, e := s.listKeys(ctx, owner, o)
		if e != nil {
			return nil, e
		}
		out.Keys = append(out.Keys, p.Keys...)
		out.Total += p.Total
	}
	// One sweep after every configuration has been read, so the page counts
	// the keys it shows.
	applicable[0].sweep(ctx)
	// Several configurations merge here, ordering text by its bytes, where a
	// database may use a case-insensitive collation for one configuration.
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

// compareKey orders two keys by field as the store does: missing values
// first, then values by their bytes or numbers, createdAt by default.
func compareKey(a, b Key, field string) int {
	text := func(x, y *string) int { return nilFirst(x, y, cmp.Compare[string]) }
	number := func(x, y *int64) int { return nilFirst(x, y, cmp.Compare[int64]) }
	date := func(x, y *time.Time) int { return nilFirst(x, y, time.Time.Compare) }
	flag := func(x, y bool) int {
		if x == y {
			return 0
		}
		if x {
			return 1
		}
		return -1
	}
	switch field {
	case "id":
		return cmp.Compare(a.ID, b.ID)
	case "configId":
		return cmp.Compare(a.ConfigID, b.ConfigID)
	case "referenceId":
		return cmp.Compare(a.ReferenceID, b.ReferenceID)
	case "name":
		return text(a.Name, b.Name)
	case "prefix":
		return text(a.Prefix, b.Prefix)
	case "start":
		return text(a.Start, b.Start)
	case "enabled":
		return flag(a.Enabled, b.Enabled)
	case "rateLimitEnabled":
		return flag(a.RateLimitEnabled, b.RateLimitEnabled)
	case "rateLimitTimeWindow":
		return number(a.RateLimitTimeWindow, b.RateLimitTimeWindow)
	case "rateLimitMax":
		return number(a.RateLimitMax, b.RateLimitMax)
	case "requestCount":
		return cmp.Compare(a.RequestCount, b.RequestCount)
	case "remaining":
		return number(a.Remaining, b.Remaining)
	case "refillInterval":
		return number(a.RefillInterval, b.RefillInterval)
	case "refillAmount":
		return number(a.RefillAmount, b.RefillAmount)
	case "lastRefillAt":
		return date(a.LastRefillAt, b.LastRefillAt)
	case "lastRequest":
		return date(a.LastRequest, b.LastRequest)
	case "expiresAt":
		return date(a.ExpiresAt, b.ExpiresAt)
	case "updatedAt":
		return a.UpdatedAt.Compare(b.UpdatedAt)
	default:
		return a.CreatedAt.Compare(b.CreatedAt)
	}
}

func nilFirst[T any](x, y *T, compare func(T, T) int) int {
	switch {
	case x == nil && y == nil:
		return 0
	case x == nil:
		return -1
	case y == nil:
		return 1
	}
	return compare(*x, *y)
}
