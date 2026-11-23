package plainauth

import (
	"bytes"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// Middleware runs Run before the endpoint hooks for each HTTP request whose
// mount-relative path matches Path. It can reject, rewrite or answer a
// request like a before hook.
//
// Path is an exact path such as "/sign-in/email", or a pattern where "*" or
// ":name" matches one segment and a final "**" matches any remaining
// segments, such as "/organization/**" or "/**". Broader patterns run first:
// "/**", then "/x/**", then "/x/*", then exact paths, in plugin order within
// each.
type Middleware struct {
	Path string
	Run  func(*HookContext) error
}

func validMiddleware(m Middleware, plugin string) error {
	segments := strings.Split(m.Path, "/")
	if m.Run == nil || !strings.HasPrefix(m.Path, "/") {
		return fmt.Errorf("auth: plugin %s middleware needs a path starting with / and Run", plugin)
	}
	for i, segment := range segments {
		if segment == "**" && i != len(segments)-1 {
			return fmt.Errorf("auth: plugin %s middleware path %s may use ** only at the end", plugin, m.Path)
		}
	}
	return nil
}

// middlewareHooks returns every plugin's middleware as before hooks, broadest pattern first.
func middlewareHooks(plugins []Plugin) []boundHook {
	type entry struct {
		hook        boundHook
		prefix, way int
	}
	var all []entry
	for _, p := range plugins {
		for _, m := range p.Middleware {
			prefix, way := middlewareRank(m.Path)
			pattern := m.Path
			all = append(all, entry{boundHook{EndpointHook{
				Match: func(c *HookContext) bool { return pathMatches(pattern, c.requestPath) },
				Run:   m.Run,
			}, "plugin:" + p.ID}, prefix, way})
		}
	}
	slices.SortStableFunc(all, func(a, b entry) int {
		if a.prefix != b.prefix {
			return a.prefix - b.prefix
		}
		return a.way - b.way
	})
	hooks := make([]boundHook, len(all))
	for i, e := range all {
		hooks[i] = e.hook
	}
	return hooks
}

// middlewareRank orders a pattern by its literal segments before the first
// wildcard, then by "**", one-segment wildcards and exact paths.
func middlewareRank(pattern string) (prefix, way int) {
	segments := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	way = 2
	for _, segment := range segments {
		if segment == "**" {
			return prefix, 0
		}
		if segment == "*" || strings.HasPrefix(segment, ":") {
			way = 1
		} else if way == 2 {
			prefix++
		}
	}
	return prefix, way
}

// pathMatches reports whether a Middleware pattern matches a mount-relative path.
func pathMatches(pattern, path string) bool {
	want, got := strings.Split(pattern, "/"), strings.Split(path, "/")
	for i, segment := range want {
		switch {
		case segment == "**":
			return true
		case i >= len(got):
			return false
		case segment == "*" || strings.HasPrefix(segment, ":"):
			if got[i] == "" {
				return false
			}
		case segment != got[i]:
			return false
		}
	}
	return len(want) == len(got)
}

// ResponseContext describes a response before it is written. OnResponse may
// change Status, Header and Body.
type ResponseContext struct {
	Request *http.Request
	// Path is the request's path relative to the auth mount.
	Path   string
	Status int
	Header http.Header
	Body   []byte
}

// bufferedResponse holds a response until the OnResponse hooks have run.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}

func (b *bufferedResponse) Write(p []byte) (int, error) {
	b.WriteHeader(http.StatusOK)
	return b.body.Write(p)
}

func (a *Auth) finishResponse(w http.ResponseWriter, b *bufferedResponse, r *http.Request, route string) {
	c := &ResponseContext{Request: r, Path: route, Status: b.status, Header: b.header, Body: b.body.Bytes()}
	if c.Status == 0 {
		c.Status = http.StatusOK
	}
	for _, p := range a.opts.Plugins {
		if p.OnResponse != nil {
			p.OnResponse(c)
		}
	}
	w.WriteHeader(c.Status)
	_, _ = w.Write(c.Body)
}
