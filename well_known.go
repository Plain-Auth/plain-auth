package plainauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// WellKnownDocument is a JSON discovery response, captured at host initialization.
// Headers may customize caching and cross-origin access.
type WellKnownDocument struct {
	Body    json.RawMessage
	Headers http.Header
}

func (a *Auth) prepareWellKnown() error {
	for _, plugin := range a.opts.Plugins {
		if plugin.WellKnown == nil {
			continue
		}
		docs, err := plugin.WellKnown(a, a.opts.Store)
		if err != nil {
			return err
		}
		for path, doc := range docs {
			u, err := url.ParseRequestURI(path)
			if err != nil || u.EscapedPath() != path || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") ||
				!strings.Contains(path, "/.well-known/") || slices.Contains(strings.Split(u.Path, "/"), "..") {
				return fmt.Errorf("auth: invalid discovery path %q", path)
			}
			if _, ok := a.wellKnown[path]; ok {
				return fmt.Errorf("auth: duplicate discovery path %q", path)
			}
			if a.HTTPPathDisabled(&http.Request{URL: u}) {
				continue
			}
			if route, mounted := strings.CutPrefix(path, strings.TrimRight(a.opts.BasePath, "/")); mounted {
				for key := range a.plugins {
					if key.path == route {
						return fmt.Errorf("auth: discovery path %q overlaps an existing endpoint", path)
					}
				}
				if _, ok := coreMethods[route]; ok {
					return fmt.Errorf("auth: discovery path %q overlaps an existing endpoint", path)
				}
			}
			body := bytes.TrimSpace(doc.Body)
			if !json.Valid(body) || body[0] != '{' {
				return fmt.Errorf("auth: invalid JSON discovery document for %q", path)
			}
			if a.wellKnown == nil {
				a.wellKnown = make(map[string]WellKnownDocument)
			}
			a.wellKnown[path] = WellKnownDocument{Body: bytes.Clone(body), Headers: doc.Headers.Clone()}
		}
	}
	return nil
}

// WellKnownPaths returns the absolute, escaped paths to mount on the public
// router. Some protocols locate discovery outside the auth handler's base path.
func (a *Auth) WellKnownPaths() []string { return slices.Sorted(maps.Keys(a.wellKnown)) }

// WellKnownJSON returns a private copy of a discovery document at its exact path.
func (a *Auth) WellKnownJSON(path string) (json.RawMessage, bool) {
	doc, ok := a.wellKnown[path]
	return bytes.Clone(doc.Body), ok
}

// ServeHTTP serves GET and HEAD when the document is mounted directly by the host.
func (d WellKnownDocument) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	for key, values := range d.Headers {
		w.Header()[http.CanonicalHeaderKey(key)] = slices.Clone(values)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(d.Body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(d.Body)
	}
}
