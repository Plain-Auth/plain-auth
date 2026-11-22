package plainauth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func prepareDisabledPaths(paths []string) (map[string]struct{}, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	disabled := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		u, err := url.ParseRequestURI(path)
		if err != nil || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "*?#") || strings.Contains(u.Path, "/:") {
			return nil, errors.New("auth: disabled paths must be exact, mount-relative paths without queries, fragments or placeholders")
		}
		disabled[strings.TrimRight(u.Path, "/")] = struct{}{}
	}
	return disabled, nil
}

// HTTPPathDisabled reports whether the request selects an HTTP path disabled on
// this mount. Auth and the bundled SCIM wrapper check this before authentication.
// Host handlers that extend the same mount can apply the same policy.
func (a *Auth) HTTPPathDisabled(r *http.Request) bool {
	if len(a.disabledPaths) == 0 {
		return false
	}
	route, mounted := strings.CutPrefix(r.URL.Path, strings.TrimRight(a.opts.BasePath, "/"))
	if !mounted || (route != "" && !strings.HasPrefix(route, "/")) {
		return false
	}
	_, disabled := a.disabledPaths[strings.TrimRight(route, "/")]
	return disabled
}
