package httporigin

import (
	"maps"
	"net/url"
	"strings"
)

// SetQuery sets query parameters on target. A custom-scheme deep link such
// as myapp://?x keeps its "//", which url.URL.String drops for an empty host.
func SetQuery(target string, set url.Values) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	q := u.Query()
	maps.Copy(q, set)
	u.RawQuery = q.Encode()
	out := u.String()
	if n := len(u.Scheme) + 1; u.Scheme != "" && u.Host == "" && len(target) > n && strings.HasPrefix(target[n:], "//") && !strings.HasPrefix(out[n:], "//") {
		out = u.Scheme + "://" + out[n:]
	}
	return out
}
