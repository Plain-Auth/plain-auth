package plainauth

import (
	"net/http"
	"strconv"
	"strings"
)

// expireStoredSessionData removes the cache cookies belonging to this auth
// instance. Credential expiration also clears the base name when the browser omitted it.
func (a *Auth) expireStoredSessionData(h http.Header, r *http.Request, expireBase bool) {
	a.reconcileSessionDataCookies(h, r, expireBase, nil)
}

func (a *Auth) reconcileSessionDataCookies(h http.Header, r *http.Request, expireBase bool, replacements map[string]bool) {
	expired := a.browserCookie("session_data", "", -1)
	prefix := expired.Name + "."
	var names []string
	var seen map[string]bool
	hasData := false
	for _, c := range r.Cookies() {
		if c.Name != expired.Name {
			suffix, ok := strings.CutPrefix(c.Name, prefix)
			if !ok {
				continue
			}
			// Chunk indexes use the canonical decimal spelling of a JavaScript safe integer.
			index, err := strconv.ParseUint(suffix, 10, 53)
			if err != nil || strconv.FormatUint(index, 10) != suffix {
				continue
			}
		}
		hasData = hasData || c.Value != ""
		if !seen[c.Name] {
			if seen == nil {
				seen = make(map[string]bool)
			}
			seen[c.Name] = true
			names = append(names, c.Name)
		}
	}
	if !expireBase && !hasData {
		return
	}
	if expireBase && !seen[expired.Name] {
		h.Add("Set-Cookie", expired.String())
	}
	for _, name := range names {
		expired.Name = name
		if expired.Domain != "" {
			host := *expired
			host.Domain = ""
			h.Add("Set-Cookie", host.String())
		}
		if !replacements[name] {
			h.Add("Set-Cookie", expired.String())
		}
	}
}
