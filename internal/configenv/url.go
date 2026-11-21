// Package configenv validates server and CLI configuration.
package configenv

import (
	"errors"
	"net/url"
	"path"
	"strings"
)

// ServerEndpoint validates an HTTP origin and resolves the server's mount
// path. The explicit router mount takes precedence over a URL path.
func ServerEndpoint(raw, mount string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return "", "", errors.New("expected an absolute HTTP(S) URL without credentials, query or fragment")
	}
	if mount == "" {
		mount = strings.TrimRight(u.EscapedPath(), "/")
	}
	if mount == "" {
		mount = "/api/auth"
	}
	if !strings.HasPrefix(mount, "/") || path.Clean(mount) != mount || strings.ContainsAny(mount, "?#%\\ \t\r\n") {
		return "", "", errors.New("auth mount must be a clean absolute URL path")
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), mount, nil
}
