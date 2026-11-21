// Package configenv reads settings shared by server and client construction.
package configenv

import (
	"errors"
	"net/url"
	"os"
	"path"
	"strings"
)

// BaseURL resolves public auth URL aliases common to the native server and
// client. BASE_URL="/" is a framework's relative public asset path.
func BaseURL() string {
	for _, name := range []string{"BETTER_AUTH_URL", "AUTH_URL", "NEXT_PUBLIC_BETTER_AUTH_URL", "PUBLIC_BETTER_AUTH_URL", "NUXT_PUBLIC_BETTER_AUTH_URL", "NUXT_PUBLIC_AUTH_URL", "BASE_URL"} {
		value := os.Getenv(name)
		if value != "" && !(name == "BASE_URL" && value == "/") {
			return value
		}
	}
	return ""
}

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
