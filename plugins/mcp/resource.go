package mcp

import (
	"errors"
	"net/netip"
	"net/url"
	"strings"
)

// validateResource checks the canonical MCP resource URL, as another
// runtime does: absolute, without credentials, fragment or query, and HTTPS
// or HTTP on a loopback host. Space, control characters and backslashes,
// which a WHATWG parser would normalize, are refused too (safety).
func validateResource(resource string) (*url.URL, error) {
	if strings.ContainsFunc(resource, func(r rune) bool { return r <= ' ' || r == 0x7f || r == '\\' }) {
		return nil, errors.New("mcp: resource URL must not contain spaces, control characters or backslashes")
	}
	u, err := url.Parse(resource)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return nil, errors.New("mcp: resource must be an absolute URL")
	}
	if u.User != nil {
		return nil, errors.New("mcp: resource URL must not contain credentials")
	}
	if strings.Contains(resource, "#") {
		return nil, errors.New("mcp: resource URL must not contain a fragment")
	}
	if strings.Contains(resource, "?") {
		return nil, errors.New("mcp: resource URL must not contain a query")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname())) {
		return nil, errors.New("mcp: resource URL must use HTTPS, except for localhost or loopback IP development URLs")
	}
	return u, nil
}

// loopbackHost reports localhost, a .localhost name or a loopback IP.
func loopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().IsLoopback()
	}
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}
