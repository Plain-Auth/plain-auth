// Package httporigin parses HTTP origins and matches configured trust rules.
package httporigin

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// Rule matches an exact origin or a configured hostname and port pattern.
type Rule struct {
	exact, scheme, host, port string
	ipv4Only                  bool
}

var (
	originLabel        = regexp.MustCompile(`^[a-z0-9*?]([a-z0-9*?-]{0,61}[a-z0-9*?])?$`)
	originPortPattern  = regexp.MustCompile(`^[0-9*?]+$`)
	numericHostPattern = regexp.MustCompile(`^[0-9.*?]+$`)
	errOriginPattern   = errors.New("expected an HTTP(S) origin or hostname wildcard with an optional port")
)

// Compile validates the configured origins and preserves their order.
func Compile(origins []string) ([]Rule, error) {
	rules := make([]Rule, 0, len(origins))
	for i, origin := range origins {
		rule, err := parseRule(origin)
		if err != nil {
			return nil, fmt.Errorf("authn: TrustedOrigins[%d]: %w", i, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseRule(raw string) (Rule, error) {
	if !strings.ContainsAny(raw, "*?") {
		origin, err := Parse(raw)
		if err != nil {
			return Rule{}, err
		}
		u, _ := url.Parse(origin)
		return Rule{exact: Canonical(u)}, nil
	}
	scheme, authority, hasScheme := strings.Cut(strings.ToLower(raw), "://")
	if !hasScheme {
		authority, scheme = scheme, "*"
	}
	if scheme != "*" && scheme != "https" && scheme != "http" {
		return Rule{}, errOriginPattern
	}
	authority = strings.TrimSuffix(authority, "/")
	host, port, hasPort := strings.Cut(authority, ":")
	if strings.HasPrefix(authority, "[") {
		value, rest, closed := strings.Cut(authority[1:], "]")
		address, err := netip.ParseAddr(value)
		if !closed || err != nil || !address.Is6() || address.Zone() != "" || (rest != "" && rest[0] != ':') {
			return Rule{}, errOriginPattern
		}
		host, port, hasPort = address.String(), strings.TrimPrefix(rest, ":"), rest != ""
	} else if !validOriginHostname(host) {
		return Rule{}, errOriginPattern
	}
	if hasPort {
		if !originPortPattern.MatchString(port) || len(port) > 5 {
			return Rule{}, errOriginPattern
		}
		if !strings.ContainsAny(port, "*?") {
			n, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return Rule{}, errOriginPattern
			}
			port = strconv.FormatUint(n, 10)
		}
	}
	ipv4Only := numericHostPattern.MatchString(host) && strings.ContainsAny(host, "0123456789")
	return Rule{scheme: scheme, host: host, port: port, ipv4Only: ipv4Only}, nil
}

func validOriginHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(strings.TrimSuffix(host, "."), ".") {
		if !originLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// Matches checks a URL and its canonical origin against the rule.
func (rule Rule) Matches(u *url.URL, origin string) bool {
	if rule.exact != "" {
		return rule.exact == origin
	}
	if rule.scheme != "*" && rule.scheme != u.Scheme {
		return false
	}
	host := strings.ToLower(u.Hostname())
	addr, err := netip.ParseAddr(host)
	if strings.HasPrefix(u.Host, "[") != (err == nil && addr.Is6()) {
		return false
	}
	if err == nil {
		if addr.Zone() != "" || (rule.ipv4Only && !addr.Is4()) {
			return false
		}
		host = addr.String()
	} else if rule.ipv4Only || strings.ContainsAny(host, "*?") || !validOriginHostname(host) {
		return false
	}
	// The pattern grammar is checked at startup, and path.Match treats dots
	// literally while allowing a star to span several subdomains.
	hostMatch, _ := path.Match(rule.host, host)
	if !hostMatch {
		return false
	}
	defaultPort := "443"
	if u.Scheme == "http" {
		defaultPort = "80"
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return false
		}
		port = strconv.FormatUint(n, 10)
	}
	if rule.port == "" {
		return port == "" || port == defaultPort
	}
	if port == "" || port == defaultPort {
		return rule.port == defaultPort
	}
	portMatch, _ := path.Match(rule.port, port)
	return portMatch
}

// Exact reports whether this rule explicitly names the canonical origin.
func (rule Rule) Exact(origin string) bool { return rule.exact != "" && rule.exact == origin }

// Parse validates a standalone origin, allowing an optional trailing slash.
func Parse(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || (u.EscapedPath() != "" && u.EscapedPath() != "/") || u.RawQuery != "" || u.ForceQuery || strings.Contains(s, "#") {
		return "", errors.New("expected an absolute HTTP(S) origin")
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), nil
}

// Canonical returns the normalized origin of an HTTP URL, or an empty string for an invalid origin.
func Canonical(u *url.URL) string {
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return ""
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if port == "" || (port == "80" && u.Scheme == "http") || (port == "443" && u.Scheme == "https") {
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	} else {
		host = net.JoinHostPort(host, port)
	}
	return u.Scheme + "://" + host
}
