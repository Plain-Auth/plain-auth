package plainauth

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// An exact origin keeps the existing URL canonicalization. Wildcards are bounded
// to the hostname or port they were declared in.
type trustedOrigin struct {
	exact, scheme, host, port string
	ipv4Only                  bool
}

var (
	originLabel        = regexp.MustCompile(`^[a-z0-9*?]([a-z0-9*?-]{0,61}[a-z0-9*?])?$`)
	originPortPattern  = regexp.MustCompile(`^[0-9*?]+$`)
	numericHostPattern = regexp.MustCompile(`^[0-9.*?]+$`)
	errOriginPattern   = errors.New("expected an HTTP(S) origin or hostname wildcard with an optional port")
)

func configuredTrustedOrigins(origins []string) ([]trustedOrigin, error) {
	rules := make([]trustedOrigin, 0, len(origins))
	for i, origin := range origins {
		rule, err := parseTrustedOrigin(origin)
		if err != nil {
			return nil, fmt.Errorf("authn: TrustedOrigins[%d]: %w", i, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseTrustedOrigin(raw string) (trustedOrigin, error) {
	if !strings.ContainsAny(raw, "*?") {
		origin, err := parseOrigin(raw)
		if err != nil {
			return trustedOrigin{}, err
		}
		u, _ := url.Parse(origin)
		return trustedOrigin{exact: canonicalOrigin(u)}, nil
	}
	scheme, authority, hasScheme := strings.Cut(strings.ToLower(raw), "://")
	if !hasScheme {
		authority, scheme = scheme, "*"
	}
	if scheme != "*" && scheme != "https" && scheme != "http" {
		return trustedOrigin{}, errOriginPattern
	}
	authority = strings.TrimSuffix(authority, "/")
	host, port, hasPort := strings.Cut(authority, ":")
	if strings.HasPrefix(authority, "[") {
		value, rest, closed := strings.Cut(authority[1:], "]")
		address, err := netip.ParseAddr(value)
		if !closed || err != nil || !address.Is6() || address.Zone() != "" || (rest != "" && rest[0] != ':') {
			return trustedOrigin{}, errOriginPattern
		}
		host, port, hasPort = address.String(), strings.TrimPrefix(rest, ":"), rest != ""
	} else if !validOriginHostname(host) {
		return trustedOrigin{}, errOriginPattern
	}
	if hasPort {
		if !originPortPattern.MatchString(port) || len(port) > 5 {
			return trustedOrigin{}, errOriginPattern
		}
		if !strings.ContainsAny(port, "*?") {
			n, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return trustedOrigin{}, errOriginPattern
			}
			port = strconv.FormatUint(n, 10)
		}
	}
	ipv4Only := numericHostPattern.MatchString(host) && strings.ContainsAny(host, "0123456789")
	return trustedOrigin{scheme: scheme, host: host, port: port, ipv4Only: ipv4Only}, nil
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

func (rule trustedOrigin) matches(u *url.URL, origin string) bool {
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
