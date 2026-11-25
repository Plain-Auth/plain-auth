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
	"unicode"
)

// Rule matches an exact origin, a configured hostname and port pattern, or
// a custom-scheme URL such as an app deep link.
type Rule struct {
	exact, scheme, host, port string
	ipv4Only                  bool
	// custom rules match a non-HTTP scheme by authority and path.
	custom, wildcard bool
	authority, path  string
}

var (
	originLabel        = regexp.MustCompile(`^[a-z0-9*?]([a-z0-9*?-]{0,61}[a-z0-9*?])?$`)
	originPortPattern  = regexp.MustCompile(`^[0-9*?]+$`)
	numericHostPattern = regexp.MustCompile(`^[0-9.*?]+$`)
	errOriginPattern   = errors.New("expected an HTTP(S) origin, a hostname wildcard with an optional port, or a custom-scheme URL such as myapp://")
	customSchemeRule   = regexp.MustCompile(`^([a-z][a-z0-9+.-]*):(/.*)?$`)
	customAuthority    = regexp.MustCompile(`^[a-z0-9._~*?:-]*$`)
	errDeniedScheme    = errors.New("this URL scheme can run code or read local data and cannot be trusted")
)

// deniedSchemes can run script, read local data or reach other protocols.
var deniedSchemes = map[string]bool{"javascript": true, "vbscript": true, "data": true, "blob": true, "file": true, "filesystem": true,
	"about": true, "view-source": true, "intent": true, "ftp": true, "ws": true, "wss": true}

// ASCIILower lowercases A-Z only, so a non-ASCII letter such as U+0130 can
// never fold into an ASCII one and match a trusted host.
func ASCIILower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// ASCIIOnly reports whether s holds no byte outside ASCII. Browsers map a
// non-ASCII host to its punycode form, which no ASCII rule can name.
func ASCIIOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// DeniedScheme reports whether a URL scheme may never be trusted.
func DeniedScheme(scheme string) bool { return deniedSchemes[ASCIILower(scheme)] }

// Compile validates the origins of the named option and preserves their order.
func Compile(field string, origins []string) ([]Rule, error) {
	rules := make([]Rule, 0, len(origins))
	for i, origin := range origins {
		rule, err := parseRule(origin)
		if err != nil {
			return nil, fmt.Errorf("authn: %s[%d]: %w", field, i, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseRule(raw string) (Rule, error) {
	if scheme, rest, ok := strings.Cut(raw, ":"); ok {
		if lower := ASCIILower(scheme); lower != "http" && lower != "https" && customSchemeRule.MatchString(lower+":"+rest) {
			return parseCustomRule(lower, rest)
		}
	}
	if !strings.ContainsAny(raw, "*?") {
		origin, err := Parse(raw)
		if err != nil {
			return Rule{}, err
		}
		u, _ := url.Parse(origin)
		return Rule{exact: Canonical(u)}, nil
	}
	scheme, authority, hasScheme := strings.Cut(ASCIILower(raw), "://")
	if !hasScheme {
		authority, scheme = scheme, "*"
	}
	if scheme != "*" && scheme != "https" && scheme != "http" {
		return Rule{}, errOriginPattern
	}
	return parseAuthority(scheme, strings.TrimSuffix(authority, "/"))
}

// parseAuthority reads a hostname or hostname pattern with an optional port
// or port pattern.
func parseAuthority(scheme, authority string) (Rule, error) {
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

// parseCustomRule reads scheme:[//authority][/path], where the authority
// and the path may hold * and ? wildcards and a path segment may be **.
func parseCustomRule(scheme, rest string) (Rule, error) {
	if DeniedScheme(scheme) {
		return Rule{}, errDeniedScheme
	}
	authority, rulePath := "", rest
	if after, ok := strings.CutPrefix(rest, "//"); ok {
		authority, rulePath, _ = strings.Cut(after, "/")
		rulePath = "/" + rulePath
	}
	authority = ASCIILower(authority)
	if !customAuthority.MatchString(authority) || strings.ContainsAny(rulePath, "%#[]\\") || strings.IndexFunc(rulePath, unicode.IsSpace) >= 0 || strings.IndexFunc(rulePath, unicode.IsControl) >= 0 {
		return Rule{}, errOriginPattern
	}
	host, _, _ := strings.Cut(authority, ":")
	ipv4Only := numericHostPattern.MatchString(host) && strings.ContainsAny(host, "0123456789")
	rulePath = cleanCustomPath(rulePath)
	if strings.Contains(authority, "**") && rulePath == "" {
		// As in exp://**, a ** authority also spans every path.
		rulePath = "/**"
	}
	return Rule{custom: true, scheme: scheme, authority: authority, path: rulePath, wildcard: strings.ContainsAny(authority+rulePath, "*?"), ipv4Only: ipv4Only}, nil
}

// cleanCustomPath drops "." and empty segments and resolves "..", so "" is the root.
func cleanCustomPath(p string) string {
	var segments []string
	for segment := range strings.SplitSeq(p, "/") {
		switch segment {
		case "", ".":
		case "..":
			if len(segments) > 0 {
				segments = segments[:len(segments)-1]
			}
		default:
			segments = append(segments, segment)
		}
	}
	if len(segments) == 0 {
		return ""
	}
	return "/" + strings.Join(segments, "/")
}

// matchSegments matches path segments, where a ** segment spans any number.
// Like a glob on characters, it backtracks only to the latest **, so its cost
// stays linear in the URL's segments.
func matchSegments(pattern, segments []string) bool {
	p, s, star, mark := 0, 0, -1, 0
	for s < len(segments) {
		if p < len(pattern) && pattern[p] == "**" {
			star, mark = p, s
			p++
			continue
		}
		if p < len(pattern) {
			if ok, _ := path.Match(pattern[p], segments[s]); ok {
				p, s = p+1, s+1
				continue
			}
		}
		if star < 0 {
			return false
		}
		mark++
		p, s = star+1, mark
	}
	for p < len(pattern) && pattern[p] == "**" {
		p++
	}
	return p == len(pattern)
}

func splitPath(p string) []string {
	if p == "" {
		return nil
	}
	return strings.Split(strings.TrimPrefix(p, "/"), "/")
}

// matchCustom checks a custom-scheme URL. The authority is one string, so
// a wildcard crosses "." and ":"; query and fragment are ignored.
func (rule Rule) matchCustom(u *url.URL) bool {
	if u.Scheme != rule.scheme || u.Opaque != "" || u.User != nil || !ASCIIOnly(u.Host) {
		return false
	}
	// An encoded separator or a dot segment could reach another app route
	// than the one matched, since apps and browsers resolve them differently.
	if escaped := strings.ToLower(u.EscapedPath()); strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") {
		return false
	}
	for segment := range strings.SplitSeq(u.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	host, urlPath := ASCIILower(u.Host), cleanCustomPath(u.Path)
	if !rule.wildcard {
		if rule.authority != "" && host != rule.authority {
			return false
		}
		return rule.path == "" || urlPath == rule.path || strings.HasPrefix(urlPath, rule.path+"/")
	}
	if ok, _ := path.Match(rule.authority, host); !ok {
		return false
	}
	if rule.ipv4Only {
		if addr, err := netip.ParseAddr(u.Hostname()); err != nil || !addr.Is4() {
			return false
		}
	}
	// A wildcard rule without a path, such as myapp://*, trusts every path.
	if rule.path == "" {
		return true
	}
	return matchSegments(splitPath(rule.path), splitPath(urlPath))
}

// Custom reports whether the rule matches a custom-scheme URL.
func (rule Rule) Custom() bool { return rule.custom }

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
	if rule.custom {
		return rule.matchCustom(u)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if rule.exact != "" {
		return rule.exact == origin
	}
	if rule.scheme != "*" && rule.scheme != u.Scheme {
		return false
	}
	if !ASCIIOnly(u.Host) {
		return false
	}
	host := ASCIILower(u.Hostname())
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

// CompileHosts validates host patterns such as example.com, *.example.com
// or localhost:3000, optionally written with an http:// or https:// prefix.
// A pattern that matches every host is refused.
func CompileHosts(field string, hosts []string) ([]Rule, error) {
	rules := make([]Rule, 0, len(hosts))
	for i, raw := range hosts {
		host := ASCIILower(raw)
		for _, prefix := range []string{"http://", "https://"} {
			host = strings.TrimPrefix(host, prefix)
		}
		rule, err := parseAuthority("*", host)
		if err == nil && strings.Trim(rule.host, "*?.") == "" {
			err = errors.New("a host pattern must name a domain")
		}
		if err != nil {
			return nil, fmt.Errorf("authn: %s[%d]: %w", field, i, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// MatchesHost reports whether a host rule from CompileHosts admits host,
// with its optional port, when the request uses scheme.
func (rule Rule) MatchesHost(scheme, host string) bool {
	u := &url.URL{Scheme: scheme, Host: host}
	return rule.Matches(u, Canonical(u))
}

// Exact reports whether this rule explicitly names the canonical origin.
func (rule Rule) Exact(origin string) bool { return rule.exact != "" && rule.exact == origin }

// Parse validates a standalone origin, allowing an optional trailing slash.
func Parse(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || !ASCIIOnly(u.Host) || u.User != nil || (u.EscapedPath() != "" && u.EscapedPath() != "/") || u.RawQuery != "" || u.ForceQuery || strings.Contains(s, "#") {
		return "", errors.New("expected an absolute HTTP(S) origin with an ASCII host")
	}
	return u.Scheme + "://" + ASCIILower(u.Host), nil
}

// Canonical returns the normalized origin of an HTTP URL, or an empty string for an invalid origin.
func Canonical(u *url.URL) string {
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || !ASCIIOnly(u.Host) {
		return ""
	}
	host, port := ASCIILower(u.Hostname()), u.Port()
	if port == "" || (port == "80" && u.Scheme == "http") || (port == "443" && u.Scheme == "https") {
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	} else {
		host = net.JoinHostPort(host, port)
	}
	return u.Scheme + "://" + host
}
