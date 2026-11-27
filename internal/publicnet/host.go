package publicnet

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// hosts maps a host as a browser's URL parser does, which allows characters
// outside RFC 1034 such as "_" and hyphens anywhere in a label.
var hosts = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.CheckHyphens(false))

var errForbiddenHost = errors.New("publicnet: forbidden host character")

// HostASCII maps a URL host to its ASCII form, or fails for one a browser
// would refuse, such as one with a space or a forbidden domain character.
func HostASCII(name string) (string, error) {
	ascii, err := hosts.ToASCII(name)
	if err == nil && strings.ContainsFunc(ascii, func(r rune) bool { return r < 0x20 || r == 0x7f || strings.ContainsRune(" #%/:<>?@[\\]^|", r) }) {
		return "", errForbiddenHost
	}
	return ascii, err
}

// PublicHost reports whether a URL host names a public destination: a
// public IP address, or a dotted DNS name that is not loopback, not
// spelled like a number, not a cloud metadata name and not under .internal
// or .local. Another runtime refuses only special-use addresses, localhost
// and cloud metadata names; the dotless, .internal and .local refusals are
// kept for safety.
func PublicHost(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if ip, err := netip.ParseAddr(name); err == nil {
		return Address(ip)
	}
	ascii, err := HostASCII(name)
	return err == nil && strings.Contains(ascii, ".") && !AmbiguousHost(ascii) && !Loopback(ascii) && ascii != "metadata.goog" &&
		!strings.HasSuffix(ascii, ".internal") && !strings.HasSuffix(ascii, ".local")
}

// Loopback reports whether a host is a loopback address, localhost or a
// name under .localhost.
func Loopback(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if ip, err := netip.ParseAddr(name); err == nil {
		return ip.Unmap().IsLoopback()
	}
	return name == "localhost" || strings.HasSuffix(name, ".localhost")
}

// AmbiguousHost reports whether a DNS name ends in a numeric label, which
// browsers may read as an IP address, or in an empty one.
func AmbiguousHost(name string) bool {
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	tail := parts[len(parts)-1]
	if tail == "" {
		return true
	}
	_, err := strconv.ParseUint(tail, 10, 64)
	return err == nil || strings.HasPrefix(strings.ToLower(tail), "0x")
}

// Origin is an HTTP(S) URL's web origin as a browser serializes it: the
// scheme, the host in ASCII, and the port as a number unless it is the
// scheme's default, without credentials. ok is false for a URL without
// one, whose origin is opaque.
func Origin(u *url.URL) (string, bool) {
	host := u.Hostname()
	if u.Scheme != "http" && u.Scheme != "https" || host == "" {
		return "", false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.String()
		if ip.Is6() {
			host = "[" + host + "]"
		}
	} else {
		ascii, err := HostASCII(host)
		if err != nil {
			return "", false
		}
		host = strings.ToLower(ascii)
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return "", false
		}
		if !(u.Scheme == "http" && n == 80 || u.Scheme == "https" && n == 443) {
			host += ":" + strconv.FormatUint(n, 10)
		}
	}
	return u.Scheme + "://" + host, true
}
