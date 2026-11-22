// Package publicnet classifies network addresses used in identity metadata.
package publicnet

import "net/netip"

// Additional special-purpose prefixes that netip.IsGlobalUnicast does not exclude.
var specialIPs = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2001::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}
var v6Global = netip.MustParsePrefix("2000::/3")

// Address reports whether an IP address belongs to a publicly routable range.
func Address(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.Zone() != "" || a.Is6() && !v6Global.Contains(a) {
		return false
	}
	for _, prefix := range specialIPs {
		if prefix.Contains(a) {
			return false
		}
	}
	return true
}
