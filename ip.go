package plainauth

import (
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// ClientIPOptions controls how the application identifies the connection peer.
type ClientIPOptions struct {
	// TrustedProxies contains the CIDR ranges of the reverse proxies in front
	// of the application. Address headers are read only from these peers.
	TrustedProxies []netip.Prefix
	// Headers lists the headers that carry the client address, in order, and
	// the first one that yields an address wins. A proxy must overwrite a
	// single-address header such as CF-Connecting-IP, or append the peer to a
	// list such as X-Forwarded-For, whose hops are read from the application
	// toward the client. The default is X-Forwarded-For.
	Headers []string
	// IPv6Subnet is the per-rate-limit prefix length (0–128, default 64).
	IPv6Subnet *int
	// DisableTracking omits the IP address from sessions and disables IP-based limits.
	DisableTracking bool
}

func (o *ClientIPOptions) prepare() error {
	o.TrustedProxies = append([]netip.Prefix(nil), o.TrustedProxies...)
	for _, prefix := range o.TrustedProxies {
		if !prefix.IsValid() {
			return errors.New("auth: invalid trusted proxy prefix")
		}
	}
	if len(o.Headers) == 0 {
		o.Headers = []string{"X-Forwarded-For"}
	}
	o.Headers = slices.Clone(o.Headers)
	for _, name := range o.Headers {
		if !validHeaderField(name) {
			return errors.New("auth: invalid client address header name")
		}
	}
	if o.IPv6Subnet != nil {
		bits := *o.IPv6Subnet
		if bits < 0 || bits > 128 {
			return errors.New("auth: IPv6 subnet length must be between 0 and 128")
		}
		o.IPv6Subnet = &bits
	}
	return nil
}

func validHeaderField(field string) bool {
	for _, c := range field {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_\x60|~", c) {
			continue
		}
		return false
	}
	return field != ""
}

func (a *Auth) clientIP(r *http.Request) string {
	opts := a.opts.ClientIP
	if opts.DisableTracking {
		return ""
	}
	direct := remoteIP(r.RemoteAddr)
	if len(opts.TrustedProxies) == 0 {
		return direct
	}
	peer, err := netip.ParseAddr(direct)
	if err != nil {
		return ""
	}
	// Headers from untrusted immediate peers never supply an identity.
	if !opts.trusted(peer) {
		return direct
	}
	// A header that is sent but yields no address fails closed unless a
	// later header supplies one.
	sent := false
	for _, name := range opts.Headers {
		chain := strings.Join(r.Header.Values(name), ",")
		if chain == "" {
			continue
		}
		sent = true
		if ip := opts.forwardedIP(peer, chain); ip != "" {
			return ip
		}
	}
	if sent {
		return ""
	}
	return direct
}

func (o ClientIPOptions) trusted(addr netip.Addr) bool {
	for _, prefix := range o.TrustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// forwardedIP walks a chain from the trusted peer toward the client and
// returns the first untrusted hop, or "" when a hop is malformed.
func (o ClientIPOptions) forwardedIP(peer netip.Addr, chain string) string {
	if len(chain) > 4096 {
		return ""
	}
	hops := strings.Split(chain, ",")
	for i := len(hops) - 1; i >= 0 && o.trusted(peer); i-- {
		var err error
		peer, err = netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil || peer.Zone() != "" {
			return ""
		}
		peer = peer.Unmap()
	}
	return peer.String()
}

func (a *Auth) rateLimitIP(ip string) string {
	if ip == "" {
		return "no-trusted-ip"
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is6() {
		return ip
	}
	bits := 64
	if n := a.opts.ClientIP.IPv6Subnet; n != nil {
		bits = *n
	}
	return netip.PrefixFrom(addr, bits).Masked().String()
}
