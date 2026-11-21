package authn

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIPOptions controls how the application identifies the connection peer.
type ClientIPOptions struct {
	// TrustedProxies contains the CIDR ranges of reverse proxies which
	// overwrite or append the actual connection address to ForwardedHeader.
	TrustedProxies []netip.Prefix
	// ForwardedHeader defaults to X-Forwarded-For. Comma-separated hops are
	// processed from the application toward the client.
	ForwardedHeader string
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
	if o.ForwardedHeader == "" {
		o.ForwardedHeader = "X-Forwarded-For"
	} else if !validHeaderField(o.ForwardedHeader) {
		return errors.New("auth: invalid forwarded address header name")
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
	trusted := func(addr netip.Addr) bool {
		for _, prefix := range opts.TrustedProxies {
			if prefix.Contains(addr) {
				return true
			}
		}
		return false
	}
	if !trusted(peer) {
		return direct
	}
	chain := strings.Join(r.Header.Values(opts.ForwardedHeader), ",")
	if chain == "" {
		return direct
	}
	if len(chain) > 4096 {
		return ""
	}
	hops := strings.Split(chain, ",")
	for i := len(hops) - 1; i >= 0 && trusted(peer); i-- {
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
