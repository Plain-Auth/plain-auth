package publicnet

import (
	"context"
	"net"
	"net/http"
	"time"
)

// Transport resolves and dials the same vetted public address. A proxy, custom dialer, or second
// DNS resolution must not redirect untrusted tenant endpoints to internal hosts.
func Transport(invalidDestination error) *http.Transport {
	return &http.Transport{TLSHandshakeTimeout: 5 * time.Second, IdleConnTimeout: 30 * time.Second, MaxResponseHeaderBytes: 32 << 10,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, e := net.SplitHostPort(addr)
			if e != nil {
				return nil, e
			}
			ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if e != nil || len(ips) == 0 {
				return nil, invalidDestination
			}
			for _, ip := range ips {
				if !Address(ip) {
					return nil, invalidDestination
				}
			}
			var d net.Dialer
			for _, ip := range ips {
				conn, e := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if e == nil {
					return conn, nil
				}
			}
			return nil, invalidDestination
		}}
}
