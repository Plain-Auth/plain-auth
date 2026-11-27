package cimd

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/Plain-Org/plain-auth/internal/publicnet"
	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// maxLookups bounds the DNS lookups one transport runs at once.
const maxLookups = 16

// capacityError is a refusal at a local limit, which wraps the provider's
// ErrFetchCapacity.
type capacityError string

func (e capacityError) Error() string { return string(e) }
func (capacityError) Unwrap() error   { return oauthprovider.ErrFetchCapacity }

// lookupAborted is a lookup the request's context ended, which says nothing
// about the host, so it is never a transient failure; it wraps the
// context's error and the provider's ErrLookupAborted.
type lookupAborted struct{ err error }

func (e lookupAborted) Error() string   { return "metadata DNS lookup aborted: " + e.err.Error() }
func (e lookupAborted) Unwrap() []error { return []error{e.err, oauthprovider.ErrLookupAborted} }

var (
	errLookupLimit error = capacityError("metadata DNS lookup limit exceeded")
	errNoAddress         = errors.New("metadata hostname returned no DNS addresses")
	errPrivate           = errors.New("metadata hostname must resolve only to public-routable addresses")
	errUpgrade           = errors.New("metadata server answered with a protocol upgrade")
)

type pinnedKey struct{}

// transport fetches metadata documents and the resources their clients
// publish, dialing only the public addresses it resolved for the host.
type transport struct {
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
	slots  chan struct{}
	inner  *http.Transport
}

// NewTransport returns the transport for metadata documents and the
// resources their clients publish, such as a jwks_uri, as another runtime's
// pinned Node transport does: HTTPS GET and HEAD without a body; the host
// resolved once, every address public, and only those addresses dialed;
// redirects returned unfollowed; no protocol upgrades; no proxy and no kept
// connections; and at most 16 lookups at once, where another runtime's
// limit is per process.
func NewTransport() http.RoundTripper {
	var dialer net.Dialer
	return newTransport(net.DefaultResolver.LookupNetIP, dialer.DialContext)
}

func newTransport(lookup func(context.Context, string, string) ([]netip.Addr, error), dial func(context.Context, string, string) (net.Conn, error)) *transport {
	t := &transport{lookup: lookup, slots: make(chan struct{}, maxLookups)}
	t.inner = &http.Transport{DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second, MaxResponseHeaderBytes: 32 << 10,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			addrs, _ := ctx.Value(pinnedKey{}).([]netip.Addr)
			err = errNoAddress
			for _, ip := range addrs {
				conn, dialErr := dial(ctx, network, net.JoinHostPort(ip.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				err = dialErr
			}
			return nil, err
		}}
	return t
}

func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil && r.Body != http.NoBody {
		r.Body.Close()
		return nil, errors.New("cimd: transport refuses a request body")
	}
	if r.URL.Scheme != "https" {
		return nil, errors.New("cimd: transport requires an HTTPS URL")
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return nil, errors.New("cimd: transport supports only GET and HEAD")
	}
	ctx := r.Context()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(r.URL.Hostname()); err == nil {
		if !publicnet.Address(ip) {
			return nil, errPrivate
		}
		addrs = []netip.Addr{ip}
	} else if addrs, err = t.resolve(ctx, r.URL.Hostname()); err != nil {
		return nil, err
	}
	res, err := t.inner.RoundTrip(r.WithContext(context.WithValue(ctx, pinnedKey{}, addrs)))
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusSwitchingProtocols {
		res.Body.Close()
		return nil, errUpgrade
	}
	return res, nil
}

// resolve looks a host up once and vets every answer. An abandoned lookup
// keeps its slot until it settles, so slow resolvers cannot pile up.
func (t *transport) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	select {
	case t.slots <- struct{}{}:
	default:
		return nil, errLookupLimit
	}
	type answer struct {
		addrs []netip.Addr
		err   error
	}
	done := make(chan answer, 1)
	go func() {
		addrs, err := t.lookup(context.WithoutCancel(ctx), "ip", host)
		<-t.slots
		done <- answer{addrs, err}
	}()
	select {
	case <-ctx.Done():
		return nil, lookupAborted{ctx.Err()}
	case a := <-done:
		if a.err != nil {
			return nil, a.err
		}
		// An empty answer reaches the dialer, which has no address to dial.
		for _, ip := range a.addrs {
			if !publicnet.Address(ip) {
				return nil, errPrivate
			}
		}
		return a.addrs, nil
	}
}
