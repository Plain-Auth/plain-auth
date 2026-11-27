package cimd

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pinnedServer is a TLS server the fake dialer reaches for every address
// except those in fail.
func pinnedServer(t *testing.T, handler http.HandlerFunc, answers []netip.Addr, fail map[string]bool) (*transport, *atomic.Int32, *[]string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	var lookups atomic.Int32
	var dialed []string
	tr := newTransport(func(context.Context, string, string) ([]netip.Addr, error) {
		lookups.Add(1)
		return answers, nil
	}, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		if fail[addr] {
			return nil, errors.New("unreachable")
		}
		var d net.Dialer
		return d.DialContext(ctx, network, server.Listener.Addr().String())
	})
	tr.inner.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	return tr, &lookups, &dialed
}

func get(t *testing.T, tr http.RoundTripper, method, raw string) (*http.Response, error) {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), method, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Probe", "kept")
	return tr.RoundTrip(r)
}

// The transport takes HTTPS GET and HEAD without a body, resolves once,
// refuses non-public answers before dialing, dials only the vetted
// addresses with the URL's host and SNI, falls back to the next address,
// returns redirects unfollowed, refuses upgrades and bounds its lookups.
func TestTransport(t *testing.T) {
	public := []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")}
	var mu sync.Mutex
	var seen struct{ host, sni, method, probe string }
	read := func() struct{ host, sni, method, probe string } {
		mu.Lock()
		defer mu.Unlock()
		return seen
	}
	status := 200
	tr, lookups, dialed := pinnedServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen.host, seen.sni, seen.method, seen.probe = r.Host, r.TLS.ServerName, r.Method, r.Header.Get("X-Probe")
		mu.Unlock()
		if status == 302 {
			w.Header().Set("Location", "https://elsewhere.example/")
		}
		w.WriteHeader(status)
	}, public, map[string]bool{"8.8.8.8:443": true})
	res, err := get(t, tr, http.MethodGet, "https://example.com/client.json")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if got := read(); lookups.Load() != 1 || strings.Join(*dialed, ",") != "8.8.8.8:443,8.8.4.4:443" || got.host != "example.com" || got.sni != "example.com" || got.probe != "kept" {
		t.Fatal("the transport did not pin and fall back", lookups.Load(), *dialed, got)
	}
	if res, err := get(t, tr, http.MethodHead, "https://example.com/client.json"); err != nil || read().method != "HEAD" {
		t.Fatal("HEAD was not sent", err, read().method)
	} else {
		res.Body.Close()
	}
	for _, code := range []int{302, 304} {
		status = code
		res, err := get(t, tr, http.MethodGet, "https://example.com/client.json")
		if err != nil || res.StatusCode != code {
			t.Fatal("a redirect or not-modified answer was not returned as is", code, err)
		}
		res.Body.Close()
	}
	status = http.StatusSwitchingProtocols
	if _, err := get(t, tr, http.MethodGet, "https://example.com/client.json"); !errors.Is(err, errUpgrade) {
		t.Fatal("a protocol upgrade was accepted", err)
	}
	// Refused requests.
	status = 200
	if _, err := get(t, tr, http.MethodGet, "http://example.com/client.json"); err == nil || err.Error() != "cimd: transport requires an HTTPS URL" {
		t.Fatal("http was accepted", err)
	}
	if _, err := get(t, tr, http.MethodPost, "https://example.com/client.json"); err == nil || err.Error() != "cimd: transport supports only GET and HEAD" {
		t.Fatal("POST was accepted", err)
	}
	body, _ := http.NewRequest(http.MethodGet, "https://example.com/client.json", strings.NewReader("x"))
	if _, err := tr.RoundTrip(body); err == nil {
		t.Fatal("a request body was accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	before := lookups.Load()
	for _, raw := range []string{"https://example.com/client.json", "https://8.8.8.8/client.json"} {
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if _, err := tr.RoundTrip(r); !errors.Is(err, context.Canceled) {
			t.Fatal("a canceled request was sent", raw, err)
		}
	}
	if lookups.Load() != before {
		t.Fatal("a canceled request started a lookup")
	}
	// Non-public answers and literals are refused before dialing.
	dials := len(*dialed)
	private, _, privateDials := pinnedServer(t, func(http.ResponseWriter, *http.Request) {}, []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}, nil)
	if _, err := get(t, private, http.MethodGet, "https://example.com/c"); !errors.Is(err, errPrivate) || len(*privateDials) != 0 {
		t.Fatal("a private answer was dialed", err)
	}
	for _, raw := range []string{"https://[fd00::1]/c", "https://[::ffff:127.0.0.1]/c", "https://127.0.0.1/c"} {
		if _, err := get(t, tr, http.MethodGet, raw); !errors.Is(err, errPrivate) {
			t.Fatal("a private literal was accepted", raw, err)
		}
	}
	empty, _, _ := pinnedServer(t, func(http.ResponseWriter, *http.Request) {}, nil, nil)
	if _, err := get(t, empty, http.MethodGet, "https://example.com/c"); !errors.Is(err, errNoAddress) {
		t.Fatal("an empty answer was accepted", err)
	}
	if len(*dialed) != dials {
		t.Fatal("a refused request was dialed")
	}
	// A public IPv6 literal is pinned without a lookup and sends no SNI.
	literal, literalLookups, literalDials := pinnedServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen.sni = r.TLS.ServerName
		mu.Unlock()
	}, nil, nil)
	literal.inner.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	res, err = get(t, literal, http.MethodGet, "https://[2606:4700::1111]/c")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if literalLookups.Load() != 0 || strings.Join(*literalDials, ",") != "[2606:4700::1111]:443" || read().sni != "" {
		t.Fatal("an IP literal was looked up or sent SNI", literalLookups.Load(), *literalDials, read().sni)
	}
}

// A stalled lookup stops its caller on cancel but keeps its slot until it
// settles; the 17th outstanding lookup is refused, and a slot frees when a
// late lookup fails.
func TestTransportLookupLimit(t *testing.T) {
	release := make(chan struct{})
	var started atomic.Int32
	tr := newTransport(func(context.Context, string, string) ([]netip.Addr, error) {
		started.Add(1)
		<-release
		return nil, errors.New("lookup failed late")
	}, func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("no dial") })
	// A request canceled before it starts takes no lookup slot.
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	early, _ := http.NewRequestWithContext(canceled, http.MethodGet, "https://example.com/c", nil)
	if _, err := tr.RoundTrip(early); !errors.Is(err, context.Canceled) || len(tr.slots) != 0 {
		t.Fatal("a canceled request took a lookup slot", err, len(tr.slots))
	}
	for range maxLookups {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/c", nil)
		var aborted lookupAborted
		if _, err := tr.RoundTrip(r); !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &aborted) {
			t.Fatal("a stalled lookup did not stop on cancel as an aborted lookup", err)
		}
		cancel()
	}
	r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/c", nil)
	if _, err := tr.RoundTrip(r); !errors.Is(err, errLookupLimit) {
		t.Fatal("the lookup limit was not enforced", err)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for len(tr.slots) > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if _, err := tr.RoundTrip(r); err == nil || errors.Is(err, errLookupLimit) {
		t.Fatal("a slot did not free after a late lookup", err)
	}
}
