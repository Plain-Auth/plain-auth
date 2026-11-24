package plainauth

import (
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestTrustedProxyAddresses(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/64")}
	bits := 56
	opts := Options{BaseURL: "http://app.test", Secret: strings.Repeat("x", 32), Store: &refreshFixture{},
		ClientIP: ClientIPOptions{TrustedProxies: trusted, Headers: []string{"X-For"}, IPv6Subnet: &bits}}
	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	trusted[0] = netip.MustParsePrefix("0.0.0.0/0")
	bits = 128
	for _, tc := range []struct{ peer, header, want string }{
		{"192.0.2.5:443", "198.51.100.1", "192.0.2.5"},
		{"10.0.0.2:443", "192.0.2.99, 198.51.100.1, 10.0.0.1", "198.51.100.1"},
		{"[2001:db8::a]:443", "::ffff:192.0.2.15", "192.0.2.15"},
		{"10.0.0.1:443", "bad header", ""},
		{"10.0.0.1:443", "", "10.0.0.1"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("X-For", tc.header)
		if got := a.clientIP(r); got != tc.want {
			t.Errorf("%s via %s: got %s, want %s", tc.header, tc.peer, got, tc.want)
		}
	}
	if got := a.rateLimitIP("2001:db8:abcd:12ff::5"); got != "2001:db8:abcd:1200::/56" {
		t.Fatal(got)
	}
	opts.ClientIP.IPv6Subnet = nil
	opts.ClientIP.TrustedProxies = []netip.Prefix{{}}
	if _, err := New(opts); err == nil {
		t.Fatal("invalid proxy accepted")
	}
	opts.ClientIP = ClientIPOptions{Headers: []string{"X-For", "invalid header"}}
	if _, err := New(opts); err == nil {
		t.Fatal("invalid header accepted")
	}
}

func TestDisableIPTracking(t *testing.T) {
	enabled := true
	a, err := New(Options{BaseURL: "http://app.test", Secret: strings.Repeat("x", 32), Store: &refreshFixture{},
		RateLimit: &enabled, ClientIP: ClientIPOptions{DisableTracking: true}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/auth/sign-in/email", nil)
	if got := a.clientIP(r); got != "" {
		t.Fatal(got)
	}
	for i := 0; i < 10; i++ {
		if a.rejectRateLimited(httptest.NewRecorder(), r, "/sign-in/email") {
			t.Fatal("disabled IP tracking invoked the per-IP limiter")
		}
	}
}
