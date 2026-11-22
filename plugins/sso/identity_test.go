package sso

import (
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
)

func TestEnterpriseIdentityTransport(t *testing.T) {
	host, err := auth.New(auth.Options{Store: memory.New(), BaseURL: "https://accounts.example.test", Secret: strings.Repeat("s", 32), TrustedOrigins: []string{"https://*.company.test", "https://login.company.test", "http://idp.company.test", "http://127.0.0.1:10999"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"http://idp.company.test/authorize", "https://127.0.0.1:10999/token", "https://[::1]/keys", "https://metadata.google.internal/keys"} {
		if secureBrowserEndpoint(host, raw) == nil {
			t.Fatal("unsafe endpoint accepted", raw)
		}
	}
	for _, raw := range []string{"https://example.org/authorize", "http://127.0.0.1:10999/keys"} {
		if e := secureBrowserEndpoint(host, raw); e != nil {
			t.Fatal(e)
		}
	}
	for _, addr := range []string{"10.0.0.4", "127.0.0.1", "::ffff:10.0.0.4", "fd42::123", "169.254.0.4", "100.64.0.8", "2001:db8::1", "2002:c000:201::1", "64:ff9b::7f00:0001", "fe80::1"} {
		if publicAddress(netip.MustParseAddr(addr)) {
			t.Fatal("restricted address accepted", addr)
		}
	}
	if !publicAddress(netip.MustParseAddr("8.8.8.8")) || !publicAddress(netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Fatal("public address rejected")
	}
	if conn, e := publicTransport.DialContext(t.Context(), "tcp", "localhost:10999"); e == nil || conn != nil {
		t.Fatal("public transport dialed local address")
	}
	var requests int
	wire := transportFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		if d, ok := r.Context().Deadline(); !ok || time.Until(d) > 10*time.Second {
			t.Fatal("unbounded provider request")
		}
		res := &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header), Request: r}
		switch r.URL.Path {
		case "/redirect":
			res.StatusCode = 307
			res.Header.Set("location", "https://login.company.test/unexpected")
		case "/large":
			res.Body = io.NopCloser(strings.NewReader(strings.Repeat("a", (1<<20)+1)))
		}
		return res, nil
	})
	client := providerHTTP(host, &http.Client{Transport: wire})
	for _, path := range []string{"/redirect", "/large"} {
		if res, e := client.Get("https://login.company.test" + path); e == nil || res != nil {
			t.Fatal("invalid response accepted", path)
		}
	}
	if requests != 2 {
		t.Fatal("followed provider redirect")
	}
	if _, e := client.Get("https://127.0.0.1:10999/token"); e == nil || requests != 2 {
		t.Fatal("forwarded to an unapproved private origin")
	}
	if host.ExplicitlyTrustedOrigin("https://unlisted.company.test") {
		t.Fatal("browser wildcard granted confidential transport")
	}
}
