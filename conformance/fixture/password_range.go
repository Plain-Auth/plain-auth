package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// The two clients exercise identical synthetic breach ranges without a network
// connection to the range service. No user credentials enter this fixture.
type passwordRangeFixture struct{ digest string }

func (f passwordRangeFixture) RoundTrip(r *http.Request) (*http.Response, error) {
	prefix := strings.TrimPrefix(r.URL.Path, "/range/")
	if r.Method != "GET" || r.URL.Host != "api.pwnedpasswords.com" || len(prefix) != 5 || r.Header.Get("Add-Padding") != "true" {
		return nil, fmt.Errorf("unexpected range request")
	}
	body := strings.Repeat("0", 35) + ":0\r\n"
	if prefix == f.digest[:5] {
		body = f.digest[5:] + ":3\r\n"
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
}
