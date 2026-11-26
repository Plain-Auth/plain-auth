package httporigin

import (
	"errors"
	"net/http"
	"slices"

	"golang.org/x/net/http/httpguts"
)

// Headers checks configured header names and values and returns a copy with
// canonical keys.
func Headers(h http.Header) (http.Header, error) {
	if len(h) == 0 {
		return nil, nil
	}
	out := make(http.Header, len(h))
	for k, values := range h {
		if !httpguts.ValidHeaderFieldName(k) {
			return nil, errors.New("invalid header name")
		}
		for _, v := range values {
			if !httpguts.ValidHeaderFieldValue(v) {
				return nil, errors.New("invalid value for header " + http.CanonicalHeaderKey(k))
			}
		}
		key := http.CanonicalHeaderKey(k)
		out[key] = append(out[key], values...)
	}
	return out, nil
}

// WithHeaders returns a copy of c that adds h to each request for origin. A
// header the request already has is kept. It returns c when h is empty.
func WithHeaders(c *http.Client, origin string, h http.Header) *http.Client {
	if len(h) == 0 {
		return c
	}
	out := *c
	out.Transport = headerTransport{base: c.Transport, origin: origin, header: h}
	return &out
}

type headerTransport struct {
	base   http.RoundTripper
	origin string
	header http.Header
}

func (t headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if Canonical(r.URL) == t.origin {
		r = r.Clone(r.Context())
		if r.Header == nil {
			r.Header = http.Header{}
		}
		for k, v := range t.header {
			if _, set := r.Header[k]; !set {
				r.Header[k] = slices.Clone(v)
			}
		}
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r)
}
