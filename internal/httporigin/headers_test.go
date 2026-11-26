package httporigin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Configured headers get canonical keys and are checked; WithHeaders adds
// them only to requests for its origin, keeps a header the request already
// has, and leaves the caller's request unchanged.
func TestWithHeaders(t *testing.T) {
	if _, err := Headers(http.Header{"Bad Name": {"a"}}); err == nil {
		t.Fatal("an invalid name was accepted")
	}
	if _, err := Headers(http.Header{"X-A": {"a\nb"}}); err == nil {
		t.Fatal("an invalid value was accepted")
	}
	h, err := Headers(http.Header{"x-tenant": {"one"}, "X-Tenant": {"two"}, "authorization": {"Bearer configured"}})
	if err != nil || len(h) != 2 || len(h["X-Tenant"]) != 2 || h.Get("Authorization") != "Bearer configured" {
		t.Fatal("canonical headers:", h, err)
	}
	seen := map[string]http.Header{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen[r.URL.Path] = r.Header.Clone() }))
	defer srv.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen["other"] = r.Header.Clone() }))
	defer other.Close()
	c := WithHeaders(srv.Client(), "http://"+srv.Listener.Addr().String(), h)
	r, _ := http.NewRequest("GET", srv.URL+"/token", nil)
	r.Header.Set("Authorization", "Basic own")
	res, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if got := seen["/token"]; len(got["X-Tenant"]) != 2 || got.Get("Authorization") != "Basic own" {
		t.Fatal("the origin's request got", got)
	}
	if len(r.Header) != 1 {
		t.Fatal("the caller's request was changed:", r.Header)
	}
	res, err = c.Get(other.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if seen["other"].Get("X-Tenant") != "" || seen["other"].Get("Authorization") != "" {
		t.Fatal("another origin got the headers")
	}
	if WithHeaders(c, "", nil) != c || WithHeaders(c, "", http.Header{}) != c {
		t.Fatal("empty headers wrapped the client")
	}
}
