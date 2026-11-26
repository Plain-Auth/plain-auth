package plainauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ExplicitlyTrustedOriginFor adds the exact origins TrustedOriginsForRequest
// returned for the request, never its wildcard patterns, and leaves the
// static check unchanged.
func TestExplicitlyTrustedOriginFor(t *testing.T) {
	a, err := New(Options{BaseURL: "https://app.test", Secret: strings.Repeat("a", 32), Store: &refreshFixture{},
		TrustedOrigins: []string{"https://static.test", "https://*.wild.test"},
		TrustedOriginsForRequest: func(r *http.Request) ([]string, error) {
			if r.URL.Path == "/exact" {
				return []string{"https://idp.test"}, nil
			}
			return []string{"https://*.idp.test"}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	scope := func(path string) context.Context {
		r, err := a.withRequestScope(httptest.NewRequest("GET", path, nil))
		if err != nil {
			t.Fatal(err)
		}
		return r.Context()
	}
	exact, wild := scope("/exact"), scope("/wild")
	for _, tc := range []struct {
		ctx  context.Context
		raw  string
		want bool
	}{
		{context.Background(), "https://idp.test/token", false},
		{context.Background(), "https://static.test/token", true},
		{context.Background(), "https://app.test/token", true},
		{context.Background(), "https://a.wild.test/token", false},
		{exact, "https://idp.test/token", true},
		{exact, "https://static.test/token", true},
		{exact, "https://other.test/token", false},
		{wild, "https://a.idp.test/token", false},
		{wild, "https://idp.test/token", false},
	} {
		if got := a.ExplicitlyTrustedOriginFor(tc.ctx, tc.raw); got != tc.want {
			t.Errorf("ExplicitlyTrustedOriginFor(%s) = %v, want %v", tc.raw, got, tc.want)
		}
	}
	if a.ExplicitlyTrustedOrigin("https://idp.test/token") {
		t.Fatal("the static check trusted a per-request origin")
	}
}
