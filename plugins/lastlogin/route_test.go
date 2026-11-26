package lastlogin

import "testing"

// The default resolver matches the request path, so a provider ID that
// contains a method name never names that method.
func TestMethodForRoute(t *testing.T) {
	for route, want := range map[string]string{
		"/siwe/verify":                   "siwe",
		"/sso/callback/siwe-guild":       "",
		"/sso/saml2/sp/acs/siwe-guild":   "",
		"/callback/siwe-guild":           "siwe-guild",
		"/callback/github/oauth-proxy":   "github",
		"/passkey/verify-authentication": "passkey",
	} {
		if got := methodForRoute(route); got != want {
			t.Fatalf("the route %s recorded %q, want %q", route, got, want)
		}
	}
}
