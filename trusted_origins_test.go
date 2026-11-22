package plainauth_test

import (
	"strings"
	"testing"

	"github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
)

func TestWildcardOriginCallbacks(t *testing.T) {
	t.Setenv("AUTH_TRUSTED_ORIGINS", "*.store.example,https://preview-?.example:84??")
	a, err := plainauth.New(plainauth.Options{Store: memory.New(), BaseURL: "https://auth.example/login",
		Secret: strings.Repeat("x", 32), TrustedOrigins: []string{
			"https://*.apps.example", "http://192.168.*.*:*", "https://[::1]:8???",
			"https://branch.**.example", "https://portal*", "*://common.example:443", "https://media.example:*",
		}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		callback string
		trusted  bool
	}{
		{"/dashboard", true},
		{"https://auth.example/home", true},
		{"https://eu.web.apps.example/user?tab=profile#name", true},
		{"https://app.apps.example:443", true}, {"https://app.apps.example:8443", false},
		{"https://apps.example", false}, {"http://app.apps.example", false},
		{"https://app.apps.example.other.test", false},
		{"http://web.store.example", true}, {"https://web.store.example", true},
		{"https://preview-a.example:8443", true}, {"https://preview-ab.example:8443", false},
		{"https://preview-a.example:8843", false}, {"https://preview-a.example", false},
		{"http://192.168.1.2:8080", true}, {"http://192.168.dev.example:8080", false},
		{"https://[::1]:8123", true}, {"https://[::2]:8123", false},
		{"https://branch.one.two.example", true},
		{"https://portal-preview", true}, {"https://portal-preview:8443", false},
		{"https://common.example", true}, {"http://common.example:443", true},
		{"https://media.example:12345", true}, {"https://media.example", false},
		{"https://media.example:65536", false}, {"https://bad_label.apps.example", false},
		{"https://*.apps.example", false}, {"https://[web.apps.example]", false}, {"https://person@web.apps.example", false},
		{"ftp://web.store.example", false},
	} {
		t.Run(tc.callback, func(t *testing.T) {
			got, err := a.CallbackURL(tc.callback)
			if (err == nil) != tc.trusted || (tc.trusted && got == "") {
				t.Fatalf("CallbackURL(%q) returned %q, %v", tc.callback, got, err)
			}
		})
	}
}

func TestInvalidWildcardOriginConfiguration(t *testing.T) {
	t.Setenv("AUTH_TRUSTED_ORIGINS", "")
	for _, value := range []string{"*.shop.example/products", "https://user@*.shop.example", "https://*.shop.example#fragment",
		"https://*.shop.example:65536", "https://*.shop.example:", "https://*.shop.example:8x", "ftp://*.shop.example",
		"https://*.shop..example", "https://[::1]oops:*", "https://a.example?param=value"} {
		t.Run(value, func(t *testing.T) {
			_, err := plainauth.New(plainauth.Options{Store: memory.New(), BaseURL: "https://auth.example",
				Secret: strings.Repeat("x", 32), TrustedOrigins: []string{value}})
			if err == nil {
				t.Fatal("invalid wildcard origin accepted at startup")
			}
		})
	}
}
