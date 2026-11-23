package sso

import (
	"context"
	"errors"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

func TestSAMLPortalLanding(t *testing.T) {
	const base = "https://login.example.test"
	const path = "/auth/sso/saml2/sp/acs/work"
	a, err := auth.New(auth.Options{Store: memory.New(), BaseURL: base, Secret: strings.Repeat("x", 48), TrustedOrigins: []string{"https://app.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	c := auth.EndpointContext{Auth: a}
	for _, test := range []struct {
		input []string
		want  string
	}{
		{[]string{"/provider", "/global", "/fallback"}, base + "/provider"},
		{[]string{"https://other.example.test", "/global", "/fallback"}, base + "/global"},
		{[]string{path, "", "/fallback"}, base + "/fallback"},
		{[]string{"//other.example.test", "https://login.example.test:443" + path + "?loop=1"}, base + "/"},
		{[]string{"https://app.example.test" + path}, "https://app.example.test" + path},
	} {
		if got := samlLanding(c, base+path, test.input...); got != test.want {
			t.Errorf("got landing %q; want %q", got, test.want)
		}
	}
	for _, raw := range []string{"//untrusted.example", "relative?query", "/a%5Cb", "javascript:unavailable"} {
		if _, err := New(Options{SAML: &SAMLOptions{IDPInitiatedCallbackURL: raw}}); err == nil {
			t.Fatal("invalid global portal callback accepted")
		}
	}
}

func TestSAMLPortalPolicyFailure(t *testing.T) {
	for _, p := range []SAMLDirectoryPolicy{
		func(context.Context, SAMLDirectory) (bool, error) { return true, errors.New("source unavailable") },
		func(context.Context, SAMLDirectory) (bool, error) { panic("source unavailable") },
	} {
		_, err := p.authorize(t.Context(), SAMLDirectory{})
		if err == nil {
			t.Fatal("expected failed authority lookup")
		}
	}
}
