package oauthprovider_test

import (
	"context"
	"testing"

	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// New refuses extension authentication methods that are reserved, empty,
// without Authenticate, or with a relative, jwt-bearer, empty or repeated
// assertion type, and accepts an extension method in the advertised list.
func TestExtensionClientAuthenticationOptions(t *testing.T) {
	authenticate := func(context.Context, op.ClientAuthenticationInput) (op.ClientAuthenticationResult, error) {
		return op.ClientAuthenticationResult{}, nil
	}
	strategy := func(types ...string) op.ClientAuthenticationStrategy {
		return op.ClientAuthenticationStrategy{AssertionTypes: types, Authenticate: authenticate}
	}
	with := func(methods ...map[string]op.ClientAuthenticationStrategy) op.Options {
		var extensions []op.Extension
		for _, m := range methods {
			extensions = append(extensions, op.Extension{ClientAuthentication: m})
		}
		return op.Options{Scopes: []string{"reports"}, Extensions: extensions}
	}
	for name, opts := range map[string]op.Options{
		"reserved":         with(map[string]op.ClientAuthenticationStrategy{"private_key_jwt": strategy("urn:test:a")}),
		"none":             with(map[string]op.ClientAuthenticationStrategy{"none": strategy("urn:test:a")}),
		"empty name":       with(map[string]op.ClientAuthenticationStrategy{" ": strategy("urn:test:a")}),
		"no authenticate":  with(map[string]op.ClientAuthenticationStrategy{"assertion": {AssertionTypes: []string{"urn:test:a"}}}),
		"relative type":    with(map[string]op.ClientAuthenticationStrategy{"assertion": strategy("relative")}),
		"jwt-bearer":       with(map[string]op.ClientAuthenticationStrategy{"assertion": strategy(op.ClientAssertionType)}),
		"empty types":      with(map[string]op.ClientAuthenticationStrategy{"assertion": {AssertionTypes: []string{}, Authenticate: authenticate}}),
		"name not a URI":   with(map[string]op.ClientAuthenticationStrategy{"assertion": {Authenticate: authenticate}}),
		"repeated method":  with(map[string]op.ClientAuthenticationStrategy{"assertion": strategy("urn:test:a")}, map[string]op.ClientAuthenticationStrategy{"assertion": strategy("urn:test:b")}),
		"repeated type":    with(map[string]op.ClientAuthenticationStrategy{"one": strategy("urn:test:a")}, map[string]op.ClientAuthenticationStrategy{"two": strategy("urn:test:a")}),
		"advertised other": {Scopes: []string{"reports"}, Metadata: op.IssuerMetadataOptions{TokenAuthMethods: []string{"assertion"}}},
	} {
		if _, err := op.New(opts); err == nil {
			t.Error("extension authentication options were accepted", name)
		}
	}
	opts := with(map[string]op.ClientAuthenticationStrategy{"assertion": strategy("urn:test:a")}, map[string]op.ClientAuthenticationStrategy{"urn:test:method": {Authenticate: authenticate}})
	opts.Metadata.TokenAuthMethods = []string{"assertion", "client_secret_basic"}
	if _, err := op.New(opts); err != nil {
		t.Fatal("valid extension authentication options were refused", err)
	}
}
