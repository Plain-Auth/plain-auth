package oauthprovider_test

import (
	"context"
	"encoding/json"
	"reflect"
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

// New refuses an extension grant type that is relative, has no handler or
// is defined by two extensions, and accepts an absolute one.
func TestExtensionGrantOptions(t *testing.T) {
	handler := func(op.GrantInput) (op.TokenResponse, error) { return op.TokenResponse{}, nil }
	with := func(grants ...map[string]op.GrantHandler) op.Options {
		var extensions []op.Extension
		for _, g := range grants {
			extensions = append(extensions, op.Extension{Grants: g})
		}
		return op.Options{Scopes: []string{"reports"}, Extensions: extensions}
	}
	for name, opts := range map[string]op.Options{
		"relative":   with(map[string]op.GrantHandler{"device_code": handler}),
		"built-in":   with(map[string]op.GrantHandler{"client_credentials": handler}),
		"no handler": with(map[string]op.GrantHandler{"urn:test:grant": nil}),
		"repeated":   with(map[string]op.GrantHandler{"urn:test:grant": handler}, map[string]op.GrantHandler{"urn:test:grant": handler}),
	} {
		if _, err := op.New(opts); err == nil {
			t.Error("extension grant options were accepted", name)
		}
	}
	if _, err := op.New(with(map[string]op.GrantHandler{"urn:test:grant": handler})); err != nil {
		t.Fatal("a valid extension grant was refused", err)
	}
}

// A token response's added fields never replace a standard member, and an
// empty refresh or ID token is left out.
func TestTokenResponseFields(t *testing.T) {
	data, err := json.Marshal(op.TokenResponse{AccessToken: "a", TokenType: "Bearer", ExpiresIn: 60, Scope: "reports",
		Fields: map[string]any{"access_token": "b", "id_token": "c", "tenant": "acme"}})
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"access_token": "a", "token_type": "Bearer", "expires_in": float64(60), "expires_at": float64(0), "scope": "reports", "tenant": "acme"}
	if !reflect.DeepEqual(body, want) {
		t.Fatal("the token response was wrong", string(data))
	}
}
