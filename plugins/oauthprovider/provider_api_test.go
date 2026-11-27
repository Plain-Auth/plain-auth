package oauthprovider

import (
	"encoding/json"
	"slices"
	"testing"
)

// The token operation lists the extensions' grant types after the built-in
// ones, and clientAllowsGrant reads an empty registration as
// authorization_code, which also allows refresh_token.
func TestTokenOperationGrants(t *testing.T) {
	handler := func(GrantInput) (TokenResponse, error) { return TokenResponse{}, nil }
	opts := Options{GrantTypes: []string{"client_credentials"}, Extensions: []Extension{{Grants: map[string]GrantHandler{"urn:test:b": handler, "urn:test:a": handler}}}}
	var operation struct {
		RequestBody struct {
			Content map[string]struct {
				Schema struct {
					Properties struct {
						GrantType struct {
							Enum []string `json:"enum"`
						} `json:"grant_type"`
					} `json:"properties"`
				} `json:"schema"`
			} `json:"content"`
		} `json:"requestBody"`
	}
	if err := json.Unmarshal(opts.tokenOperation(), &operation); err != nil {
		t.Fatal(err)
	}
	got := operation.RequestBody.Content[tokenFormType].Schema.Properties.GrantType.Enum
	if !slices.Equal(got, []string{"client_credentials", "authorization_code", "refresh_token", "urn:test:a", "urn:test:b"}) {
		t.Fatal("the token operation's grant types were wrong", got)
	}
	if !slices.Equal(opts.supportedGrants(), []string{"client_credentials", "urn:test:a", "urn:test:b"}) {
		t.Fatal("the supported grants were wrong", opts.supportedGrants())
	}
	for _, c := range []struct {
		registered []string
		grant      string
		want       bool
	}{{nil, "authorization_code", true}, {nil, "refresh_token", true}, {nil, "urn:test:a", false}, {[]string{"urn:test:a"}, "urn:test:a", true}, {[]string{"urn:test:a"}, "refresh_token", false}} {
		if clientAllowsGrant(c.registered, c.grant) != c.want {
			t.Error("clientAllowsGrant was wrong", c.registered, c.grant)
		}
	}
}
