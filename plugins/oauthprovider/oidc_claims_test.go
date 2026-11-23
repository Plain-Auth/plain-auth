package oauthprovider

import (
	"net/url"
	"testing"
	"time"
)

func TestOpenIDClaimRequirements(t *testing.T) {
	for _, test := range []struct{ claims, problem string }{
		{`{"userinfo":{"email":null},"id_token":{"acr":{"essential":true,"values":["1","0"]}}}`, ""},
		{`{"id_token":{"acr":{"essential":false,"value":"1"}}}`, ""},
		{`{"id_token":{"acr":{"essential":true,"value":"2"}}}`, "access_denied"},
		{`{"id_token":{"acr":{"essential":true,"values":[]}}}`, "access_denied"},
		{`{"id_token":{"acr":{"values":[0]}}}`, "invalid_request"},
		{`{"id_token":{"acr":{"value":0}}}`, "invalid_request"},
		{`{"id_token":{"acr":{"essential":"true"}}}`, "invalid_request"},
		{`{"userinfo":[]}`, "invalid_request"}, {`null`, "invalid_request"},
	} {
		_, problem := parseOIDCClaims(test.claims)
		if problem == nil && test.problem != "" || problem != nil && problem.Code != test.problem {
			t.Errorf("claims %s: got %v, expected %q", test.claims, problem, test.problem)
		}
	}
	// Reject impossible assurance before asking a public client for PKCE.
	client := BrowserClient{AuthMethod: "none", Scopes: []string{"openid"}}
	_, err := (Options{}).browserGrant(client, url.Values{"response_type": {"code"}, "claims": {`{"id_token":{"acr":{"essential":true,"value":"2"}}}`}})
	if err == nil || err.Code != "access_denied" {
		t.Fatalf("unexpected authorization error: %v", err)
	}
}

func TestIDTokenLifetime(t *testing.T) {
	for _, invalid := range []time.Duration{-time.Second, time.Millisecond, 1500 * time.Millisecond} {
		if _, err := New(Options{Tokens: TokenOptions{IDTokenLifetime: invalid}}); err == nil {
			t.Errorf("accepted ID token lifetime %s", invalid)
		}
	}
}
