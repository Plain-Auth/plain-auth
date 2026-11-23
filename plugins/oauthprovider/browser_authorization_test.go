package oauthprovider

import (
	"encoding/json"
	"net/url"
	"slices"
	"testing"
	"time"
)

func TestBrowserAuthorizationRules(t *testing.T) {
	for _, d := range []time.Duration{-time.Second, time.Millisecond} {
		if _, err := New(Options{Authorization: BrowserAuthorizationOptions{CodeLifetime: d}}); err == nil {
			t.Fatal("accepted invalid code lifetime")
		}
	}
	base := BrowserClient{AuthMethod: "none", ApplicationType: "native", RedirectURIs: []string{"http://127.0.0.1:3000/a%2Fb?x=1&y=2", "http://[::1]/cb"}}
	for _, tc := range []struct {
		uri   string
		match bool
	}{
		{"http://127.0.0.1:4411/a%2Fb?x=1&y=2", true}, {"http://[::1]:4321/cb", true},
		{"http://localhost:4411/a%2Fb?x=1&y=2", false}, {"http://127.0.0.1:4411/a/b?x=1&y=2", false}, {"http://127.0.0.1:4411/a%2Fb?y=2&x=1", false},
	} {
		if base.matchesCallback(tc.uri) != tc.match {
			t.Error("incorrect native callback comparison", tc.uri)
		}
	}
	base.ApplicationType = "web"
	if base.matchesCallback("http://[::1]:4321/cb") {
		t.Fatal("web registration allowed a variable port")
	}
	opts := Options{Scopes: []string{"read"}}
	for _, tc := range []struct{ k, v, code string }{
		{"request", "signed", "request_not_supported"}, {"request_uri", "urn:entry", "request_uri_not_supported"},
		{"response_type", "token", "unsupported_response_type"}, {"response_mode", "form_post", "invalid_request"},
		{"scope", "write", "invalid_scope"}, {"prompt", "none consent", "invalid_request"}, {"prompt", "unknown", "invalid_request"},
		{"max_age", "-1", "invalid_request"}, {"code_challenge_method", "plain", "invalid_request"}, {"claims", "{}", "invalid_request"},
		{"resource", "urn:api", "invalid_target"}, {"dpop_jkt", "binding", "invalid_request"},
	} {
		q := url.Values{"response_type": {"code"}, "code_challenge": {"digest"}, "code_challenge_method": {"S256"}}
		q.Set(tc.k, tc.v)
		if _, err := opts.browserGrant(base, q); err == nil || err.Code != tc.code {
			t.Errorf("%s: %v", tc.k, err)
		}
	}
	q := url.Values{"response_type": {"code"}, "code_challenge": {"digest"}, "code_challenge_method": {"S256"}}
	request, err := opts.browserGrant(base, q)
	if err != nil || !slices.Equal(request.Scopes, opts.Scopes) {
		t.Fatal("missing scope did not inherit issuer scopes")
	}
	base.Scopes = []string{}
	request, err = opts.browserGrant(base, q)
	if err != nil || len(request.Scopes) != 0 {
		t.Fatal("an explicitly empty client list inherited scopes")
	}
	empty := ""
	code := storedAuthorizationCode{}
	code.Query.Scope = &empty
	code.Query.Challenge, code.Query.ChallengeMethod = tokenDigest("verifier"), "S256"
	client := AuthorizationCodeClient{MachineClient: MachineClient{AuthMethod: "none"}, Scopes: []string{"read"}}
	if scopes, err := code.scopesForExchange(client, tokenRequest{}, "verifier", ""); err != nil || len(scopes) != 0 {
		t.Fatal("could not redeem an explicitly empty scope grant", scopes, err)
	}
	if !browserFragmentError(url.Values{"response_type": {"id_token token"}, "response_mode": {"unknown"}}) || browserFragmentError(url.Values{"response_type": {"token"}, "response_mode": {"query"}}) {
		t.Fatal("incorrect error response mode")
	}
	now := time.Now()
	age := int64(5)
	issue := BrowserCodeIssue{MaxAge: &age}
	if !issue.SessionFresh(now.Add(-5*time.Second), now) || issue.SessionFresh(now.Add(-5001*time.Millisecond), now) {
		t.Fatal("incorrect max_age boundary")
	}
	age = 0
	if issue.SessionFresh(now, now) {
		t.Fatal("max_age=0 accepted an existing session")
	}
	for _, method := range []string{"GET", "POST"} {
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(browserAuthorizationOperation(method), &doc); err != nil || (doc["requestBody"] != nil) != (method == "POST") || (doc["parameters"] != nil) != (method == "GET") {
			t.Fatal("incorrect OpenAPI request transport", method)
		}
	}
}
