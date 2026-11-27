package oauthprovider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
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
		{"prompt", "login\tconsent", "invalid_request"}, {"prompt", "consent\u0085", "invalid_request"},
		{"max_age", "-1", "invalid_request"}, {"code_challenge_method", "plain", "invalid_request"}, {"claims", "{}", "invalid_request"},
		{"resource", "https://api.example.test/#frag", "invalid_request"}, {"dpop_jkt", "binding", "invalid_request"},
	} {
		q := url.Values{"response_type": {"code"}, "code_challenge": {"digest"}, "code_challenge_method": {"S256"}}
		q.Set(tc.k, tc.v)
		if _, err := opts.browserGrant(base, q); err == nil || err.Code != tc.code {
			t.Errorf("%s: %v", tc.k, err)
		}
	}
	// A dpop_jkt in thumbprint form is kept for the exchange.
	jkt := strings.Repeat("A", 43)
	if request, err := opts.browserGrant(base, url.Values{"response_type": {"code"}, "code_challenge": {"digest"}, "code_challenge_method": {"S256"}, "dpop_jkt": {jkt}}); err != nil || request.Query["dpop_jkt"] != jkt {
		t.Fatal("a dpop_jkt was not kept", err)
	}
	// Resource indicators keep their request order without repeats, up to 64.
	indicators := url.Values{"response_type": {"code"}, "code_challenge": {"digest"}, "code_challenge_method": {"S256"}, "resource": {"urn:b", "urn:a", "urn:b"}}
	if request, err := opts.browserGrant(base, indicators); err != nil || !slices.Equal(request.Resources, []string{"urn:b", "urn:a"}) {
		t.Fatal("resource indicators were not kept in order without repeats", request.Resources, err)
	}
	indicators["resource"] = make([]string, 65)
	for i := range indicators["resource"] {
		indicators["resource"][i] = "urn:r" + strconv.Itoa(i)
	}
	if _, err := opts.browserGrant(base, indicators); err == nil || err.Code != "invalid_target" {
		t.Fatal("more than 64 resource indicators were accepted", err)
	}
	// Each supported prompt and the query response mode are accepted, and a
	// prompt list loses its repeats and extra spaces.
	for _, prompt := range []string{"none", "login", "consent", "select_account", "create"} {
		q := url.Values{"response_type": {"code"}, "code_challenge": {"digest"}, "code_challenge_method": {"S256"}, "prompt": {prompt}, "response_mode": {"query"}}
		if request, err := opts.browserGrant(base, q); err != nil || !slices.Equal(request.prompts, []string{prompt}) {
			t.Fatal("a supported prompt was refused", prompt, err)
		}
	}
	if request, err := opts.browserGrant(base, url.Values{"response_type": {"code"}, "code_challenge": {"digest"}, "code_challenge_method": {"S256"}, "prompt": {"login  consent login\t \ufefflogin"}}); err != nil || !slices.Equal(request.prompts, []string{"login", "consent"}) {
		t.Fatal("a prompt list kept its repeats", request.prompts, err)
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

// An authorization response keeps the spelling of a registered deep link,
// whose "//" url.URL.String would drop for an empty host.
func TestBrowserRedirectKeepsDeepLinks(t *testing.T) {
	c := auth.EndpointContext{Request: httptest.NewRequest("GET", "https://issuer.example/authorize", nil), ResponseHeader: http.Header{}}
	values := url.Values{"code": {"x"}, "state": {"s"}}
	for target, want := range map[string]string{
		"myapp://":            "myapp://?code=x&state=s",
		"myapp://?app=1":      "myapp://?app=1&code=x&state=s",
		"myapp:/callback":     "myapp:/callback?code=x&state=s",
		"https://app.example": "https://app.example?code=x&state=s",
	} {
		if got := browserRedirect(c, target, values, false); got != auth.Redirect(want) {
			t.Errorf("query response to %q = %v, want %q", target, got, want)
		}
	}
	if got := browserRedirect(c, "myapp://", values, true); got != auth.Redirect("myapp://#code=x&state=s") {
		t.Errorf("fragment response = %v", got)
	}
}

// RequireOpenID refuses a request whose scope parameter omits openid, and
// the default scopes do not satisfy it; every unknown scope is named.
func TestRequireOpenIDAtAuthorization(t *testing.T) {
	if _, err := New(Options{Scopes: []string{"read"}, Authorization: BrowserAuthorizationOptions{RequireOpenID: true}}); err == nil {
		t.Fatal("RequireOpenID was accepted without openid in Scopes")
	}
	strict := Options{Scopes: []string{"openid", "read"}, Authorization: BrowserAuthorizationOptions{RequireOpenID: true}}
	client := BrowserClient{AuthMethod: "none"}
	request := func(scope *string) url.Values {
		q := url.Values{"response_type": {"code"}, "code_challenge": {"digest"}, "code_challenge_method": {"S256"}}
		if scope != nil {
			q.Set("scope", *scope)
		}
		return q
	}
	for _, scope := range []*string{nil, new(string), ptr("read")} {
		if _, err := strict.browserGrant(client, request(scope)); err == nil || err.Code != "invalid_scope" || err.Description != "the openid scope is required" {
			t.Errorf("a request without openid was not refused: %v", err)
		}
	}
	if got, err := strict.browserGrant(client, request(ptr("read openid"))); err != nil || !slices.Equal(got.Scopes, []string{"read", "openid"}) {
		t.Fatal("a request with openid was refused", got.Scopes, err)
	}
	if _, err := strict.browserGrant(client, request(ptr("write read extra"))); err == nil || err.Description != "The following scopes are invalid: write, extra" {
		t.Fatal("unknown scopes were not all named", err)
	}
}

func ptr(s string) *string { return &s }
