package goapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"golang.org/x/oauth2"
)

// postWith is post with extra request headers.
func (n *tokenAuthNode) postWith(t *testing.T, path, body string, header http.Header) *http.Response {
	t.Helper()
	r, _ := http.NewRequest("POST", n.base+"/api/auth"+path, strings.NewReader(body))
	for k, v := range header {
		r.Header[k] = v
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", n.base)
	res, err := n.browser.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

// accountID returns the signed-in user's only linked account.
func (n *tokenAuthNode) accountID(t *testing.T) string {
	t.Helper()
	res, err := n.browser.Get(n.base + "/api/auth/list-accounts")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var accounts []struct{ ID string }
	if err := json.NewDecoder(res.Body).Decode(&accounts); err != nil || len(accounts) != 1 {
		t.Fatal("no linked account:", err)
	}
	return accounts[0].ID
}

// TokenParams reach the code exchange only and TokenHeaders reach the code
// exchange and the refresh, never a profile request, and never replace a
// header the request sets; New refuses the protocol fields, a request that
// ExchangeCode or Refresh replaces, and invalid headers.
func TestOAuthTokenParamsAndHeaders(t *testing.T) {
	srv, received := tokenProvider(t)
	p := workProvider(srv, "secret", auth.TokenEndpointAuth{})
	p.Config.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	p.TokenParams = url.Values{"audience": {"api"}, "resource": {"https://api.example"}}
	p.TokenHeaders = http.Header{"x-qonto-staging-token": {"staging"}, "Authorization": {"Bearer configured"}}
	p.Resolve = func(ctx context.Context, _ *oauth2.Token, _ string) (auth.OAuthProfile, error) {
		res, err := ctx.Value(oauth2.HTTPClient).(*http.Client).Get(srv.URL + "/userinfo")
		if err != nil {
			return auth.OAuthProfile{}, err
		}
		res.Body.Close()
		return auth.OAuthProfile{Subject: "subject", Email: "person@example.org", EmailVerified: true}, nil
	}
	n, err := newTokenAuthNode(t, p)
	if err != nil {
		t.Fatal(err)
	}
	if to := n.signIn(t); to != "/done" {
		t.Fatal("the sign-in landed at", to)
	}
	got := received()
	if len(got) != 2 || got[0].path != "/token" || got[1].path != "/userinfo" {
		t.Fatal("the provider saw", got)
	}
	exchange := got[0]
	user, secret, ok := (&http.Request{Header: exchange.header}).BasicAuth()
	if exchange.form.Get("audience") != "api" || exchange.form.Get("resource") != "https://api.example" || exchange.form.Get("code") != "c" ||
		exchange.header.Get("X-Qonto-Staging-Token") != "staging" || !ok || user != "client" || secret != "secret" {
		t.Fatalf("the code exchange sent %v %v", exchange.form, exchange.header)
	}
	if got[1].header.Get("X-Qonto-Staging-Token") != "" {
		t.Fatal("the profile request carried a token header")
	}
	if status := n.refresh(t); status != 200 {
		t.Fatal("the refresh answered", status)
	}
	got = received()
	if len(got) != 1 || got[0].form.Get("grant_type") != "refresh_token" || got[0].header.Get("X-Qonto-Staging-Token") != "staging" || got[0].form.Has("audience") {
		t.Fatal("the refresh sent", got)
	}
	exchangeCode := func(context.Context, oauth2.Config, string, string, url.Values) (*oauth2.Token, error) {
		return nil, errors.New("unused")
	}
	refresh := func(context.Context, oauth2.Config, string) (*oauth2.Token, error) { return nil, errors.New("unused") }
	refused := map[string]func(*auth.OAuthProvider){
		"TokenParams with ExchangeCode": func(p *auth.OAuthProvider) {
			p.TokenParams = url.Values{"audience": {"api"}}
			p.ExchangeCode = exchangeCode
		},
		"TokenHeaders with ExchangeCode": func(p *auth.OAuthProvider) { p.TokenHeaders = http.Header{"X-A": {"a"}}; p.ExchangeCode = exchangeCode },
		"TokenHeaders with Refresh":      func(p *auth.OAuthProvider) { p.TokenHeaders = http.Header{"X-A": {"a"}}; p.Refresh = refresh },
		"two values":                     func(p *auth.OAuthProvider) { p.TokenParams = url.Values{"audience": {"a", "b"}} },
		"invalid header name":            func(p *auth.OAuthProvider) { p.TokenHeaders = http.Header{"Bad Name": {"a"}} },
		"invalid header value":           func(p *auth.OAuthProvider) { p.TokenHeaders = http.Header{"X-A": {"a\r\nX-B: b"}} },
	}
	for _, field := range []string{"grant_type", "code", "redirect_uri", "code_verifier", "refresh_token", "client_id", "client_secret", "client_assertion", "client_assertion_type"} {
		refused["TokenParams "+field] = func(p *auth.OAuthProvider) { p.TokenParams = url.Values{field: {"x"}} }
	}
	for name, change := range refused {
		p := workProvider(srv, "secret", auth.TokenEndpointAuth{})
		change(&p)
		if _, err := newTokenAuthNode(t, p); err == nil {
			t.Fatal("New accepted", name)
		}
	}
}

// RefreshParams adds fields to the refresh request, computed from the
// triggering request and the account's owner, before the account is locked:
// it can read the session through the store's only connection. nil adds
// nothing, a redirect_uri is sent, a failure or a field the refresh or
// client authentication sets fails the refresh without calling the
// provider, and a trusted server call passes no headers.
func TestOAuthRefreshParams(t *testing.T) {
	srv, received := tokenProvider(t)
	var mu sync.Mutex
	var calls []auth.OAuthRefreshRequest
	var n *tokenAuthNode
	result := func(r auth.OAuthRefreshRequest) (url.Values, error) {
		return url.Values{"audience": {"api"}, "organization": {r.Header.Get("X-Active-Org")}}, nil
	}
	p := workProvider(srv, "secret", auth.TokenEndpointAuth{})
	p.RefreshParams = func(ctx context.Context, r auth.OAuthRefreshRequest) (url.Values, error) {
		mu.Lock()
		calls = append(calls, r)
		mu.Unlock()
		if r.Header != nil {
			if session, err := n.node.GetSession(ctx, r.Header); err != nil || session == nil || session.User.ID != r.UserID {
				return nil, errors.New("the session could not be read")
			}
		}
		return result(r)
	}
	var err error
	if n, err = newTokenAuthNode(t, p); err != nil {
		t.Fatal(err)
	}
	if to := n.signIn(t); to != "/done" {
		t.Fatal("the sign-in landed at", to)
	}
	received()
	account := n.accountID(t)
	refreshWith := func(org string) *http.Response {
		return n.postWith(t, "/refresh-token", `{"accountId":"`+account+`"}`, http.Header{"X-Active-Org": {org}})
	}
	if res := refreshWith("org-1"); res.StatusCode != 200 {
		t.Fatal("the refresh answered", res.StatusCode, errorCode(t, res))
	}
	got := received()
	if len(got) != 1 || got[0].form.Get("grant_type") != "refresh_token" || got[0].form.Get("refresh_token") != "refresh" ||
		got[0].form.Get("audience") != "api" || got[0].form.Get("organization") != "org-1" {
		t.Fatal("the refresh sent", got)
	}
	if user, secret, ok := (&http.Request{Header: got[0].header}).BasicAuth(); !ok && got[0].form.Get("client_secret") != "secret" || ok && (user != "client" || secret != "secret") {
		t.Fatal("the refresh did not authenticate the client")
	}
	mu.Lock()
	first := calls[len(calls)-1]
	mu.Unlock()
	if first.AccountID != account || first.UserID == "" || first.Header.Get("X-Active-Org") != "org-1" {
		t.Fatalf("RefreshParams saw %+v", first)
	}
	if _, err := n.node.RefreshToken(context.Background(), nil, auth.AccountSelection{UserID: first.UserID, AccountID: account}); err != nil {
		t.Fatal("the server refresh failed:", err)
	}
	mu.Lock()
	server := calls[len(calls)-1]
	mu.Unlock()
	if server.Header != nil || server.UserID != first.UserID || server.AccountID != account {
		t.Fatalf("the server refresh passed %+v", server)
	}
	received()
	result = func(auth.OAuthRefreshRequest) (url.Values, error) { return nil, nil }
	if res := refreshWith("org-1"); res.StatusCode != 200 {
		t.Fatal("the refresh with no fields answered", res.StatusCode)
	}
	if got := received(); len(got) != 1 || len(got[0].form) != 2 {
		t.Fatal("nil added fields:", got)
	}
	result = func(auth.OAuthRefreshRequest) (url.Values, error) {
		return url.Values{"redirect_uri": {"https://app.example/callback"}}, nil
	}
	if res := refreshWith("org-1"); res.StatusCode != 200 {
		t.Fatal("a refresh with redirect_uri answered", res.StatusCode)
	}
	if got := received(); len(got) != 1 || got[0].form.Get("redirect_uri") != "https://app.example/callback" {
		t.Fatal("redirect_uri did not reach the provider:", got)
	}
	for name, fails := range map[string]func(auth.OAuthRefreshRequest) (url.Values, error){
		"an error":      func(auth.OAuthRefreshRequest) (url.Values, error) { return nil, errors.New("no entitlement") },
		"grant_type":    func(auth.OAuthRefreshRequest) (url.Values, error) { return url.Values{"grant_type": {"password"}}, nil },
		"refresh_token": func(auth.OAuthRefreshRequest) (url.Values, error) { return url.Values{"refresh_token": {"other"}}, nil },
		"client_id":     func(auth.OAuthRefreshRequest) (url.Values, error) { return url.Values{"client_id": {"other"}}, nil },
		"client_secret": func(auth.OAuthRefreshRequest) (url.Values, error) { return url.Values{"client_secret": {"other"}}, nil },
		"client_assertion": func(auth.OAuthRefreshRequest) (url.Values, error) {
			return url.Values{"client_assertion": {"other"}}, nil
		},
	} {
		result = fails
		res := refreshWith("org-1")
		if code := errorCode(t, res); res.StatusCode != 400 || code != "FAILED_TO_REFRESH_ACCESS_TOKEN" {
			t.Fatal(name, "answered", res.StatusCode, code)
		}
		if got := received(); len(got) != 0 {
			t.Fatal(name, "still called the provider")
		}
	}
	p.Refresh = func(context.Context, oauth2.Config, string) (*oauth2.Token, error) { return nil, errors.New("unused") }
	if _, err := newTokenAuthNode(t, p); err == nil {
		t.Fatal("New accepted RefreshParams with Refresh")
	}
}
