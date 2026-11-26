package goapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

// tokenRecord is one request a provider's token endpoint received.
type tokenRecord struct {
	path   string
	form   url.Values
	header http.Header
}

// tokenProvider serves /authorize, which approves with code "c", /token,
// which returns a refreshable token, and /userinfo; it records each token and
// user-info request.
func tokenProvider(t *testing.T) (*httptest.Server, func() []tokenRecord) {
	t.Helper()
	var mu sync.Mutex
	var seen []tokenRecord
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			target, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
			target.RawQuery = url.Values{"code": {"c"}, "state": {r.URL.Query().Get("state")}}.Encode()
			http.Redirect(w, r, target.String(), http.StatusFound)
		case "/token", "/userinfo":
			_ = r.ParseForm()
			mu.Lock()
			seen = append(seen, tokenRecord{path: r.URL.Path, form: r.PostForm, header: r.Header.Clone()})
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []tokenRecord {
		mu.Lock()
		defer mu.Unlock()
		out := seen
		seen = nil
		return out
	}
}

// tokenAuthNode is an Auth whose provider "work" authenticates with auth.
type tokenAuthNode struct {
	base    string
	browser *http.Client
	logs    *bytes.Buffer
	node    *auth.Auth
}

func newTokenAuthNode(t *testing.T, provider auth.OAuthProvider) (*tokenAuthNode, error) {
	t.Helper()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	app := httptest.NewUnstartedServer(nil)
	base := "http://" + app.Listener.Addr().String()
	logs := &bytes.Buffer{}
	node, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: base, RateLimit: new(bool),
		Logger: slog.New(slog.NewTextHandler(logs, nil)), SocialProviders: map[string]auth.OAuthProvider{"work": provider}})
	if err != nil {
		app.Close()
		return nil, err
	}
	app.Config.Handler = node
	app.Start()
	t.Cleanup(app.Close)
	jar, _ := cookiejar.New(nil)
	return &tokenAuthNode{base: base, browser: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, logs: logs, node: node}, nil
}

func (n *tokenAuthNode) post(t *testing.T, path, body string) *http.Response {
	t.Helper()
	r, _ := http.NewRequest("POST", n.base+"/api/auth"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", n.base)
	res, err := n.browser.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

// signIn runs the browser flow and returns where the callback sent it.
func (n *tokenAuthNode) signIn(t *testing.T) string {
	t.Helper()
	res := n.post(t, "/sign-in/social", `{"provider":"work","callbackURL":"/done","errorCallbackURL":"/oops","disableRedirect":true}`)
	var started struct{ URL string }
	if err := json.NewDecoder(res.Body).Decode(&started); err != nil || started.URL == "" {
		t.Fatal("the sign-in did not start:", res.StatusCode, err)
	}
	approved, err := n.browser.Get(started.URL)
	if err != nil {
		t.Fatal(err)
	}
	approved.Body.Close()
	done, err := n.browser.Get(approved.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	done.Body.Close()
	return done.Header.Get("Location")
}

// refresh refreshes the signed-in user's only account and returns the status.
func (n *tokenAuthNode) refresh(t *testing.T) int {
	t.Helper()
	r, _ := http.NewRequest("GET", n.base+"/api/auth/list-accounts", nil)
	res, err := n.browser.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var accounts []struct{ ID string }
	if err := json.NewDecoder(res.Body).Decode(&accounts); err != nil || len(accounts) != 1 {
		t.Fatal("no linked account:", err)
	}
	return n.post(t, "/refresh-token", `{"accountId":"`+accounts[0].ID+`"}`).StatusCode
}

func workProvider(srv *httptest.Server, secret string, method auth.TokenEndpointAuth) auth.OAuthProvider {
	return auth.OAuthProvider{
		Config:            oauth2.Config{ClientID: "client", ClientSecret: secret, Endpoint: oauth2.Endpoint{AuthURL: srv.URL + "/authorize", TokenURL: srv.URL + "/token"}},
		TokenEndpointAuth: method,
		Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) {
			return auth.OAuthProfile{Subject: "subject", Email: "person@example.org", EmailVerified: true, Name: "Person"}, nil
		},
	}
}

// Each token endpoint authentication method reaches both the code exchange
// and the refresh: Basic, form secret, a public client, a signed client
// assertion from the callback, and a custom authentication that sees only
// the grant fields.
func TestTokenEndpointAuthMethods(t *testing.T) {
	srv, received := tokenProvider(t)
	var mu sync.Mutex
	var assertions []auth.TokenRequest
	assertion := func(_ context.Context, r auth.TokenRequest) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		assertions = append(assertions, r)
		return "assertion-" + r.GrantType, nil
	}
	custom := func(_ context.Context, r auth.TokenRequest, form url.Values, header http.Header) error {
		if form.Has("client_id") || form.Has("client_secret") {
			return errors.New("the hook saw client credentials")
		}
		form.Set("client_id", r.ClientID)
		form.Set("client_assertion_type", "urn:vercel:params:oauth:client-assertion-type:oidc-bearer")
		form.Set("client_assertion", "workload-token")
		header.Set("X-Client-Auth", "custom")
		return nil
	}
	basicOverParams := workProvider(srv, "secret", auth.TokenEndpointAuth{Method: auth.TokenAuthClientSecretBasic})
	basicOverParams.Config.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	for _, tc := range []struct {
		name     string
		provider auth.OAuthProvider
		check    func(tokenRecord) bool
	}{
		{"basic", basicOverParams, func(r tokenRecord) bool {
			u, p, ok := (&http.Request{Header: r.header}).BasicAuth()
			return ok && u == "client" && p == "secret" && !r.form.Has("client_secret")
		}},
		{"post", workProvider(srv, "secret", auth.TokenEndpointAuth{Method: auth.TokenAuthClientSecretPost}), func(r tokenRecord) bool {
			return r.header.Get("Authorization") == "" && r.form.Get("client_id") == "client" && r.form.Get("client_secret") == "secret"
		}},
		{"none", workProvider(srv, "", auth.TokenEndpointAuth{Method: auth.TokenAuthNone}), func(r tokenRecord) bool {
			return r.header.Get("Authorization") == "" && r.form.Get("client_id") == "client" && !r.form.Has("client_secret")
		}},
		{"private_key_jwt", workProvider(srv, "", auth.TokenEndpointAuth{Method: auth.TokenAuthPrivateKeyJWT, ClientAssertion: assertion}), func(r tokenRecord) bool {
			return r.header.Get("Authorization") == "" && !r.form.Has("client_secret") && r.form.Get("client_id") == "client" &&
				r.form.Get("client_assertion_type") == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" && r.form.Get("client_assertion") == "assertion-"+r.form.Get("grant_type")
		}},
		{"custom", workProvider(srv, "", auth.TokenEndpointAuth{Method: auth.TokenAuthCustom, CustomizeRequest: custom}), func(r tokenRecord) bool {
			return r.header.Get("X-Client-Auth") == "custom" && r.header.Get("Authorization") == "" && r.form.Get("client_id") == "client" &&
				r.form.Get("client_assertion") == "workload-token" && !r.form.Has("client_secret")
		}},
		{"custom with a secret", workProvider(srv, "custom-client-secret-value", auth.TokenEndpointAuth{Method: auth.TokenAuthCustom, CustomizeRequest: custom}), func(r tokenRecord) bool {
			return r.header.Get("X-Client-Auth") == "custom" && r.header.Get("Authorization") == "" && r.form.Get("client_id") == "client" && !r.form.Has("client_secret")
		}},
	} {
		n, err := newTokenAuthNode(t, tc.provider)
		if err != nil {
			t.Fatal(tc.name, err)
		}
		if to := n.signIn(t); to != "/done" {
			t.Fatalf("%s: the sign-in landed at %s", tc.name, to)
		}
		if status := n.refresh(t); status != 200 {
			t.Fatalf("%s: the refresh answered %d", tc.name, status)
		}
		got := received()
		if len(got) != 2 || got[0].form.Get("grant_type") != "authorization_code" || got[0].form.Get("code") != "c" || got[0].form.Get("code_verifier") == "" ||
			got[1].form.Get("grant_type") != "refresh_token" || got[1].form.Get("refresh_token") != "refresh" {
			t.Fatalf("%s: the token endpoint received %+v", tc.name, got)
		}
		for _, r := range got {
			if !tc.check(r) {
				t.Fatalf("%s: a token request was authenticated wrongly: %v %v", tc.name, r.form, r.header)
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(assertions) != 2 || assertions[0].GrantType != "authorization_code" || assertions[1].GrantType != "refresh_token" || assertions[0].ClientID != "client" || assertions[0].TokenURL != srv.URL+"/token" {
		t.Fatalf("the assertion callback saw %+v", assertions)
	}
}

// New refuses token endpoint authentication that does not fit the
// provider's configuration.
func TestTokenEndpointAuthRefusals(t *testing.T) {
	srv, _ := tokenProvider(t)
	assertion := func(context.Context, auth.TokenRequest) (string, error) { return "a", nil }
	custom := func(context.Context, auth.TokenRequest, url.Values, http.Header) error { return nil }
	withExchange := workProvider(srv, "secret", auth.TokenEndpointAuth{Method: auth.TokenAuthClientSecretPost})
	withExchange.ExchangeCode = func(context.Context, oauth2.Config, string, string, url.Values) (*oauth2.Token, error) {
		return nil, nil
	}
	withRefresh := workProvider(srv, "secret", auth.TokenEndpointAuth{Method: auth.TokenAuthClientSecretPost})
	withRefresh.Refresh = func(context.Context, oauth2.Config, string) (*oauth2.Token, error) { return nil, nil }
	basicHeader := workProvider(srv, "", auth.TokenEndpointAuth{})
	basicHeader.Config.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	for name, p := range map[string]auth.OAuthProvider{
		"a callback without its method":       workProvider(srv, "", auth.TokenEndpointAuth{ClientAssertion: assertion}),
		"Basic without a secret":              basicHeader,
		"basic without a secret":              workProvider(srv, "", auth.TokenEndpointAuth{Method: auth.TokenAuthClientSecretBasic}),
		"post without a secret":               workProvider(srv, "", auth.TokenEndpointAuth{Method: auth.TokenAuthClientSecretPost}),
		"none with a secret":                  workProvider(srv, "secret", auth.TokenEndpointAuth{Method: auth.TokenAuthNone}),
		"private_key_jwt with a secret":       workProvider(srv, "secret", auth.TokenEndpointAuth{Method: auth.TokenAuthPrivateKeyJWT, ClientAssertion: assertion}),
		"private_key_jwt without a callback":  workProvider(srv, "", auth.TokenEndpointAuth{Method: auth.TokenAuthPrivateKeyJWT}),
		"custom without a hook":               workProvider(srv, "", auth.TokenEndpointAuth{Method: auth.TokenAuthCustom}),
		"an assertion for another method":     workProvider(srv, "secret", auth.TokenEndpointAuth{Method: auth.TokenAuthClientSecretPost, ClientAssertion: assertion}),
		"a hook for another method":           workProvider(srv, "secret", auth.TokenEndpointAuth{Method: auth.TokenAuthClientSecretPost, CustomizeRequest: custom}),
		"an unknown method":                   workProvider(srv, "secret", auth.TokenEndpointAuth{Method: "client_secret_jwt"}),
		"a method with ExchangeCode":          withExchange,
		"a method with a refresh replacement": withRefresh,
	} {
		if _, err := newTokenAuthNode(t, p); err == nil || !strings.Contains(err.Error(), `"work"`) {
			t.Fatalf("New accepted %s: %v", name, err)
		}
	}
}

// A failed assertion, a hook that changes a grant field or adds half an
// assertion, and a failing refresh assertion send nothing to the token
// endpoint, and no secret, assertion or callback error reaches a response
// or the log.
func TestTokenEndpointAuthFailuresSendNothing(t *testing.T) {
	srv, received := tokenProvider(t)
	failing := func(context.Context, auth.TokenRequest) (string, error) {
		return "", errors.New("private key service down")
	}
	empty := func(context.Context, auth.TokenRequest) (string, error) { return "", nil }
	hook := func(change func(url.Values)) func(context.Context, auth.TokenRequest, url.Values, http.Header) error {
		return func(_ context.Context, r auth.TokenRequest, form url.Values, _ http.Header) error {
			form.Set("client_id", r.ClientID)
			change(form)
			return nil
		}
	}
	for name, method := range map[string]auth.TokenEndpointAuth{
		"failing assertion": {Method: auth.TokenAuthPrivateKeyJWT, ClientAssertion: failing},
		"empty assertion":   {Method: auth.TokenAuthPrivateKeyJWT, ClientAssertion: empty},
		"changed code":      {Method: auth.TokenAuthCustom, CustomizeRequest: hook(func(f url.Values) { f.Set("code", "other") })},
		"changed redirect":  {Method: auth.TokenAuthCustom, CustomizeRequest: hook(func(f url.Values) { f.Set("redirect_uri", "https://evil.example") })},
		"changed verifier":  {Method: auth.TokenAuthCustom, CustomizeRequest: hook(func(f url.Values) { f.Del("code_verifier") })},
		"half assertion":    {Method: auth.TokenAuthCustom, CustomizeRequest: hook(func(f url.Values) { f.Set("client_assertion", "token") })},
		"failing custom hook": {Method: auth.TokenAuthCustom, CustomizeRequest: func(context.Context, auth.TokenRequest, url.Values, http.Header) error {
			return errors.New("workload token unavailable")
		}},
	} {
		secret := ""
		if method.Method == auth.TokenAuthCustom {
			secret = "custom-client-secret-value"
		}
		n, err := newTokenAuthNode(t, workProvider(srv, secret, method))
		if err != nil {
			t.Fatal(name, err)
		}
		if to := n.signIn(t); to != "/oops?error=invalid_code" {
			t.Fatalf("%s: the callback went to %s", name, to)
		}
		if got := received(); len(got) != 0 {
			t.Fatalf("%s: the token endpoint was called %d times", name, len(got))
		}
		if strings.Contains(n.logs.String(), "private key service down") || strings.Contains(n.logs.String(), "workload token unavailable") ||
			secret != "" && strings.Contains(n.logs.String(), secret) {
			t.Fatalf("%s: the callback's error or the secret reached the log", name)
		}
	}
	var fail bool
	var mu sync.Mutex
	assertion := func(context.Context, auth.TokenRequest) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return "", errors.New("signing key rotated away")
		}
		return "signed-assertion", nil
	}
	n, err := newTokenAuthNode(t, workProvider(srv, "", auth.TokenEndpointAuth{Method: auth.TokenAuthPrivateKeyJWT, ClientAssertion: assertion}))
	if err != nil {
		t.Fatal(err)
	}
	if to := n.signIn(t); to != "/done" {
		t.Fatal("the sign-in landed at", to)
	}
	received()
	mu.Lock()
	fail = true
	mu.Unlock()
	res := n.post(t, "/refresh-token", `{"accountId":"`+n.accountID(t)+`"}`)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 400 || strings.Contains(string(body), "signed-assertion") || strings.Contains(string(body), "signing key rotated away") {
		t.Fatal("a refresh with a failing assertion answered", res.StatusCode, string(body))
	}
	if got := received(); len(got) != 0 {
		t.Fatal("a failing refresh assertion still called the token endpoint")
	}
	if strings.Contains(n.logs.String(), "signed-assertion") || strings.Contains(n.logs.String(), "signing key rotated away") {
		t.Fatal("an assertion or its error reached the log")
	}
}
