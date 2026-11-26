package providers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

// browserFlow runs one browser sign-in with p under name: it starts the flow,
// has the provider return code "provider-code", finishes the callback and
// returns the instance, the callback's answer and the authorization URL.
type browserFlow struct {
	h         *auth.Auth
	callback  *httptest.ResponseRecorder
	authorize *url.URL
}

func runBrowserFlow(t *testing.T, name string, p auth.OAuthProvider) browserFlow {
	t.Helper()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	const base = "https://app.example.org"
	h, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: base, SocialProviders: map[string]auth.OAuthProvider{name: p}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", base+"/api/auth/sign-in/social", strings.NewReader(`{"provider":"`+name+`","callbackURL":"/done","errorCallbackURL":"/oops"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	u, err := url.Parse(res.Header().Get("Location"))
	if err != nil || res.Code != 200 {
		t.Fatalf("start: %d %v", res.Code, err)
	}
	callback := httptest.NewRequest("GET", base+"/api/auth/callback/"+name+"?"+url.Values{"code": {"provider-code"}, "state": {u.Query().Get("state")}}.Encode(), nil)
	for _, c := range res.Result().Cookies() {
		callback.AddCookie(c)
	}
	done := httptest.NewRecorder()
	h.ServeHTTP(done, callback)
	return browserFlow{h: h, callback: done, authorize: u}
}

// call sends a request with the flow's session cookies and decodes the JSON
// answer into out.
func (f browserFlow) call(t *testing.T, method, path, body string, out any) int {
	t.Helper()
	req := httptest.NewRequest(method, "https://app.example.org/api/auth"+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", "https://app.example.org")
	for _, c := range f.callback.Result().Cookies() {
		if c.MaxAge >= 0 {
			req.AddCookie(c)
		}
	}
	res := httptest.NewRecorder()
	f.h.ServeHTTP(res, req)
	if out != nil {
		if err := json.Unmarshal(res.Body.Bytes(), out); err != nil {
			t.Fatalf("%s answered %d with %s", path, res.Code, res.Body)
		}
	}
	return res.Code
}

func textResponse(status int, contentType, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {contentType}}, Body: io.NopCloser(strings.NewReader(body))}
}

// A GitHub browser sign-in authorizes with read:user and user:email and no
// nonce, exchanges the code once with the secret in the form, reads the
// verified primary address, and keeps a token response without a refresh
// token or expiry as it is.
func TestGitHubBrowserSignIn(t *testing.T) {
	var challenge string
	tokenCalls := 0
	p := GitHub("client", "secret")
	p.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case "https://github.com/login/oauth/access_token":
			tokenCalls++
			_ = r.ParseForm()
			if _, _, basic := r.BasicAuth(); basic || r.Form.Get("client_id") != "client" || r.Form.Get("client_secret") != "secret" || r.Form.Get("code") != "provider-code" || oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != challenge {
				t.Fatal("incorrect GitHub code exchange:", r.Form)
			}
			return textResponse(200, "application/x-www-form-urlencoded", "access_token=gho_x&scope=read%3Auser%2Cuser%3Aemail&token_type=bearer"), nil
		case "https://api.github.com/user":
			return textResponse(200, "application/json", `{"id":42,"login":"octo","email":null,"avatar_url":"https://avatars.example/42"}`), nil
		case "https://api.github.com/user/emails":
			return textResponse(200, "application/json", `[{"email":"other@example.org","primary":false,"verified":true},{"email":"octo@example.org","primary":true,"verified":true}]`), nil
		}
		t.Fatalf("unexpected request %s", r.URL)
		return nil, nil
	})}
	// The challenge is only known once the flow starts, so the token
	// endpoint reads it from the authorization URL captured here.
	p.CustomizeAuthorization = func(u *url.URL) { challenge = u.Query().Get("code_challenge") }
	f := runBrowserFlow(t, "github", p)
	q := f.authorize.Query()
	if f.authorize.Host != "github.com" || f.authorize.Path != "/login/oauth/authorize" || q.Get("client_id") != "client" || q.Get("scope") != "read:user user:email" ||
		q.Get("redirect_uri") != "https://app.example.org/api/auth/callback/github" || q.Get("code_challenge_method") != "S256" || q.Has("nonce") {
		t.Fatalf("authorize URL %s", f.authorize)
	}
	if f.callback.Code != 302 || f.callback.Header().Get("Location") != "/done" || tokenCalls != 1 {
		t.Fatalf("callback: %d %s (token calls %d)", f.callback.Code, f.callback.Header().Get("Location"), tokenCalls)
	}
	var session auth.SessionResult
	f.call(t, "GET", "/get-session", "", &session)
	if session.User.Email != "octo@example.org" || !session.User.EmailVerified || session.User.Name != "octo" || session.User.Image == nil || *session.User.Image != "https://avatars.example/42" {
		t.Fatalf("session user %+v", session.User)
	}
	var accounts []struct{ ID, ProviderID, AccountID string }
	f.call(t, "GET", "/list-accounts", "", &accounts)
	if len(accounts) != 1 || accounts[0].ProviderID != "github" || accounts[0].AccountID != "42" {
		t.Fatalf("accounts %+v", accounts)
	}
	var token struct {
		AccessToken          string
		AccessTokenExpiresAt *string
		Scopes               []string
	}
	if code := f.call(t, "POST", "/get-access-token", `{"accountId":"`+accounts[0].ID+`"}`, &token); code != 200 || token.AccessToken != "gho_x" || token.AccessTokenExpiresAt != nil || strings.Join(token.Scopes, " ") != "read:user user:email" {
		t.Fatalf("get-access-token %d %+v", code, token)
	}
	var refused struct{ Code string }
	if code := f.call(t, "POST", "/refresh-token", `{"accountId":"`+accounts[0].ID+`"}`, &refused); code != 400 || refused.Code != "REFRESH_TOKEN_NOT_FOUND" {
		t.Fatalf("refresh-token %d %+v", code, refused)
	}
	if tokenCalls != 1 {
		t.Fatal("the token endpoint was called again:", tokenCalls)
	}
}

// When GitHub refuses the email list, as for an app without the email
// permission, a profile without a public email answers email_not_found and a
// public email signs in unverified.
func TestGitHubWithoutEmailPermission(t *testing.T) {
	for _, public := range []string{"null", `"public@example.org"`} {
		p := GitHub("client", "secret")
		p.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.URL.String() {
			case "https://github.com/login/oauth/access_token":
				return textResponse(200, "application/json", `{"access_token":"gho_x","token_type":"bearer"}`), nil
			case "https://api.github.com/user":
				return textResponse(200, "application/json", `{"id":7,"login":"app","email":`+public+`}`), nil
			case "https://api.github.com/user/emails":
				return textResponse(403, "application/json", `{"message":"Resource not accessible by integration"}`), nil
			}
			t.Fatalf("unexpected request %s", r.URL)
			return nil, nil
		})}
		f := runBrowserFlow(t, "github", p)
		if public == "null" {
			if f.callback.Header().Get("Location") != "/oops?error=email_not_found" {
				t.Fatal("a profile without an email redirected to", f.callback.Header().Get("Location"))
			}
			for _, c := range f.callback.Result().Cookies() {
				if strings.HasSuffix(c.Name, "session_token") && c.MaxAge >= 0 {
					t.Fatal("a refused sign-in set a session cookie")
				}
			}
			continue
		}
		var session auth.SessionResult
		f.call(t, "GET", "/get-session", "", &session)
		if f.callback.Header().Get("Location") != "/done" || session.User.Email != "public@example.org" || session.User.EmailVerified {
			t.Fatalf("a public email signed in as %+v (%s)", session.User, f.callback.Header().Get("Location"))
		}
	}
}

// A Cloudflare client without a secret keeps PKCE, sends no client secret
// or Basic header in the code exchange, and refreshes with only client_id,
// grant_type and refresh_token.
func TestCloudflarePublicClient(t *testing.T) {
	p, err := New("cloudflare", "public-client", "")
	if err != nil {
		t.Fatal(err)
	}
	var challenge string
	refreshes := 0
	p.CustomizeAuthorization = func(u *url.URL) { challenge = u.Query().Get("code_challenge") }
	p.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case "https://dash.cloudflare.com/oauth2/token":
			_ = r.ParseForm()
			if _, _, basic := r.BasicAuth(); basic || r.Form.Has("client_secret") || r.Form.Get("client_id") != "public-client" {
				t.Fatal("a public Cloudflare client sent a secret:", r.Form)
			}
			if r.Form.Get("grant_type") == "refresh_token" {
				refreshes++
				if len(r.Form) != 3 || r.Form.Get("refresh_token") != "r1" {
					t.Fatal("unexpected refresh form:", r.Form)
				}
				return textResponse(200, "application/json", `{"access_token":"a2","refresh_token":"r2","token_type":"bearer","expires_in":3600}`), nil
			}
			if r.Form.Get("code") != "provider-code" || r.Form.Get("grant_type") != "authorization_code" || oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != challenge {
				t.Fatal("incorrect Cloudflare code exchange:", r.Form)
			}
			return textResponse(200, "application/json", `{"access_token":"a1","refresh_token":"r1","token_type":"bearer","expires_in":3600}`), nil
		case "https://api.cloudflare.com/client/v4/user":
			return textResponse(200, "application/json", `{"success":true,"result":{"id":"cf-sub","email":"person@example.org","first_name":"A","last_name":"Person"}}`), nil
		}
		t.Fatalf("unexpected request %s", r.URL)
		return nil, nil
	})}
	f := runBrowserFlow(t, "cloudflare", p)
	if f.authorize.Query().Get("code_challenge_method") != "S256" || f.callback.Header().Get("Location") != "/done" {
		t.Fatalf("flow: %s %s", f.authorize, f.callback.Header().Get("Location"))
	}
	var accounts []struct{ ID string }
	f.call(t, "GET", "/list-accounts", "", &accounts)
	if len(accounts) != 1 {
		t.Fatal("no Cloudflare account")
	}
	var refreshed struct{ AccessToken string }
	if code := f.call(t, "POST", "/refresh-token", `{"accountId":"`+accounts[0].ID+`"}`, &refreshed); code != 200 || refreshed.AccessToken != "a2" || refreshes != 1 {
		t.Fatalf("refresh-token %d %+v (%d refreshes)", code, refreshed, refreshes)
	}
}

// Cognito sends its identity provider and extra scopes with %20 between
// scopes, a call's additionalParams win, and RequireClientSecret refuses an
// empty secret.
func TestCognitoAuthorizationOptions(t *testing.T) {
	options := CognitoOptions{Domain: "auth.example.com", Region: "us-east-1", UserPoolID: "us-east-1_ABC123", IdentityProvider: "Google"}
	p, err := Cognito("client", "secret", options)
	if err != nil {
		t.Fatal(err)
	}
	if q := startAuthorization(t, "cognito", p, nil).Query(); q.Get("identity_provider") != "Google" {
		t.Fatal("the identity provider was not sent:", q)
	}
	if q := startAuthorization(t, "cognito", p, map[string]any{"additionalParams": map[string]any{"identity_provider": "COGNITO"}}).Query(); q.Get("identity_provider") != "COGNITO" {
		t.Fatal("a call's identity provider did not win:", q)
	}
	scoped := p
	scoped.Config.Scopes = append(append([]string{}, p.Config.Scopes...), "phone", "aws.cognito.signin.user.admin")
	u := startAuthorization(t, "cognito", scoped, nil)
	if u.Query().Get("scope") != "openid profile email phone aws.cognito.signin.user.admin" || !strings.Contains(u.RawQuery, "%20") || strings.Contains(u.RawQuery, "+") {
		t.Fatal("the extra scopes were not sent with %20:", u.RawQuery)
	}
	if u := startAuthorization(t, "cognito", p, map[string]any{"scopes": []string{"phone"}}); u.Query().Get("scope") != "openid profile email phone" {
		t.Fatal("a requested scope was not added:", u.Query().Get("scope"))
	}
	options.RequireClientSecret = true
	if _, err := Cognito("client", "", options); err == nil {
		t.Fatal("RequireClientSecret accepted an empty secret")
	}
	options.RequireClientSecret = false
	if _, err := Cognito("public-client", "", options); err != nil {
		t.Fatal("a public client was refused:", err)
	}
}
