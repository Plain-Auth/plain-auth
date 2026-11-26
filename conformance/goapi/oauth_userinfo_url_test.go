package goapi_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"golang.org/x/oauth2"
)

// userInfoProvider answers /token with token and /userinfo with status and
// profile, counting the user-info calls and keeping their Authorization.
type userInfoProvider struct {
	*httptest.Server
	token, profile string
	status         int
	calls          atomic.Int32
	authorization  atomic.Value
}

func newUserInfoProvider(t *testing.T) *userInfoProvider {
	t.Helper()
	p := &userInfoProvider{token: `{"access_token":"access","token_type":"Bearer"}`, status: 200}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			target, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
			target.RawQuery = url.Values{"code": {"c"}, "state": {r.URL.Query().Get("state")}}.Encode()
			http.Redirect(w, r, target.String(), http.StatusFound)
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(p.token))
		case "/userinfo":
			p.calls.Add(1)
			p.authorization.Store(r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(p.status)
			_, _ = w.Write([]byte(p.profile))
		}
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *userInfoProvider) provider() auth.OAuthProvider {
	return auth.OAuthProvider{
		Config:      oauth2.Config{ClientID: "client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{AuthURL: p.URL + "/authorize", TokenURL: p.URL + "/token"}},
		UserInfoURL: p.URL + "/userinfo",
	}
}

// cookieHeader returns the browser's cookies for the app.
func (n *tokenAuthNode) cookieHeader() string {
	u, _ := url.Parse(n.base)
	var parts []string
	for _, c := range n.browser.Jar.Cookies(u) {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// unsignedIDToken is a compact JWT with claims and no valid signature.
func unsignedIDToken(claims string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc([]byte(claims)) + ".c2ln"
}

// A provider with UserInfoURL and no Resolve reads the profile from that
// endpoint with the access token, a numeric id becoming the subject, or
// from an ID token in the token response that names a subject and an email,
// whose id claim, when it has one, names the account.
// A profile without an id, an error status or no email fails the sign-in,
// and New refuses an insecure endpoint, a missing profile source, and
// UserInfoURL alongside Resolve.
func TestOAuthUserInfoURL(t *testing.T) {
	idp := newUserInfoProvider(t)
	idp.profile = `{"id":42,"email":"person@example.org","email_verified":"true","name":"Person","picture":"https://img.example/p.png","plan":"pro"}`
	n, err := newTokenAuthNode(t, idp.provider())
	if err != nil {
		t.Fatal(err)
	}
	if to := n.signIn(t); to != "/done" {
		t.Fatal("the sign-in landed at", to)
	}
	if session, _ := n.node.GetSession(t.Context(), http.Header{"Cookie": {n.cookieHeader()}}); session == nil || session.User.Email != "person@example.org" {
		t.Fatal("the browser has no session for the profile's email")
	}
	if idp.calls.Load() != 1 || idp.authorization.Load() != "Bearer access" {
		t.Fatal("the user-info endpoint saw", idp.calls.Load(), idp.authorization.Load())
	}
	res, err := n.browser.Get(n.base + "/api/auth/account-info?accountId=" + n.accountID(t))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var info struct {
		User struct {
			Name, Email   string
			EmailVerified bool
			Image         string
		}
		Account struct{ AccountID string }
		Data    map[string]any
	}
	if err := json.NewDecoder(res.Body).Decode(&info); err != nil || res.StatusCode != 200 {
		t.Fatal("account-info answered", res.StatusCode, err)
	}
	if info.Account.AccountID != "42" || info.User.Email != "person@example.org" || !info.User.EmailVerified || info.User.Name != "Person" ||
		info.User.Image != "https://img.example/p.png" || info.Data["plan"] != "pro" || info.Data["id"] != float64(42) || info.Data["emailVerified"] != true {
		t.Fatalf("account-info returned %+v", info)
	}

	idp = newUserInfoProvider(t)
	idp.token = `{"access_token":"access","token_type":"Bearer","id_token":"` + unsignedIDToken(`{"sub":"subject-1","email":"token@example.org","email_verified":true,"name":"Token"}`) + `"}`
	if n, err = newTokenAuthNode(t, idp.provider()); err != nil {
		t.Fatal(err)
	}
	if to := n.signIn(t); to != "/done" || idp.calls.Load() != 0 {
		t.Fatal("the ID token sign-in landed at", to, "after", idp.calls.Load(), "user-info calls")
	}
	r, _ := http.NewRequest("GET", n.base+"/api/auth/get-session", nil)
	if res, err := n.browser.Do(r); err != nil {
		t.Fatal(err)
	} else {
		var session struct{ User struct{ Email string } }
		_ = json.NewDecoder(res.Body).Decode(&session)
		res.Body.Close()
		if session.User.Email != "token@example.org" {
			t.Fatal("the ID token's user is", session.User.Email)
		}
	}

	idp = newUserInfoProvider(t)
	idp.token = `{"access_token":"access","token_type":"Bearer","id_token":"` + unsignedIDToken(`{"sub":"s-1","id":"42","email":"named@example.org"}`) + `"}`
	if n, err = newTokenAuthNode(t, idp.provider()); err != nil {
		t.Fatal(err)
	}
	if to := n.signIn(t); to != "/done" {
		t.Fatal("the ID token with an id claim landed at", to)
	}
	res, err = n.browser.Get(n.base + "/api/auth/account-info?accountId=" + n.accountID(t))
	if err != nil {
		t.Fatal(err)
	}
	var named struct {
		Account struct{ AccountID string }
		Data    map[string]any
	}
	_ = json.NewDecoder(res.Body).Decode(&named)
	res.Body.Close()
	if named.Account.AccountID != "42" || named.Data["id"] != "42" {
		t.Fatalf("an id claim gave account %q and data id %v", named.Account.AccountID, named.Data["id"])
	}

	for _, tc := range []struct {
		name, profile, want string
		status              int
	}{
		{"only sub", `{"sub":"subject","email":"person@example.org"}`, "unable_to_get_user_info", 200},
		{"error status", `{"id":"1","email":"person@example.org"}`, "unable_to_get_user_info", 401},
		{"not an object", `["id"]`, "unable_to_get_user_info", 200},
		{"no email", `{"id":"1"}`, "email_not_found", 200},
	} {
		idp := newUserInfoProvider(t)
		idp.profile, idp.status = tc.profile, tc.status
		n, err := newTokenAuthNode(t, idp.provider())
		if err != nil {
			t.Fatal(err)
		}
		if to := n.signIn(t); !strings.HasPrefix(to, "/oops?error="+tc.want) {
			t.Fatal(tc.name, "landed at", to)
		}
		if session, _ := n.node.GetSession(t.Context(), http.Header{"Cookie": {n.cookieHeader()}}); session != nil {
			t.Fatal(tc.name, "signed the browser in")
		}
	}

	insecure := idp.provider()
	insecure.UserInfoURL = "http://idp.example/userinfo"
	both := idp.provider()
	both.Resolve = workProvider(idp.Server, "secret", auth.TokenEndpointAuth{}).Resolve
	for name, p := range map[string]auth.OAuthProvider{"plain HTTP": insecure, "no profile source": {Config: insecure.Config}, "both": both} {
		if _, err := newTokenAuthNode(t, p); err == nil {
			t.Fatal("New accepted", name)
		}
	}
}
