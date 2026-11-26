package providers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

// facebookGraph answers the Limited Login keys, debug_token and /me, and
// records the Graph requests.
type facebookGraph struct {
	jwks, debug, me string
	debugStatus     int
	seen            []string
}

func newFacebookGraph(t *testing.T, key *rsa.PrivateKey) *facebookGraph {
	t.Helper()
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, Algorithm: "RS256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	return &facebookGraph{jwks: string(jwks), debugStatus: 200,
		debug: `{"data":{"app_id":"app","user_id":"fb-user","is_valid":true}}`,
		me:    `{"id":"fb-user","name":"Person","email":"person@example.org","picture":{"data":{"url":"https://img.example/p.png"}}}`}
}

func (g *facebookGraph) client(t *testing.T) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.URL.String() == facebookKeys:
			return textResponse(200, "application/json", g.jwks), nil
		case r.URL.Host == "graph.facebook.com" && r.URL.Path == "/debug_token":
			q := r.URL.Query()
			g.seen = append(g.seen, "debug:"+q.Get("input_token")+":"+q.Get("access_token"))
			if g.debugStatus == http.StatusFound {
				return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"https://collector.example/steal"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			return textResponse(g.debugStatus, "application/json", g.debug), nil
		case r.URL.String() == "https://graph.facebook.com/me?fields=id%2Cname%2Cemail%2Cpicture":
			g.seen = append(g.seen, "me:"+r.Header.Get("Authorization"))
			return textResponse(200, "application/json", g.me), nil
		}
		t.Fatalf("unexpected request %s", r.URL)
		return nil, nil
	})}
}

func limitedLoginToken(t *testing.T, key *rsa.PrivateKey, issuer, aud, nonce string, extra map[string]any) string {
	t.Helper()
	claims := map[string]any{"aud": aud, "email": "person@example.org", "email_verified": true, "name": "Person", "picture": "https://img.example/p.png"}
	for k, v := range extra {
		claims[k] = v
	}
	return signedClaims(t, key, issuer, "fb-user", nonce, claims)
}

// A Limited Login ID token is accepted when Facebook signed it for the
// client ID or a listed audience, with the request's nonce and within the
// hour; its email is never marked verified.
func TestFacebookLimitedLogin(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	foreign, _ := rsa.GenerateKey(rand.Reader, 2048)
	g := newFacebookGraph(t, key)
	p := Facebook("app", "secret", FacebookOptions{Audiences: []string{"ios-app"}, HTTPClient: g.client(t)})
	for _, aud := range []string{"app", "ios-app"} {
		profile, _, err := p.VerifyIDToken(t.Context(), limitedLoginToken(t, key, facebookIssuer, aud, "n", nil), "n")
		if err != nil || profile.Subject != "fb-user" || profile.Email != "person@example.org" || profile.Name != "Person" ||
			profile.Image == nil || *profile.Image != "https://img.example/p.png" || profile.EmailVerified {
			t.Fatalf("a token for %s gave %+v, %v", aud, profile, err)
		}
	}
	for name, raw := range map[string]string{
		"an unlisted audience": limitedLoginToken(t, key, facebookIssuer, "other-app", "n", nil),
		"another issuer":       limitedLoginToken(t, key, "https://facebook.com", "app", "n", nil),
		"another nonce":        limitedLoginToken(t, key, facebookIssuer, "app", "other", nil),
		"an old token":         limitedLoginToken(t, key, facebookIssuer, "app", "n", map[string]any{"iat": time.Now().Add(-2 * time.Hour).Unix()}),
		"a foreign key":        limitedLoginToken(t, foreign, facebookIssuer, "app", "n", nil),
	} {
		if _, _, err := p.VerifyIDToken(t.Context(), raw, "n"); err == nil {
			t.Fatal("Limited Login accepted", name)
		}
	}
	if _, _, err := p.VerifyIDToken(t.Context(), limitedLoginToken(t, key, facebookIssuer, "app", "n", nil), ""); err == nil {
		t.Fatal("Limited Login accepted a token without the request's nonce")
	}
	if _, _, err := p.VerifyIDToken(t.Context(), limitedLoginToken(t, key, facebookIssuer, "app", "", nil), ""); err == nil {
		t.Fatal("Limited Login accepted a token and request without a nonce")
	}
	if p, _ := New("facebook", "app", "secret"); p.VerifyIDToken == nil || p.VerifyAccessToken == nil {
		t.Fatal("New(\"facebook\") has no direct sign-in")
	}
}

// A Facebook access token signs in once debug_token shows it is valid for
// the client ID or a listed audience and /me names the same user; a Limited
// Login token for that user and App ID then signs into the same account, one
// for a listed audience names that app's own user, a token without its nonce
// is refused, and account-info reads the Graph profile with the stored access
// token. A redirect from debug_token is not followed.
func TestFacebookAccessTokenSignIn(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	g := newFacebookGraph(t, key)
	p := Facebook("app", "secret", FacebookOptions{Audiences: []string{"ios-app"}, HTTPClient: g.client(t)})
	p.HTTPClient = g.client(t)
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const base = "https://app.example.org"
	h, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: base, RateLimit: new(bool), SocialProviders: map[string]auth.OAuthProvider{"facebook": p}})
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, base+"/api/auth"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", base)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		return res
	}
	var first struct{ User struct{ ID string } }
	res := call("POST", "/sign-in/social", `{"provider":"facebook","idToken":{"token":"EAAB-token","accessToken":"EAAB-token"}}`, nil)
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &first) != nil {
		t.Fatal("the access token sign-in answered", res.Code, res.Body)
	}
	if strings.Join(g.seen, ",") != "debug:EAAB-token:app|secret,me:Bearer EAAB-token" {
		t.Fatal("Graph saw", g.seen)
	}
	raw := limitedLoginToken(t, key, facebookIssuer, "app", "n", nil)
	if res := call("POST", "/sign-in/social", `{"provider":"facebook","idToken":{"token":"`+raw+`"}}`, nil); res.Code != 401 || !strings.Contains(res.Body.String(), "INVALID_TOKEN") {
		t.Fatal("a Limited Login token without its nonce answered", res.Code, res.Body)
	}
	var second struct{ User struct{ ID string } }
	res = call("POST", "/sign-in/social", `{"provider":"facebook","idToken":{"token":"`+raw+`","nonce":"n"}}`, nil)
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &second) != nil || second.User.ID != first.User.ID {
		t.Fatal("the Limited Login sign-in answered", res.Code, res.Body)
	}
	// Facebook gives each App ID its own user IDs, so a listed audience's
	// token names another subject: here a user of the iOS app.
	ios := limitedLoginToken(t, key, facebookIssuer, "ios-app", "n", map[string]any{"sub": "fb-ios-user", "email": "ios@example.org"})
	var third struct{ User struct{ ID string } }
	if res := call("POST", "/sign-in/social", `{"provider":"facebook","idToken":{"token":"`+ios+`","nonce":"n"}}`, nil); res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &third) != nil || third.User.ID == first.User.ID {
		t.Fatal("the listed audience's token answered", res.Code, res.Body)
	}
	var accounts []struct{ ID, AccountID string }
	if res := call("GET", "/list-accounts", "", res.Result().Cookies()); json.Unmarshal(res.Body.Bytes(), &accounts) != nil || len(accounts) != 1 || accounts[0].AccountID != "fb-user" {
		t.Fatal("the user's accounts are", res.Body)
	}
	g.seen = nil
	info, err := h.AccountInfo(t.Context(), nil, auth.AccountSelection{AccountID: accounts[0].ID, UserID: first.User.ID})
	if data, _ := info.Data.(profileData); err != nil || data["id"] != "fb-user" || len(g.seen) != 2 {
		t.Fatal("account-info returned", info.Data, err, g.seen)
	}

	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, g.client(t))
	for name, tc := range map[string]struct {
		debug, me string
		status    int
		valid     bool
	}{
		"a listed audience": {`{"data":{"app_id":"ios-app","user_id":"fb-user","is_valid":true}}`, g.me, 200, true},
		"another app":       {`{"data":{"app_id":"other-app","user_id":"fb-user","is_valid":true}}`, g.me, 200, false},
		"an invalid token":  {`{"data":{"app_id":"app","user_id":"fb-user","is_valid":false}}`, g.me, 200, false},
		"no user":           {`{"data":{"app_id":"app","is_valid":true}}`, g.me, 200, false},
		"another user":      {g.debug, `{"id":"someone-else","email":"person@example.org"}`, 200, false},
		"a redirect":        {g.debug, g.me, http.StatusFound, false},
	} {
		check := *g
		check.debug, check.me, check.debugStatus = tc.debug, tc.me, tc.status
		ctx := context.WithValue(ctx, oauth2.HTTPClient, check.client(t))
		if _, err := p.VerifyAccessToken(ctx, "EAAB-token"); (err == nil) != tc.valid {
			t.Fatalf("%s: valid=%v, got %v", name, tc.valid, err)
		}
	}
}
