package goapi_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/plugins/multisession"
	"github.com/Plain-Org/plain-auth/schema"
)

// An endpoint answers with an HTMLError page and its status, keeping the
// headers it set, and the error still reaches OnAPIError.
func TestHTMLErrorPage(t *testing.T) {
	var reported int
	page := authn.Plugin{ID: "page", Endpoints: []authn.Endpoint{{Method: http.MethodGet, Path: "/refused", Handler: func(c authn.EndpointContext) (any, error) {
		c.ResponseHeader.Set("Content-Security-Policy", "default-src 'none'")
		return nil, &authn.HTMLError{Status: http.StatusConflict, Page: "<p>Refused.</p>"}
	}}}}
	off := false
	a := newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example", RateLimit: &off, Plugins: []authn.Plugin{page},
		OnAPIError: func(_ authn.ErrorContext, err error) error {
			reported++
			return nil
		}})
	res := serve(t, a, http.MethodGet, "/api/auth/refused", "", http.Header{}, http.StatusConflict)
	body, _ := io.ReadAll(res.Body)
	if string(body) != "<p>Refused.</p>" || res.Header.Get("Content-Type") != "text/html; charset=utf-8" || res.Header.Get("X-Content-Type-Options") != "nosniff" ||
		res.Header.Get("Content-Security-Policy") != "default-src 'none'" || reported != 1 {
		t.Fatal("the HTML error was not written as a page", string(body), res.Header, reported)
	}
}

// EndSession ends a session through the delete hooks. Ending the browser's
// own session expires its session and device cookies; ending another leaves
// the cookies alone; a hook that skips the write keeps the session.
func TestEndSessionFromAnEndpoint(t *testing.T) {
	devices, err := multisession.New(multisession.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var before, after int
	var skip string
	end := authn.Plugin{ID: "end", Endpoints: []authn.Endpoint{{Method: http.MethodPost, Path: "/end", Handler: func(c authn.EndpointContext) (any, error) {
		token, _ := c.Body["token"].(string)
		return map[string]bool{"ended": true}, c.EndSession(token)
	}}}}
	off := false
	a := newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example", RateLimit: &off, Plugins: []authn.Plugin{devices, end},
		DatabaseHooks: authn.DatabaseHooks{Session: authn.ModelHooks[authn.SessionRecord]{Delete: authn.OperationHooks[authn.SessionRecord]{
			Before: func(_ context.Context, s *authn.SessionRecord, _ *authn.HookContext) error {
				before++
				if s.Token == skip {
					return authn.ErrSkipWrite
				}
				return nil
			},
			After: func(context.Context, authn.SessionRecord, *authn.HookContext) error {
				after++
				return nil
			},
		}}}})
	headers := http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
	signUp := serve(t, a, http.MethodPost, "/api/auth/sign-up/email", `{"email":"ada@example.com","password":"correct horse battery","name":"Ada"}`, headers, 200)
	signIn := serve(t, a, http.MethodPost, "/api/auth/sign-in/email", `{"email":"ada@example.com","password":"correct horse battery"}`, headers, 200)
	browser := func(res *http.Response) (http.Header, string) {
		t.Helper()
		h := headers.Clone()
		var token string
		for _, c := range res.Cookies() {
			if strings.HasSuffix(c.Name, "session_token") && c.MaxAge >= 0 {
				h.Add("Cookie", c.Name+"="+c.Value)
				token = a.VerifySignedSessionToken(c.Value)
			}
		}
		if token == "" {
			t.Fatal("no session cookie", res.Header.Values("Set-Cookie"))
		}
		return h, token
	}
	first, firstToken := browser(signUp)
	second, secondToken := browser(signIn)
	alive := func(h http.Header) bool {
		t.Helper()
		session, err := a.GetSession(t.Context(), h)
		if err != nil {
			t.Fatal(err)
		}
		return session != nil
	}
	expired := func(res *http.Response) (session, device bool) {
		for _, c := range res.Cookies() {
			if c.MaxAge < 0 && strings.HasSuffix(c.Name, "session_token") {
				session = true
			}
			if c.MaxAge < 0 && strings.Contains(c.Name, "_multi-") {
				device = true
			}
		}
		return session, device
	}
	// Ending another browser's session leaves this browser's cookies.
	res := serve(t, a, http.MethodPost, "/api/auth/end", `{"token":"`+secondToken+`"}`, first, 200)
	if session, device := expired(res); session || device || alive(second) || !alive(first) || before != 1 || after != 1 {
		t.Fatal("ending another session touched this browser or kept the session", session, device, before, after)
	}
	// A hook that skips the write keeps the session, and the cookies still go.
	skip = firstToken
	res = serve(t, a, http.MethodPost, "/api/auth/end", `{"token":"`+firstToken+`"}`, first, 200)
	if session, _ := expired(res); !session || !alive(first) || after != 1 {
		t.Fatal("a skipped end removed the session or kept the cookie", session, after)
	}
	// Ending this browser's own session expires its session and device cookies.
	skip = ""
	res = serve(t, a, http.MethodPost, "/api/auth/end", `{"token":"`+firstToken+`"}`, first, 200)
	if session, device := expired(res); !session || !device || alive(first) || after != 2 {
		t.Fatal("ending this browser's session kept a cookie or the session", session, device, after, res.Header.Values("Set-Cookie"))
	}
}

// An ID token hint verifies an ID token this server signed for its issuer,
// even after it expired, and refuses unsigned, foreign-issuer, foreign-key
// and access or logout tokens.
func TestOAuthIDTokenHint(t *testing.T) {
	signing, err := authn.NewJWT(authn.JWTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := authn.NewJWT(authn.JWTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	hint := authn.Plugin{ID: "hint", Endpoints: []authn.Endpoint{{Method: http.MethodPost, Path: "/hint", Handler: func(c authn.EndpointContext) (any, error) {
		token, _ := c.Body["token"].(string)
		claims, err := c.OAuthIDTokenHint(token)
		return map[string]any{"claims": claims}, err
	}}}}
	off := false
	ctx := t.Context()
	host := func(plugins ...authn.Plugin) *authn.Auth {
		t.Helper()
		store, err := sqlstore.OpenWithOptions(ctx, "sqlite", ":memory:", []string{"jwt"}, schema.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		h, err := authn.New(authn.Options{Store: store, BaseURL: "https://auth.example", Secret: strings.Repeat("h", 32), RateLimit: &off, Plugins: plugins})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	a, stranger := host(signing, hint), host(other)
	past := time.Now().Add(-2 * time.Hour)
	sign := func(signer *authn.Auth, typ, issuer string) string {
		t.Helper()
		token, err := signer.SignJWT(ctx, "user-1", authn.JWTSignOptions{Type: typ, Issuer: issuer, Audience: []string{"client-1"}, IssuedAt: past, ExpiresAt: past.Add(time.Hour),
			Claims: map[string]any{"sid": "session-1"}})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	check := func(token string) map[string]any {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "https://auth.example/api/auth/hint", strings.NewReader(`{"token":"`+token+`"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://auth.example")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		var out struct {
			Claims map[string]any `json:"claims"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatal("the hint endpoint failed", w.Code, w.Body.String())
		}
		return out.Claims
	}
	issuer := a.OAuthIssuer()
	if claims := check(sign(a, "", issuer)); claims["sub"] != "user-1" || claims["sid"] != "session-1" || claims["aud"] != "client-1" {
		t.Fatal("an expired ID token was not accepted as a hint", claims)
	}
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+issuer+`","sub":"user-1"}`)) + "."
	for name, token := range map[string]string{
		"unsigned": unsigned, "foreign issuer": sign(a, "", "https://other.example"), "foreign key": sign(stranger, "", issuer),
		"access token": sign(a, "at+jwt", issuer), "logout token": sign(a, "logout+jwt", issuer), "garbage": "not-a-token",
	} {
		if claims := check(token); claims != nil {
			t.Fatal("a hint was accepted", name, claims)
		}
	}
}
