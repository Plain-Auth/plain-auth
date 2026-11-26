package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

func TestLINEChannelTokenVerification(t *testing.T) {
	const channel, nonce = "01234", "browser-state-nonce"
	now := time.Now().Unix()
	for _, tc := range []struct {
		name, field string
		value       any
		allowed     bool
	}{
		{"active channel", "", nil, true},
		{"other channel", "aud", "another", false},
		{"different browser", "nonce", "another", false},
		{"unrecognized issuer", "iss", "https://other.example", false},
		{"expired ID token", "exp", now - 1, false},
		{"unissued ID token", "iat", now + 300, false},
		{"stale ID token", "iat", now - 7200, false},
		{"missing email permission", "email", "", true},
		{"empty user ID", "sub", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := LINE(channel, "fixture-secret")
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != "POST" || r.URL.String() != "https://api.line.me/oauth2/v2.1/verify" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Authorization") != "" {
					t.Fatal("unexpected verification request")
				}
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if r.PostForm.Get("client_id") != channel || r.PostForm.Get("nonce") != nonce || r.PostForm.Get("id_token") != "aWQ.dG9rZW4.c2ln" || len(r.PostForm) != 3 {
					t.Fatal("wrong verification grant")
				}
				claims := map[string]any{"iss": lineIssuer, "aud": channel, "nonce": nonce, "iat": now, "exp": now + 900, "sub": "line-user", "email": "jo@example.org", "email_verified": true, "name": "Jo"}
				if tc.field != "" {
					claims[tc.field] = tc.value
				}
				data, err := json.Marshal(claims)
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(data))}, nil
			})}
			ctx := context.WithValue(t.Context(), oauth2.HTTPClient, client)
			token := (&oauth2.Token{AccessToken: "access"}).WithExtra(map[string]any{"id_token": "aWQ.dG9rZW4.c2ln"})
			profile, err := p.Resolve(ctx, token, nonce)
			if tc.allowed {
				if err != nil || profile.Subject != "line-user" || profile.EmailVerified || profile.Name != "Jo" {
					t.Fatal(profile, err)
				}
				// Without the email permission the profile has no email,
				// which the sign-in answers with email_not_found.
				if tc.field == "email" && profile.Email != "" {
					t.Fatal("a profile without an email permission has", profile.Email)
				}
			} else if err == nil {
				t.Fatal("accepted invalid channel identity")
			}
		})
	}
	t.Run("verification refused", func(t *testing.T) {
		p := LINE(channel, "fixture-secret")
		calls := 0
		ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader("{}"))}, nil
		})})
		token := (&oauth2.Token{AccessToken: "access"}).WithExtra(map[string]any{"id_token": "cmVq.ZWN0ZWQ.c2ln"})
		if _, err := p.Resolve(ctx, token, nonce); err == nil || calls != 1 {
			t.Fatal("failed channel verification must stop sign-in", err, calls)
		}
	})
}

// lineToken spells the fixture claims "<channel>:<user>:<email>" as a
// compact token, one base64url segment each; lineClaims reads them back.
func lineToken(claims string) string {
	var parts []string
	for _, part := range strings.SplitN(claims, ":", 3) {
		parts = append(parts, base64.RawURLEncoding.EncodeToString([]byte(part)))
	}
	return strings.Join(parts, ".")
}

func lineClaims(token string) string {
	var parts []string
	for _, part := range strings.Split(token, ".") {
		b, _ := base64.RawURLEncoding.DecodeString(part)
		parts = append(parts, string(b))
	}
	return strings.Join(parts, ":")
}

// lineFixture answers LINE's token and verify endpoints for any channel. The
// token endpoint returns the ID token for "<channel>:<code>", where the code
// is "<user>:<email>", and an ID token verifies only for its own channel.
type lineFixture struct {
	mu               sync.Mutex
	tokens, verifies []url.Values
	authorization    []string
}

func (f *lineFixture) client(t *testing.T) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.String() {
		case lineAPI + "/token":
			f.tokens = append(f.tokens, r.PostForm)
			return jsonResponse(t, map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600, "id_token": lineToken(r.PostForm.Get("client_id") + ":" + r.PostForm.Get("code"))}), nil
		case lineAPI + "/verify":
			f.verifies = append(f.verifies, r.PostForm)
			f.authorization = append(f.authorization, r.Header.Get("Authorization"))
			parts := strings.SplitN(lineClaims(r.PostForm.Get("id_token")), ":", 3)
			if len(parts) != 3 || parts[0] != r.PostForm.Get("client_id") {
				return textResponse(http.StatusBadRequest, "application/json", `{"error":"invalid_request"}`), nil
			}
			now := time.Now().Unix()
			return jsonResponse(t, map[string]any{"iss": lineIssuer, "aud": parts[0], "nonce": r.PostForm.Get("nonce"), "iat": now, "exp": now + 900, "sub": parts[1], "email": parts[2], "name": "Jo", "picture": "https://img.example/jo.png"}), nil
		}
		t.Fatalf("unexpected request %s", r.URL)
		return nil, nil
	})}
}

// lineAuth serves providers from one SQLite store.
func lineAuth(t *testing.T, providers map[string]auth.OAuthProvider, configure ...func(*auth.Options)) (*auth.Auth, *sqlite.Store) {
	t.Helper()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	o := auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: "https://app.example.org", RateLimit: new(bool), SocialProviders: providers}
	for _, c := range configure {
		c(&o)
	}
	h, err := auth.New(o)
	if err != nil {
		t.Fatal(err)
	}
	return h, store
}

func serve(h *auth.Auth, method, path, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://app.example.org/api/auth"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://app.example.org")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	return res
}

// A LINE ID token signs in directly at LINE() and New("line") once LINE's
// verify endpoint accepts it for that channel with the nonce; the request
// carries exactly the client ID, token and nonce and no credentials. A
// request without a nonce, or a token in another spelling, never reaches
// LINE, and a token LINE refuses
// answers INVALID_TOKEN. New("line") hands hooks LINE's raw claims, as its
// browser flow hands them LINE's raw profile; LINE() hands them its mapped
// profile.
func TestLINEDirectIDToken(t *testing.T) {
	catalogLINE, err := New("line", "channel", "secret")
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]auth.OAuthProvider{"LINE()": LINE("channel", "secret"), "New": catalogLINE} {
		f := &lineFixture{}
		p.HTTPClient = f.client(t)
		var profile map[string]any
		h, _ := lineAuth(t, map[string]auth.OAuthProvider{"line": p}, func(o *auth.Options) {
			o.ValidateUserInfo = func(_ context.Context, v auth.UserInfoValidation) error {
				profile = v.Profile
				return nil
			}
		})
		// A token without a nonce, or in another spelling, never reaches LINE.
		for _, body := range []string{`{"token":"` + lineToken("channel:U1:jo@example.org") + `"}`, `{"token":"` + lineToken("channel:U1:jo@example.org") + `","nonce":""}`,
			`{"token":"` + lineToken("channel:U1:jo@example.org") + `.","nonce":"n"}`, `{"token":"` + lineToken("channel:U1:jo@example.org") + `=","nonce":"n"}`} {
			if res := serve(h, "POST", "/sign-in/social", `{"provider":"line","idToken":`+body+`}`, nil); res.Code != 401 || !strings.Contains(res.Body.String(), "INVALID_TOKEN") || len(f.verifies) != 0 {
				t.Fatal(name, "answered a token without a nonce with", res.Code, res.Body)
			}
		}
		res := serve(h, "POST", "/sign-in/social", `{"provider":"line","idToken":{"token":"`+lineToken("channel:U1:jo@example.org")+`","nonce":"n"}}`, nil)
		var signedIn struct{ User struct{ EmailVerified bool } }
		if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &signedIn) != nil || signedIn.User.EmailVerified {
			t.Fatal(name, "answered", res.Code, res.Body)
		}
		if len(f.verifies) != 1 || len(f.verifies[0]) != 3 || f.verifies[0].Get("client_id") != "channel" || f.verifies[0].Get("id_token") != lineToken("channel:U1:jo@example.org") ||
			f.verifies[0].Get("nonce") != "n" || f.authorization[0] != "" {
			t.Fatal(name, "verified with", f.verifies, f.authorization)
		}
		res = serve(h, "POST", "/sign-in/social", `{"provider":"line","idToken":{"token":"`+lineToken("other:U1:jo@example.org")+`","nonce":"n"}}`, nil)
		if res.Code != 401 || !strings.Contains(res.Body.String(), "INVALID_TOKEN") {
			t.Fatal(name, "accepted a token LINE refused:", res.Code, res.Body)
		}
		raw := profile["picture"] == "https://img.example/jo.png" && profile["iss"] == lineIssuer && profile["image"] == nil
		mapped := profile["image"] == "https://img.example/jo.png" && profile["emailVerified"] == false && profile["iss"] == nil
		if name == "New" && !raw || name == "LINE()" && !mapped {
			t.Fatal(name, "handed hooks", profile)
		}
	}
}

// Two LINE channels under their own keys keep their own client IDs,
// secrets, callbacks and account namespaces: the same LINE user ID in each
// is a different account, the same unverified email at the second key
// answers account_not_linked, a state from one key fails at the other's
// callback, and a direct ID token works only at its own channel's key.
func TestLINEChannelsUnderSeparateKeys(t *testing.T) {
	f := &lineFixture{}
	jp, th := LINE("jp-channel", "jp-secret"), LINE("th-channel", "th-secret")
	jp.HTTPClient, th.HTTPClient = f.client(t), f.client(t)
	h, store := lineAuth(t, map[string]auth.OAuthProvider{"line-jp": jp, "line-th": th})
	start := func(key string) (*url.URL, []*http.Cookie) {
		t.Helper()
		res := serve(h, "POST", "/sign-in/social", `{"provider":"`+key+`","callbackURL":"/done"}`, nil)
		u, err := url.Parse(res.Header().Get("Location"))
		if err != nil || res.Code != 200 {
			t.Fatal(key, "did not start:", res.Code, err)
		}
		return u, res.Result().Cookies()
	}
	users := map[string]string{}
	for key, channel := range map[string]string{"line-jp": "jp", "line-th": "th"} {
		authorize, cookies := start(key)
		q := authorize.Query()
		if q.Get("client_id") != channel+"-channel" || q.Get("redirect_uri") != "https://app.example.org/api/auth/callback/"+key {
			t.Fatal(key, "authorized with", q)
		}
		done := serve(h, "GET", "/callback/"+key+"?"+url.Values{"code": {"U1:" + channel + "@example.org"}, "state": {q.Get("state")}}.Encode(), "", cookies)
		if done.Header().Get("Location") != "/done" {
			t.Fatal(key, "sign-in landed at", done.Header().Get("Location"))
		}
		exchange := f.tokens[len(f.tokens)-1]
		if exchange.Get("client_id") != channel+"-channel" || exchange.Get("client_secret") != channel+"-secret" || exchange.Get("redirect_uri") != "https://app.example.org/api/auth/callback/"+key {
			t.Fatal(key, "exchanged with", exchange)
		}
		session, err := h.GetSession(t.Context(), http.Header{"Cookie": {cookieHeader(done.Result().Cookies())}})
		if err != nil || session == nil {
			t.Fatal(key, "has no session:", err)
		}
		accounts, err := store.ListUserAccounts(t.Context(), session.User.ID)
		if err != nil || len(accounts) != 1 || accounts[0].ProviderID != key || accounts[0].AccountID != "U1" {
			t.Fatal(key, "accounts are", accounts, err)
		}
		users[key] = session.User.ID
	}
	if users["line-jp"] == users["line-th"] {
		t.Fatal("the same LINE user ID in two channels is one account")
	}
	// LINE emails are unverified, so the same person with the same email at
	// a second key is not linked implicitly.
	for _, key := range []string{"line-jp", "line-th"} {
		authorize, cookies := start(key)
		done := serve(h, "GET", "/callback/"+key+"?"+url.Values{"code": {"U5:same@example.org"}, "state": {authorize.Query().Get("state")}}.Encode(), "", cookies)
		want := "/done"
		if key == "line-th" {
			want = "error=account_not_linked"
		}
		if !strings.Contains(done.Header().Get("Location"), want) {
			t.Fatal("the same email at", key, "went to", done.Header().Get("Location"))
		}
	}
	authorize, cookies := start("line-jp")
	tokens := len(f.tokens)
	crossed := serve(h, "GET", "/callback/line-th?"+url.Values{"code": {"U1:th@example.org"}, "state": {authorize.Query().Get("state")}}.Encode(), "", cookies)
	if !strings.Contains(crossed.Header().Get("Location"), "error=state_mismatch") || len(f.tokens) != tokens {
		t.Fatal("a line-jp state at line-th went to", crossed.Header().Get("Location"))
	}
	if res := serve(h, "POST", "/sign-in/social", `{"provider":"line-th","idToken":{"token":"`+lineToken("th-channel:U2:new@example.org")+`","nonce":"n"}}`, nil); res.Code != 200 {
		t.Fatal("a line-th token at line-th answered", res.Code, res.Body)
	}
	if res := serve(h, "POST", "/sign-in/social", `{"provider":"line-th","idToken":{"token":"`+lineToken("jp-channel:U3:other@example.org")+`","nonce":"n"}}`, nil); res.Code != 401 {
		t.Fatal("a line-jp token at line-th answered", res.Code, res.Body)
	}
}

func cookieHeader(cookies []*http.Cookie) string {
	var parts []string
	for _, c := range cookies {
		if c.MaxAge >= 0 {
			parts = append(parts, c.Name+"="+c.Value)
		}
	}
	return strings.Join(parts, "; ")
}
