package goapi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

const sessionEndpointPassword = "a session endpoint password"

// sessionClient signs users in over HTTP and reads the results.
type sessionClient struct {
	t    *testing.T
	auth http.Handler
}

func (c sessionClient) headers(cookie string) http.Header {
	h := http.Header{"Content-Type": {"application/json"}, "Origin": {"https://auth.example"}}
	if cookie != "" {
		h.Set("Cookie", cookie)
	}
	return h
}

func (c sessionClient) post(path, body, cookie string, status int) *http.Response {
	c.t.Helper()
	return serve(c.t, c.auth, "POST", "/api/auth"+path, body, c.headers(cookie), status)
}

// get sends a GET to an auth path, which may already carry a query; a path
// that starts with the base path is sent as it is.
func (c sessionClient) get(path, cookie string, status int) *http.Response {
	c.t.Helper()
	if !strings.HasPrefix(path, "/api/auth/") {
		path = "/api/auth" + path
	}
	return serve(c.t, c.auth, "GET", path, "", c.headers(cookie), status)
}

// signIn returns the session cookie and token of a new sign-in.
func (c sessionClient) signIn(email string) (string, string) {
	c.t.Helper()
	r := c.post("/sign-in/email", `{"email":"`+email+`","password":"`+sessionEndpointPassword+`"}`, "", 200)
	var out struct{ Token string }
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil || out.Token == "" {
		c.t.Fatal("sign-in returned no token", err)
	}
	for _, cookie := range r.Cookies() {
		if strings.HasSuffix(cookie.Name, "session_token") {
			return cookie.Name + "=" + cookie.Value, out.Token
		}
	}
	c.t.Fatal("sign-in set no session cookie")
	return "", ""
}

// user returns the email of the cookie's session, or "" for none.
func (c sessionClient) user(cookie string) string {
	c.t.Helper()
	r := serve(c.t, c.auth, "GET", "/api/auth/get-session", "", c.headers(cookie), 200)
	var out *struct{ User struct{ Email string } }
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		c.t.Fatal(err)
	}
	if out == nil {
		return ""
	}
	return out.User.Email
}

// statusBody requires the {"status":true} body.
func statusBody(t *testing.T, r *http.Response) {
	t.Helper()
	data, _ := io.ReadAll(r.Body)
	if strings.TrimSpace(string(data)) != `{"status":true}` {
		t.Fatalf("unexpected body %s", data)
	}
}

// expiresSession reports whether the response expires the session cookie.
func expiresSession(r *http.Response) bool {
	for _, cookie := range r.Cookies() {
		if strings.HasSuffix(cookie.Name, "session_token") && cookie.MaxAge < 0 {
			return true
		}
	}
	return false
}

func errorCode(t *testing.T, r *http.Response) string {
	t.Helper()
	var out struct{ Code string }
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Code
}

// The session revocation routes: revoke-session ends only the caller's own
// session and clears cookies only for the current one, revoke-other-sessions
// keeps the current session, and revoke-sessions ends every session and the
// cookies. Each answers {"status":true}, and each needs a session.
func TestSessionRevocationEndpoints(t *testing.T) {
	off := false
	c := sessionClient{t, newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example", RateLimit: &off})}
	for _, email := range []string{"ada@example.test", "bob@example.test"} {
		c.post("/sign-up/email", `{"name":"Person","email":"`+email+`","password":"`+sessionEndpointPassword+`"}`, "", 200)
	}
	if code := errorCode(t, c.post("/revoke-other-sessions", `{}`, "", 401)); code != "UNAUTHORIZED" {
		t.Fatal("revoke-other-sessions without a session answered", code)
	}
	if code := errorCode(t, c.post("/revoke-sessions", `{}`, "", 401)); code != "UNAUTHORIZED" {
		t.Fatal("revoke-sessions without a session answered", code)
	}

	a1, _ := c.signIn("ada@example.test")
	a2, a2Token := c.signIn("ada@example.test")
	b1, b1Token := c.signIn("bob@example.test")
	// Another user's token is left alone, and the answer is the same.
	r := c.post("/revoke-session", `{"token":"`+b1Token+`"}`, a1, 200)
	if expiresSession(r) {
		t.Fatal("revoking another user's session expired the caller's cookie")
	}
	statusBody(t, r)
	if c.user(b1) != "bob@example.test" {
		t.Fatal("another user's session was revoked")
	}
	// Another of the caller's sessions ends without touching the caller's.
	r = c.post("/revoke-session", `{"token":"`+a2Token+`"}`, a1, 200)
	if expiresSession(r) {
		t.Fatal("revoking another of the caller's sessions expired the current cookie")
	}
	statusBody(t, r)
	if c.user(a2) != "" || c.user(a1) != "ada@example.test" {
		t.Fatal("revoke-session did not end exactly the named session")
	}
	if code := errorCode(t, c.post("/revoke-session", `{}`, a1, 400)); code != "VALIDATION_ERROR" {
		t.Fatal("revoke-session without a token answered", code)
	}

	a3, _ := c.signIn("ada@example.test")
	statusBody(t, c.post("/revoke-other-sessions", `{}`, a3, 200))
	if c.user(a1) != "" || c.user(a3) != "ada@example.test" {
		t.Fatal("revoke-other-sessions did not keep only the current session")
	}

	a4, _ := c.signIn("ada@example.test")
	r = c.post("/revoke-sessions", `{}`, a3, 200)
	if !expiresSession(r) {
		t.Fatal("revoke-sessions kept the session cookie")
	}
	statusBody(t, r)
	if c.user(a3) != "" || c.user(a4) != "" {
		t.Fatal("revoke-sessions left a session signed in")
	}
	serve(t, c.auth, "GET", "/api/auth/list-sessions", "", c.headers(a4), 401)
	if c.user(b1) != "bob@example.test" {
		t.Fatal("revoke-sessions ended another user's session")
	}
}

// list-sessions needs a fresh session and leaves expired sessions out.
func TestListSessionsFreshAndLive(t *testing.T) {
	store := memory.New()
	off := false
	auth, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off})
	if err != nil {
		t.Fatal(err)
	}
	account, err := auth.SignUpEmail(t.Context(), authn.SignUpInput{Email: "ada@example.test", Password: sessionEndpointPassword, Name: "Ada"}, authn.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	stale := authn.StoredSession{Session: authn.Session{ID: "stale", Token: "stale-token", UserID: account.User.ID, CreatedAt: now.Add(-48 * time.Hour), UpdatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(time.Hour)}}
	expired := authn.StoredSession{Session: authn.Session{ID: "expired", Token: "expired-token", UserID: account.User.ID, CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)}}
	for _, s := range []authn.StoredSession{stale, expired} {
		if err := store.CreateSession(t.Context(), s); err != nil {
			t.Fatal(err)
		}
	}
	list := func(token string, status int) *http.Response {
		t.Helper()
		cookie := auth.SessionCookie(token, false)
		return serve(t, auth, "GET", "/api/auth/list-sessions", "", http.Header{"Cookie": {cookie.Name + "=" + cookie.Value}}, status)
	}
	if code := errorCode(t, list("stale-token", 403)); code != "SESSION_NOT_FRESH" {
		t.Fatal("a two-day-old session listed sessions:", code)
	}
	var sessions []authn.Session
	if err := json.NewDecoder(list(account.Token, 200).Body).Decode(&sessions); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, s := range sessions {
		ids[s.ID] = true
	}
	if len(sessions) != 2 || !ids["stale"] || ids["expired"] {
		t.Fatalf("list-sessions returned %+v, want the fresh and the stale session only", sessions)
	}
}

// A sign-out that ends a provider session answers with Location set to the
// provider's logout URL, unless the caller asked for no redirect.
func TestSignOutProviderLocation(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	profile := authn.OAuthProfile{Subject: "user", Email: "jo@example.org", Name: "Jo"}
	provider := authn.OAuthProvider{Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token"}},
		EndSessionEndpoint: "https://id.example/end",
		Resolve:            func(context.Context, *oauth2.Token, string) (authn.OAuthProfile, error) { return profile, nil },
		VerifyIDToken: func(context.Context, string, string) (authn.OAuthProfile, time.Time, error) {
			return profile, time.Now().Add(time.Hour), nil
		},
	}
	auth, err := authn.New(authn.Options{BaseURL: "https://auth.example", Secret: strings.Repeat("x", 32), Store: store, SocialProviders: map[string]authn.OAuthProvider{"work": provider}})
	if err != nil {
		t.Fatal(err)
	}
	c := sessionClient{t, auth}
	for _, disable := range []bool{false, true} {
		// Each pass signs in with a new ID token; a used one is refused.
		grant := "id.grant." + strconv.FormatBool(disable)
		r := c.post("/sign-in/social", `{"provider":"work","idToken":{"token":"`+grant+`","nonce":"bound"}}`, "", 200)
		var cookie string
		for _, ck := range r.Cookies() {
			if strings.HasSuffix(ck.Name, "session_token") {
				cookie = ck.Name + "=" + ck.Value
			}
		}
		body := `{}`
		if disable {
			body = `{"disableRedirect":true}`
		}
		r = c.post("/sign-out", body, cookie, 200)
		var out struct {
			URL      string
			Redirect bool
		}
		if err := json.NewDecoder(r.Body).Decode(&out); err != nil || !strings.HasPrefix(out.URL, "https://id.example/end?") || out.Redirect == disable {
			t.Fatal("sign-out returned", out, err)
		}
		if location := r.Header.Get("Location"); disable && location != "" || !disable && location != out.URL {
			t.Fatalf("with disableRedirect %v the sign-out Location was %q, want the logout URL only without it", disable, location)
		}
	}
}
