package sqlstore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// endSessionStore counts client lookups and can fail session deletes.
type endSessionStore struct {
	*Store
	lookups   atomic.Int32
	failClose atomic.Bool
}

func (s *endSessionStore) LookupOAuthClient(ctx context.Context, id string) (op.ClientDetails, error) {
	s.lookups.Add(1)
	return s.Store.LookupOAuthClient(ctx, id)
}

func (s *endSessionStore) DeleteSession(ctx context.Context, token string) error {
	if s.failClose.Load() {
		return errors.New("delete failed")
	}
	return s.Store.DeleteSession(ctx, token)
}

type endSessionReply struct {
	code   int
	body   string
	header http.Header
}

func (r endSessionReply) cookie(name string) *http.Cookie {
	for _, line := range r.header.Values("Set-Cookie") {
		if c, err := http.ParseSetCookie(line); err == nil && c.Name == name {
			return c
		}
	}
	return nil
}

// RP-Initiated Logout: a valid ID token hint ends the hinted session, with
// or without the browser's cookies, and a request without a usable hint, or
// for another session, needs the user's confirmation, which a browser gives
// on a page backed by a signed short-lived cookie. Redirects go only to an
// exact registered post-logout URI, rechecked at confirmation.
func TestEndSession(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			raw, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"oauth-provider", "jwt"}, schema.Options{})
			must(err)
			t.Cleanup(func() { raw.Close() })
			store := &endSessionStore{Store: raw}
			const origin = "https://logout.example.test"
			allowIntranet := true
			receiver := &logoutReceiver{}
			opts := op.Options{Scopes: []string{"openid", "offline_access"}, BackchannelTransport: receiver,
				Authorization: op.BrowserAuthorizationOptions{LoginPage: "/login", ConsentPage: "/consent"},
				Registration: op.RegistrationOptions{AllowHTTPRedirect: func(u *url.URL) bool {
					return allowIntranet && u.Hostname() == "intranet.example"
				}},
				ClientPrivileges: func(context.Context, op.ClientAccess) (bool, error) { return true, nil }}
			off := false
			host := func(basePath string) *auth.Auth {
				t.Helper()
				p, err := op.New(opts)
				must(err)
				signing, err := auth.NewJWT(auth.JWTOptions{})
				must(err)
				h, err := auth.New(auth.Options{BaseURL: origin, BasePath: basePath, Secret: strings.Repeat("e", 40), Store: store, EmailAndPassword: true,
					Plugins: []auth.Plugin{p, signing}, RateLimit: &off})
				must(err)
				return h
			}
			h := host("")
			mount := origin + "/api/auth"
			sessionCookie := h.Cookie("session_token", "", 0).Name
			confirmCookie := sessionCookie + ".oauth_logout_confirmation"
			send := func(method, path string, query url.Values, form string, header http.Header) endSessionReply {
				t.Helper()
				target := mount + path
				if len(query) > 0 {
					target += "?" + query.Encode()
				}
				r := httptest.NewRequest(method, target, strings.NewReader(form))
				r.Header = header.Clone()
				if form != "" && r.Header.Get("Content-Type") == "" {
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				if method == http.MethodPost && r.Header.Get("Origin") == "" {
					r.Header.Set("Origin", origin)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return endSessionReply{w.Code, w.Body.String(), w.Header()}
			}
			browser := func(cookies ...string) http.Header {
				return http.Header{"Accept": {"text/html"}, "Sec-Fetch-Mode": {"navigate"}, "Cookie": {strings.Join(cookies, "; ")}}
			}
			api := func(cookies ...string) http.Header {
				return http.Header{"Accept": {"application/json"}, "Cookie": {strings.Join(cookies, "; ")}}
			}
			// signIn returns a browser session's cookie, token and ID.
			var user string
			signIn := func(first bool) (string, string, string) {
				t.Helper()
				path, body := "/sign-in/email", `{"email":"owner@logout.test","password":"local logout test password"}`
				if first {
					path, body = "/sign-up/email", `{"name":"Owner","email":"owner@logout.test","password":"local logout test password"}`
				}
				r := send(http.MethodPost, path, nil, body, http.Header{"Content-Type": {"application/json"}})
				c := r.cookie(sessionCookie)
				if r.code != 200 || c == nil {
					t.Fatal("sign-in failed", r.code, r.body)
				}
				token := h.VerifySignedSessionToken(c.Value)
				var id string
				must(raw.db.QueryRowContext(ctx, raw.bind(`SELECT "id","userId" FROM "session" WHERE "token"=?`), token).Scan(&id, &user))
				return sessionCookie + "=" + c.Value, token, id
			}
			alive := func(token string) bool {
				t.Helper()
				var n int
				must(raw.db.QueryRowContext(ctx, raw.bind(`SELECT COUNT(*) FROM "session" WHERE "token"=?`), token).Scan(&n))
				return n == 1
			}
			// Clients: app may end sessions and lists a post-logout URI; other
			// receives back-channel logout tokens.
			cookie, _, _ := signIn(true)
			manager, err := op.NewClientManager(h, store, opts)
			must(err)
			yes, no := true, false
			logoutURI := "https://app.example.test/logged-out"
			admin := http.Header{"Cookie": {cookie}}
			create := func(end bool, extra op.RegistrationMetadata) string {
				t.Helper()
				extra.RedirectURIs = []string{"https://app.example.test/cb"}
				created, err := manager.CreateClient(ctx, admin, op.ClientCreation{RegistrationMetadata: extra, EnableEndSession: &end})
				must(err)
				return created.ClientID
			}
			backchannel := "https://other.example.test/logout"
			app := create(true, op.RegistrationMetadata{PostLogoutRedirectURIs: []string{logoutURI, "http://intranet.example/logged-out"}})
			disabled := create(true, op.RegistrationMetadata{})
			plain := create(false, op.RegistrationMetadata{})
			create(false, op.RegistrationMetadata{BackchannelLogoutURI: &backchannel})
			_, err = manager.UpdateClient(ctx, admin, disabled, op.ClientAdminUpdate{Disabled: &yes})
			must(err)
			doc, err := op.GetOpenIDConfig(h)
			must(err)
			if doc.EndSessionEndpoint != mount+"/oauth2/end-session" {
				t.Fatal("discovery did not publish the end-session endpoint", doc.EndSessionEndpoint)
			}
			now := time.Now()
			hint := func(sid string, audience []string, extra map[string]any, expired bool) string {
				t.Helper()
				claims := map[string]any{"sid": sid}
				for k, v := range extra {
					claims[k] = v
				}
				issued := now
				if expired {
					issued = now.Add(-2 * time.Hour)
				}
				token, err := h.SignJWT(ctx, user, auth.JWTSignOptions{Issuer: h.OAuthIssuer(), Audience: audience, IssuedAt: issued, ExpiresAt: issued.Add(time.Hour), Claims: claims})
				must(err)
				return token
			}
			var other string
			must(raw.db.QueryRowContext(ctx, raw.bind(`SELECT "clientId" FROM "oauthClient" WHERE "backchannelLogoutUri" IS NOT NULL`)).Scan(&other))
			holdTokens := func(sid string) {
				t.Helper()
				_, err := raw.db.ExecContext(ctx, raw.bind(`INSERT INTO "oauthAccessToken" ("id","token","clientId","sessionId","scopes","createdAt","expiresAt") VALUES (?,?,?,?,'[]',?,?)`),
					rand.Text(), rand.Text(), other, sid, raw.date(now), raw.date(now.Add(time.Hour)))
				must(err)
			}
			problem := func(r endSessionReply, code int, oauthError, description string) {
				t.Helper()
				var body struct {
					Error       string `json:"error"`
					Description string `json:"error_description"`
				}
				if r.code != code || json.Unmarshal([]byte(r.body), &body) != nil || body.Error != oauthError || body.Description != description || r.header.Get("WWW-Authenticate") != "" {
					t.Fatalf("wanted %d %s %q, got %d %s", code, oauthError, description, r.code, r.body)
				}
			}

			// A valid hint for the browser's own session ends it, expires the
			// cookie, notifies the other client and redirects with state.
			cookie, token, sid := signIn(false)
			holdTokens(sid)
			r := send(http.MethodGet, "/oauth2/end-session", url.Values{"id_token_hint": {hint(sid, []string{app}, nil, false)}, "post_logout_redirect_uri": {logoutURI}, "state": {"s1"}}, "", browser(cookie))
			if r.code != http.StatusFound || r.header.Get("Location") != logoutURI+"?state=s1" || alive(token) || r.cookie(sessionCookie) == nil || r.cookie(sessionCookie).MaxAge >= 0 ||
				r.header.Get("Pragma") != "no-cache" || !strings.Contains(r.header.Get("Cache-Control"), "no-store") {
				t.Fatal("a valid hint for this browser did not end its session and redirect", r.code, r.header)
			}
			if got := receiver.take(); len(got) != 1 || got[0].host != "other.example.test" {
				t.Fatal("ending the session did not notify the client holding its tokens", got)
			}
			// A valid expired hint without cookies ends the hinted session,
			// as a JSON or a form POST, and answers null.
			_, token, sid = signIn(false)
			r = send(http.MethodPost, "/oauth2/end-session", nil, `{"id_token_hint":"`+hint(sid, []string{app}, nil, true)+`"}`, http.Header{"Content-Type": {"application/json"}, "Accept": {"application/json"}})
			if r.code != 200 || strings.TrimSpace(r.body) != "null" || alive(token) {
				t.Fatal("a valid expired hint without cookies did not end the session", r.code, r.body)
			}
			_, token, sid = signIn(false)
			r = send(http.MethodPost, "/oauth2/end-session", nil, url.Values{"id_token_hint": {hint(sid, []string{app}, nil, false)}, "post_logout_redirect_uri": {logoutURI + "?x=1"}}.Encode(), api())
			if r.code != 200 || strings.TrimSpace(r.body) != "null" || alive(token) {
				t.Fatal("a form POST with a hint and an altered redirect did not end the session with null", r.code, r.body)
			}
			// The Go client ends its own session and gets the redirect.
			c, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
			must(err)
			signed, err := c.SignInEmail(ctx, client.SignInRequest{Email: "owner@logout.test", Password: "local logout test password"})
			must(err)
			var clientSID string
			must(raw.db.QueryRowContext(ctx, raw.bind(`SELECT "id" FROM "session" WHERE "token"=?`), *signed.Token).Scan(&clientSID))
			target, err := c.EndOAuthSession(ctx, client.EndOAuthSession{IDTokenHint: hint(clientSID, []string{app}, nil, false), PostLogoutRedirectURI: logoutURI, State: "go"})
			if err != nil || target != logoutURI+"?state=go" || alive(*signed.Token) {
				t.Fatal("the Go client did not end its session", target, err)
			}
			// An unregistered redirect gets the logged-out page with a note.
			_, token, sid = signIn(false)
			r = send(http.MethodGet, "/oauth2/end-session", url.Values{"id_token_hint": {hint(sid, []string{app}, nil, false)}, "post_logout_redirect_uri": {"https://app.example.test/elsewhere"}}, "", browser())
			if r.code != 200 || !strings.Contains(r.body, `data-oidc-logout-state="logged-out">Logged out. The requested post-logout redirect was not registered.`) ||
				r.header.Get("Content-Security-Policy") != "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" || alive(token) {
				t.Fatal("an unregistered redirect did not get the logged-out page", r.code, r.body, r.header)
			}
			// The transport check runs first, with AllowHTTPRedirect.
			_, token, sid = signIn(false)
			problem(send(http.MethodGet, "/oauth2/end-session", url.Values{"id_token_hint": {hint(sid, []string{app}, nil, false)}, "post_logout_redirect_uri": {"http://plain.example/x"}}, "", api()),
				400, "invalid_request", "Redirect URI must use HTTPS (HTTP allowed only for loopback hosts)")
			r = send(http.MethodGet, "/oauth2/end-session", url.Values{"id_token_hint": {hint(sid, []string{app}, nil, false)}, "post_logout_redirect_uri": {"http://intranet.example/logged-out"}}, "", api())
			if r.code != 200 || !strings.Contains(r.body, `"url":"http://intranet.example/logged-out"`) || alive(token) {
				t.Fatal("an allowed HTTP redirect was refused", r.code, r.body)
			}
			// Client refusals, and invalid hints, keep the session.
			_, token, sid = signIn(false)
			problem(send(http.MethodGet, "/oauth2/end-session", url.Values{"id_token_hint": {hint(sid, []string{"absent"}, nil, false)}}, "", api()), 400, "invalid_client", "The logout client does not exist")
			problem(send(http.MethodGet, "/oauth2/end-session", url.Values{"id_token_hint": {hint(sid, []string{disabled}, nil, false)}}, "", api()), 400, "invalid_client", "The logout client is disabled")
			problem(send(http.MethodGet, "/oauth2/end-session", url.Values{"id_token_hint": {hint(sid, []string{plain}, nil, false)}}, "", api()), 401, "invalid_client", "The client is not allowed to initiate logout")
			problem(send(http.MethodGet, "/oauth2/end-session", url.Values{"client_id": {plain}}, "", api()), 401, "invalid_client", "The client is not allowed to initiate logout")
			valid := hint(sid, []string{app}, nil, false)
			parts := strings.Split(valid, ".")
			tampered := parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2]))
			unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + parts[1] + "."
			for _, bad := range []string{tampered, unsigned, hint(sid, []string{app}, map[string]any{"sid": ""}, false)} {
				problem(send(http.MethodGet, "/oauth2/end-session", url.Values{"id_token_hint": {bad}}, "", api()), 401, "invalid_token", "The id_token_hint is invalid")
			}
			// A hint must name the client given as client_id.
			problem(send(http.MethodGet, "/oauth2/end-session", url.Values{"client_id": {app}, "id_token_hint": {hint(sid, []string{plain}, nil, false)}}, "", api()), 401, "invalid_token", "The id_token_hint is invalid")
			if !alive(token) {
				t.Fatal("a refused logout ended the session")
			}
			// A multi-audience hint resolves through azp with one lookup;
			// several audiences without azp resolve none.
			store.lookups.Store(0)
			problem(send(http.MethodGet, "/oauth2/end-session", url.Values{"id_token_hint": {hint(sid, []string{"x1", "x2", "x3"}, nil, false)}}, "", api()), 400, "invalid_client", "The logout client does not exist")
			if store.lookups.Load() != 0 {
				t.Fatal("an unverified audience list was looked up", store.lookups.Load())
			}
			r = send(http.MethodGet, "/oauth2/end-session", url.Values{"id_token_hint": {hint(sid, []string{app, other}, map[string]any{"azp": app}, false)}}, "", api())
			if r.code != 200 || alive(token) || store.lookups.Load() != 1 {
				t.Fatal("a multi-audience hint did not resolve through azp", r.code, r.body, store.lookups.Load())
			}
			// A failing delete answers 500 and keeps the session.
			_, token, sid = signIn(false)
			store.failClose.Store(true)
			problem(send(http.MethodGet, "/oauth2/end-session", url.Values{"id_token_hint": {hint(sid, []string{app}, nil, false)}}, "", api()), 500, "server_error", "Unable to complete logout")
			store.failClose.Store(false)
			if !alive(token) {
				t.Fatal("a failed delete ended the session")
			}
			// Requests that need confirmation: another caller is refused.
			cookie, token, sid = signIn(false)
			problem(send(http.MethodGet, "/oauth2/end-session", nil, "", api(cookie)), 400, "invalid_request", "User confirmation is required to complete logout")
			problem(send(http.MethodGet, "/oauth2/end-session", nil, "", api()), 400, "invalid_request", "No active session is available for logout")
			_, otherToken, otherSID := signIn(false)
			problem(send(http.MethodGet, "/oauth2/end-session", url.Values{"id_token_hint": {hint(otherSID, []string{app}, nil, false)}}, "", api(cookie)), 400, "invalid_request", "User confirmation is required to complete logout")
			if !alive(token) || !alive(otherToken) {
				t.Fatal("a request that needs confirmation ended a session")
			}

			// A browser gets the confirmation page and its cookie.
			page := func(r endSessionReply) *http.Cookie {
				t.Helper()
				state := r.cookie(confirmCookie)
				if r.code != 200 || !strings.Contains(r.body, `<form method="post" data-oidc-logout-confirmation action="`+mount+`/oauth2/end-session/confirm">`) ||
					!strings.Contains(r.body, `<button type="submit" name="action" value="confirm">Confirm logout</button>`) || state == nil || !state.HttpOnly ||
					state.SameSite != http.SameSiteLaxMode || state.MaxAge != 300 || state.Path != "/api/auth/oauth2/end-session/confirm" {
					t.Fatal("no confirmation page with its cookie", r.code, r.body, r.header.Values("Set-Cookie"))
				}
				return state
			}
			confirm := func(header http.Header, state *http.Cookie) endSessionReply {
				t.Helper()
				header = header.Clone()
				if state != nil {
					header.Set("Cookie", strings.TrimPrefix(header.Get("Cookie")+"; "+state.Name+"="+state.Value, "; "))
				}
				return send(http.MethodPost, "/oauth2/end-session/confirm", nil, "action=confirm", header)
			}
			state := page(send(http.MethodGet, "/oauth2/end-session", nil, "", browser(cookie)))
			page(send(http.MethodPost, "/oauth2/end-session", nil, "state=x", browser(cookie)))
			page(send(http.MethodGet, "/oauth2/end-session", url.Values{"id_token_hint": {tampered}}, "", browser(cookie)))
			page(send(http.MethodGet, "/oauth2/end-session", url.Values{"id_token_hint": {hint(otherSID, []string{app}, nil, false)}}, "", browser(cookie)))
			if !alive(token) {
				t.Fatal("showing the confirmation page ended the session")
			}
			// Confirmation needs the cookie, untampered, unexpired, bound to
			// this session, and a same-origin form.
			pageError := func(r endSessionReply, code int, description string) {
				t.Helper()
				if r.code != code || !strings.Contains(r.body, `data-oidc-logout-state="error">`+description) {
					t.Fatal("wrong confirmation refusal", code, description, r.code, r.body)
				}
			}
			pageError(confirm(browser(cookie), nil), 400, "The logout confirmation is invalid or expired")
			pageError(confirm(browser(cookie), &http.Cookie{Name: confirmCookie, Value: state.Value + "x"}), 400, "The logout confirmation is invalid or expired")
			stale := h.SignedCookie("session_token", `{"sessionId":"`+sid+`","expiresAt":1}`, 300)
			pageError(confirm(browser(cookie), &http.Cookie{Name: confirmCookie, Value: stale.Value}), 400, "The logout confirmation is invalid or expired")
			otherState := h.SignedCookie("session_token", `{"sessionId":"`+otherSID+`","expiresAt":`+jsonNumber(now.Add(time.Minute).UnixMilli())+`}`, 300)
			pageError(confirm(browser(cookie), &http.Cookie{Name: confirmCookie, Value: otherState.Value}), 400, "The logout confirmation is invalid or expired")
			cross := browser(cookie)
			cross.Set("Origin", "https://evil.example")
			if r := confirm(cross, state); r.code != http.StatusForbidden || !alive(token) {
				t.Fatal("a cross-origin confirmation was not refused", r.code, r.body)
			}
			if r := send(http.MethodPost, "/oauth2/end-session/confirm", nil, "action=other", browser(cookie)); r.code != 400 || !strings.Contains(r.body, "action must be one of: confirm") {
				t.Fatal("a confirmation without action=confirm was accepted", r.code, r.body)
			}
			if !alive(token) {
				t.Fatal("a refused confirmation ended the session")
			}
			// Confirming ends the session, clears both cookies and notifies.
			holdTokens(sid)
			r = confirm(browser(cookie), state)
			if r.code != 200 || !strings.Contains(r.body, `data-oidc-logout-state="logged-out">Logged out.</p>`) || alive(token) ||
				r.cookie(sessionCookie) == nil || r.cookie(sessionCookie).MaxAge >= 0 || r.cookie(confirmCookie) == nil || r.cookie(confirmCookie).MaxAge >= 0 {
				t.Fatal("confirming did not end the session and clear the cookies", r.code, r.body, r.header.Values("Set-Cookie"))
			}
			if got := receiver.take(); len(got) != 1 {
				t.Fatal("a confirmed logout did not notify the client holding tokens", got)
			}
			// A registered redirect for an identified client is followed after
			// confirmation; without client_id it is not.
			cookie, token, _ = signIn(false)
			state = page(send(http.MethodGet, "/oauth2/end-session", url.Values{"client_id": {app}, "post_logout_redirect_uri": {logoutURI}, "state": {"s2"}}, "", browser(cookie)))
			if r := confirm(browser(cookie), state); r.code != http.StatusFound || r.header.Get("Location") != logoutURI+"?state=s2" || alive(token) {
				t.Fatal("a confirmed logout did not follow the registered redirect", r.code, r.header)
			}
			cookie, token, _ = signIn(false)
			state = page(send(http.MethodGet, "/oauth2/end-session", url.Values{"post_logout_redirect_uri": {logoutURI}}, "", browser(cookie)))
			if r := confirm(browser(cookie), state); r.code != 200 || r.header.Get("Location") != "" || alive(token) {
				t.Fatal("a redirect without client_id was followed", r.code, r.header)
			}
			// The redirect is rechecked at confirmation.
			for name, change := range map[string]func(bool){
				"disabled": func(undo bool) {
					_, err := manager.UpdateClient(ctx, admin, app, op.ClientAdminUpdate{Disabled: map[bool]*bool{false: &yes, true: &no}[undo]})
					must(err)
				},
				"end session off": func(undo bool) {
					_, err := manager.UpdateClient(ctx, admin, app, op.ClientAdminUpdate{EnableEndSession: map[bool]*bool{false: &no, true: &yes}[undo]})
					must(err)
				},
				"uri removed": func(undo bool) {
					uris := []string{"http://intranet.example/logged-out"}
					if undo {
						uris = append(uris, logoutURI)
					}
					_, err := manager.UpdateClient(ctx, admin, app, op.ClientAdminUpdate{Fields: map[string]any{"post_logout_redirect_uris": uris}})
					must(err)
				},
				"http refused": func(undo bool) { allowIntranet = undo },
			} {
				cookie, token, _ = signIn(false)
				redirect := logoutURI
				if name == "http refused" {
					redirect = "http://intranet.example/logged-out"
				}
				state = page(send(http.MethodGet, "/oauth2/end-session", url.Values{"client_id": {app}, "post_logout_redirect_uri": {redirect}}, "", browser(cookie)))
				change(false)
				r := confirm(browser(cookie), state)
				change(true)
				if r.code != 200 || r.header.Get("Location") != "" || !strings.Contains(r.body, "The requested post-logout redirect was not registered.") || alive(token) {
					t.Fatal("a redirect that stopped qualifying was followed", name, r.code, r.header, r.body)
				}
			}
			// A confirmation started without the session cookie completes
			// once the browser sends it.
			cookie, token, _ = signIn(false)
			state = page(send(http.MethodGet, "/oauth2/end-session", nil, "", browser()))
			if r := confirm(browser(cookie), state); r.code != 200 || alive(token) {
				t.Fatal("a confirmation started without the session cookie did not complete", r.code, r.body)
			}
			// A custom base path moves the form action and the cookie path.
			custom := host("/identity")
			mount = origin + "/identity"
			h = custom
			signIn(false)
			r = send(http.MethodGet, "/oauth2/end-session", nil, "", browser())
			if c := r.cookie(confirmCookie); r.code != 200 || !strings.Contains(r.body, `action="`+origin+`/identity/oauth2/end-session/confirm"`) || c == nil || c.Path != "/identity/oauth2/end-session/confirm" {
				t.Fatal("the custom base path was not used for the confirmation", r.code, r.body, r.header.Values("Set-Cookie"))
			}
		})
	}
}

func jsonNumber(n int64) string {
	raw, _ := json.Marshal(n)
	return string(raw)
}
