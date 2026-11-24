package sqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
	"golang.org/x/oauth2"
)

func TestSocialAuthorizationSession(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			const base = "https://issuer.example.test"
			const callback = "https://client.example.test/done"
			s, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO "oauthClient" ("id","clientId","applicationType","redirectUris","tokenEndpointAuthMethod","scopes","skipConsent") VALUES ('row','app','web',?,'none',?,?)`), `["https://client.example.test/done"]`, `["read"]`, true)
			must(err)
			plugin, err := op.New(op.Options{Scopes: []string{"read"}, Authorization: op.BrowserAuthorizationOptions{LoginPage: "/login", ConsentPage: "/consent"}})
			must(err)
			profile := auth.OAuthProfile{Subject: "external-subject", Name: "External owner", Email: "social@example.test", EmailVerified: true}
			exchanges := 0
			provider := auth.OAuthProvider{
				Config: oauth2.Config{ClientID: "upstream", Endpoint: oauth2.Endpoint{AuthURL: "https://identity.example.test/authorize", TokenURL: "https://identity.example.test/token"}},
				VerifyIDToken: func(_ context.Context, raw, nonce string) (auth.OAuthProfile, time.Time, error) {
					if (raw != "verified-id-token" && raw != "link-id-token") || nonce != "valid-nonce" {
						return auth.OAuthProfile{}, time.Time{}, errors.New("invalid direct grant")
					}
					return profile, time.Now().Add(time.Hour), nil
				},
				ExchangeCode: func(_ context.Context, _ oauth2.Config, code, verifier string, _ url.Values) (*oauth2.Token, error) {
					exchanges++
					if code != "approved" || verifier == "" {
						return nil, errors.New("invalid provider exchange")
					}
					return &oauth2.Token{AccessToken: "local-access"}, nil
				},
				Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) { return profile, nil },
			}
			off := false
			config := auth.Options{Store: s, BaseURL: base, Secret: strings.Repeat("s", 40), Plugins: []auth.Plugin{plugin},
				SocialProviders: map[string]auth.OAuthProvider{"work": provider}, RateLimit: &off, EmailAndPassword: true}
			first, err := auth.New(config)
			must(err)
			peer, err := auth.New(config)
			must(err)
			request := url.Values{"client_id": {"app"}, "response_type": {"code"}, "redirect_uri": {callback}, "scope": {"read"},
				"state": {"rp-state"}, "prompt": {"login"}, "code_challenge_method": {"S256"}, "code_challenge": {"challenge"}}
			w := httptest.NewRecorder()
			first.ServeHTTP(w, httptest.NewRequest("GET", base+"/api/auth/oauth2/authorize?"+request.Encode(), nil))
			page, err := url.Parse(w.Header().Get("Location"))
			must(err)
			if w.Code != 302 || page.Path != "/login" {
				t.Fatal("missing signed login page", w.Code)
			}
			query, err := first.VerifyOAuthPageQuery(page.RawQuery)
			must(err)
			jar, err := cookiejar.New(nil)
			must(err)
			sdk, err := client.New(base, &http.Client{Transport: guestTransport{first}, Jar: jar})
			must(err)
			previous, err := sdk.SignUpEmail(ctx, client.SignUpRequest{Name: "Previous", Email: "other@example.test", Password: "local credential for fixture"})
			must(err)
			input := client.SocialSignInRequest{Provider: "work", OAuthQuery: query.Encode(), DisableRedirect: true, ErrorCallbackURL: "/retry"}
			start := func() string {
				t.Helper()
				reply, err := sdk.SignInSocial(ctx, input)
				must(err)
				upstream, err := url.Parse(reply.URL)
				must(err)
				state := upstream.Query().Get("state")
				if upstream.Host != "identity.example.test" || state == "" || state == "rp-state" || upstream.Query().Has("oauth_query") {
					t.Fatal("unexpected upstream request")
				}
				return state
			}
			finish := func(state, result string, useJar bool) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequest("GET", base+"/api/auth/callback/work?state="+url.QueryEscape(state)+"&"+result, nil)
				r.Header.Set("Sec-Fetch-Mode", "navigate")
				if useJar {
					for _, c := range jar.Cookies(r.URL) {
						r.AddCookie(c)
					}
				}
				w := httptest.NewRecorder()
				peer.ServeHTTP(w, r)
				return w
			}
			state := start()
			if w := finish(state, "code=approved", false); w.Code != 302 || !strings.HasSuffix(w.Header().Get("Location"), "/error?error=state_mismatch") || exchanges != 0 {
				t.Fatal("callback accepted a different browser", w.Code, w.Header().Get("Location"))
			}
			if w := finish(state, "error=access_denied", true); w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "/retry?") || exchanges != 0 {
				t.Fatal("provider denial resumed the signed request")
			}
			if w := finish(state, "code=approved", true); w.Code != 302 || !strings.HasSuffix(w.Header().Get("Location"), "/error?error=state_mismatch") || exchanges != 0 {
				t.Fatal("provider state was reusable after denial", w.Code, w.Header().Get("Location"))
			}
			state = start()
			if w := finish(state, "code=bad", true); w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "OAUTH_TOKEN_EXCHANGE_FAILED") || exchanges != 1 {
				t.Fatal("unsuccessful token exchange authorized an existing session")
			}
			state = start()
			// Give the stored issuer request an expired signature while its
			// independent provider state is still valid.
			var encoded string
			var flow auth.OAuthFlow
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "value" FROM "verification" WHERE "id"=?`), state).Scan(&encoded))
			must(json.Unmarshal([]byte(encoded), &flow))
			if flow.IssuerLoginQuery != input.OAuthQuery {
				t.Fatal("provider state did not retain the verified issuer request")
			}
			flow.IssuerLoginQuery = first.SignOAuthQuery(query, time.Now().Add(-time.Minute))
			altered, err := json.Marshal(flow)
			must(err)
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "verification" SET "value"=? WHERE "id"=?`), string(altered), state)
			must(err)
			if w := finish(state, "code=approved", true); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_signature") || exchanges != 1 {
				t.Fatal("expired issuer query reached the provider exchange")
			}
			state = start()
			completed := finish(state, "code=approved", true)
			callbackURL, err := url.Parse(completed.Header().Get("Location"))
			must(err)
			if completed.Code != 302 || callbackURL.Host != "client.example.test" || callbackURL.Query().Get("state") != "rp-state" || callbackURL.Query().Get("code") == "" {
				t.Fatal("callback on another issuer instance failed to resume")
			}
			if w := finish(state, "code=approved", true); w.Code != 302 || !strings.HasSuffix(w.Header().Get("Location"), "/error?error=state_mismatch") || exchanges != 2 {
				t.Fatal("callback state could be reused on success", w.Code, w.Header().Get("Location"))
			}
			// The SDK still holds the earlier user's cookie. A direct provider
			// grant must issue its authorization for the newly authenticated user.
			input.IDToken = &client.SocialIDToken{Token: "verified-id-token", Nonce: "valid-nonce"}
			direct, err := sdk.SignInSocial(ctx, input)
			must(err)
			if !direct.Redirect || direct.Token != "" || direct.User != nil {
				t.Fatal("direct issuer login did not return a JSON destination")
			}
			result, err := url.Parse(direct.URL)
			must(err)
			current, err := sdk.GetSession(ctx)
			must(err)
			if result.Host != "client.example.test" || result.Query().Get("code") == "" || result.Query().Get("state") != "rp-state" || current.User.Email != profile.Email || current.User.ID == previous.User.ID {
				t.Fatal("direct grant did not authorize the external owner")
			}
			var lastSession string
			for _, issued := range []*url.URL{callbackURL, result} {
				digest := sha256.Sum256([]byte(issued.Query().Get("code")))
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT "value" FROM "verification" WHERE "identifier"=?`), base64.RawURLEncoding.EncodeToString(digest[:])).Scan(&encoded))
				var grant struct{ UserID, SessionID string }
				must(json.Unmarshal([]byte(encoded), &grant))
				if grant.UserID != current.User.ID || grant.SessionID == "" || grant.SessionID == lastSession {
					t.Fatal("issuer code was not bound to the fresh social session")
				}
				lastSession = grant.SessionID
			}
			if lastSession != current.Session.ID {
				t.Fatal("direct grant carried another session")
			}
			if _, err := sdk.SignInSocial(ctx, input); err == nil {
				t.Fatal("direct grant could be used a second time")
			}
			input.IDToken.Token = "link-id-token"
			linked, err := sdk.LinkSocial(ctx, input)
			must(err)
			afterLink, err := sdk.GetSession(ctx)
			must(err)
			if !linked.Status || linked.Redirect || linked.URL != "" || afterLink.Session.ID != current.Session.ID {
				t.Fatal("account linking resumed issuer authorization or changed the session")
			}
		})
	}
}
