package sqlstore

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

// The local issuer enforces the same redirect, client authentication and PKCE
// parameters that were sent to its authorization endpoint before signing an ID token.
type ssoCode struct{ nonce, challenge, redirect, email, subject, style, mode string }
type ssoIssuer struct {
	*httptest.Server
	signer           jose.Signer
	key              jose.JSONWebKey
	mu               sync.Mutex
	codes            map[string]ssoCode
	tokens           atomic.Int32
	entered, release chan struct{}
	// discoveries counts discovery fetches; discoveryDown answers them with 404.
	discoveries   atomic.Int32
	discoveryDown atomic.Bool
	methods       []string
	// assertionKey verifies private_key_jwt client assertions; each verified
	// assertion's kid and alg are recorded in assertions.
	assertionKey crypto.PublicKey
	assertions   []string
	// claims adds ID token claims for a grant's mode.
	claims map[string]map[string]any
	// discovered replaces fields of the discovery document.
	discovered map[string]any
}

func newSSOIssuer(t *testing.T) *ssoIssuer {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, (&jose.SignerOptions{}).WithHeader("kid", "test-key"))
	if e != nil {
		t.Fatal(e)
	}
	idp := &ssoIssuer{signer: signer, key: jose.JSONWebKey{Key: pub, KeyID: "test-key", Use: "sig", Algorithm: "EdDSA"}, codes: map[string]ssoCode{}, entered: make(chan struct{}), release: make(chan struct{})}
	idp.Server = httptest.NewServer(http.HandlerFunc(idp.serve))
	t.Cleanup(idp.Close)
	return idp
}
func (i *ssoIssuer) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		i.discoveries.Add(1)
		if i.discoveryDown.Load() {
			w.WriteHeader(404)
			return
		}
		i.mu.Lock()
		doc := map[string]any{"issuer": i.URL, "authorization_endpoint": i.URL + "/authorize", "token_endpoint": i.URL + "/token", "jwks_uri": i.URL + "/keys", "token_endpoint_auth_methods_supported": i.methods}
		for k, v := range i.discovered {
			doc[k] = v
		}
		i.mu.Unlock()
		json.NewEncoder(w).Encode(doc)
	case "/keys":
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{i.key}})
	case "/token":
		i.tokens.Add(1)
		if r.Method != "POST" || r.ParseForm() != nil {
			w.WriteHeader(400)
			return
		}
		code := r.PostForm.Get("code")
		i.mu.Lock()
		grant, ok := i.codes[code]
		delete(i.codes, code)
		i.mu.Unlock()
		uid, secret, basic := r.BasicAuth()
		if !basic {
			uid = r.PostForm.Get("client_id")
			secret = r.PostForm.Get("client_secret")
		}
		if grant.style == "private_key_jwt" {
			secret = ""
			if !basic && r.PostForm.Get("client_secret") == "" && r.PostForm.Get("client_assertion_type") == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
				if signed, err := jwt.ParseSigned(r.PostForm.Get("client_assertion"), []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.PS256}); err == nil {
					var claims jwt.Claims
					i.mu.Lock()
					if signed.Claims(i.assertionKey, &claims) == nil && claims.Issuer == uid && claims.Subject == uid && claims.Audience.Contains(i.URL+"/token") && claims.ID != "" {
						secret = "oidc-secret"
						i.assertions = append(i.assertions, signed.Headers[0].KeyID+" "+signed.Headers[0].Algorithm)
					}
					i.mu.Unlock()
				}
			}
		}
		if !ok || basic != (grant.style == "client_secret_basic") || uid != "enterprise-client" || secret != "oidc-secret" || r.PostForm.Get("redirect_uri") != grant.redirect || (grant.challenge != "" || r.PostForm.Get("code_verifier") != "") && oauth2.S256ChallengeFromVerifier(r.PostForm.Get("code_verifier")) != grant.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		if grant.mode == "pause" {
			close(i.entered)
			<-i.release
		}
		claims := map[string]any{"iss": i.URL, "aud": uid, "sub": grant.subject, "email": grant.email, "name": "Enterprise User", "email_verified": true, "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(), "nonce": grant.nonce}
		switch grant.mode {
		case "azp":
			claims["aud"] = []string{uid, "other"}
		case "nonce":
			claims["nonce"] = "other-browser"
		case "expired":
			claims["exp"] = time.Now().Add(-time.Minute).Unix()
		case "mismatch":
			claims["iss"] = i.URL + "/other"
		case "future":
			claims["iat"] = time.Now().Add(time.Hour).Unix()
		case "missing-sub":
			delete(claims, "sub")
		}
		i.mu.Lock()
		for k, v := range i.claims[grant.mode] {
			claims[k] = v
		}
		i.mu.Unlock()
		signer := i.signer
		if grant.mode == "signature" {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			signer, _ = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: other}, (&jose.SignerOptions{}).WithHeader("kid", "test-key"))
		}
		signed, _ := jwt.Signed(signer).Claims(claims).Serialize()
		response := map[string]any{"access_token": "access-" + grant.subject, "token_type": "Bearer", "id_token": signed, "expires_in": 3600, "scope": "openid email"}
		if grant.mode == "userinfo-only" {
			delete(response, "id_token")
		}
		json.NewEncoder(w).Encode(response)
	case "/userinfo":
		sub := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer access-")
		if sub == "disagree" {
			sub = "someone-else"
		}
		json.NewEncoder(w).Encode(map[string]any{"sub": sub, "email": sub + "@userinfo.example", "name": "UserInfo"})
	default:
		w.WriteHeader(404)
	}
}

func TestEnterpriseOIDCBrowser(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			ddl, e := schema.Generate(dialect, []string{"organization", "admin", "sso", "oauth-provider"})
			must(e)
			first, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer first.Close()
			other, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer other.Close()
			idp := newSSOIssuer(t)
			host := func(s *Store, shared, disable, implicit bool, extras ...auth.Plugin) *auth.Auth {
				p, e := sso.New(sso.Options{SharedCallback: shared, DisableImplicitSignUp: implicit})
				must(e)
				a, e := auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", RateLimit: new(bool), Store: s, EmailAndPassword: true, DisableSignUp: disable, Secret: strings.Repeat("k", 32), TrustedOrigins: []string{idp.URL}, EncryptOAuthTokens: true, Plugins: append([]auth.Plugin{p}, extras...)})
				must(e)
				return a
			}
			one, two := host(first, false, false, false), host(other, false, false, false)
			call := func(a *auth.Auth, method, path, cookie string, body any) *httptest.ResponseRecorder {
				var buf bytes.Buffer
				if body != nil {
					json.NewEncoder(&buf).Encode(body)
				}
				req := httptest.NewRequest(method, "https://service.test/identity/"+path, &buf)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", "https://service.test")
				if cookie != "" {
					req.Header.Set("Cookie", cookie)
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, req)
				return w
			}
			now := time.Now().UTC()
			create := func(name string) {
				must(first.CreateUser(ctx, auth.User{ID: name, Name: name, Email: name + "@example.test", CreatedAt: now, UpdatedAt: now}, "credential", nil))
			}
			create("owner")
			create("existing")
			exec := func(query string, args ...any) {
				_, e := first.db.ExecContext(ctx, first.bind(query), args...)
				must(e)
			}
			exec(`INSERT INTO "organization" ("id","name","slug","createdAt") VALUES (?,?,?,?)`, "tenant", "Enterprise", "company", first.date(now))
			insert := func(id, style, domain string, tenant *string, ui bool) {
				cfg := sso.Config{Issuer: idp.URL, ClientID: "enterprise-client", ClientSecret: "oidc-secret", AuthorizationEndpoint: idp.URL + "/authorize", TokenEndpoint: idp.URL + "/token", JWKSEndpoint: idp.URL + "/keys", TokenEndpointAuthentication: style, PKCE: new(bool)}
				*cfg.PKCE = true
				if ui {
					cfg.UserInfoEndpoint = idp.URL + "/userinfo"
				}
				raw, _ := json.Marshal(cfg)
				exec(`INSERT INTO "ssoProvider" ("id","providerId","issuer","oidcConfig","domain","userId","organizationId") VALUES (?,?,?,?,?,?,?)`, "record-"+id, id, idp.URL, string(raw), domain, "owner", tenant)
			}
			tenant := "tenant"
			insert("acme", "client_secret_basic", "example.test,acme.example", &tenant, false)
			insert("staff", "client_secret_post", "staff.example", nil, true)
			sdk, e := client.New("https://service.test/identity", &http.Client{Transport: guestTransport{one}})
			must(e)
			authz, e := sdk.SignInSSO(ctx, client.SSOSignInRequest{ProviderID: "staff", CallbackURL: "/home", Scopes: []string{"openid"}, AdditionalParams: map[string]string{"prompt": "login"}})
			must(e)
			parsed, e := url.Parse(authz.URL)
			must(e)
			if !authz.Redirect || parsed.Query().Get("scope") != "openid" || parsed.Query().Get("redirect_uri") != "https://service.test/identity/sso/callback/staff" {
				t.Fatal("invalid native client authorization")
			}
			type pending struct{ cookie, path, code string }
			start := func(a *auth.Auth, id, email, sub, style, mode string, selector map[string]any) pending {
				t.Helper()
				body := map[string]any{"callbackURL": "/home", "newUserCallbackURL": "/welcome", "errorCallbackURL": "/retry", "loginHint": "employee", "additionalParams": map[string]any{"prompt": "login"}}
				for k, v := range selector {
					if body[k] = v; v == nil {
						delete(body, k)
					}
				}
				w := call(a, "POST", "sign-in/sso", "", body)
				if w.Code != 200 {
					t.Fatalf("start %d %s", w.Code, w.Body.String())
				}
				var result struct {
					URL      string
					Redirect bool
				}
				must(json.Unmarshal(w.Body.Bytes(), &result))
				u, e := url.Parse(result.URL)
				must(e)
				q := u.Query()
				if u.String() == "" || !result.Redirect || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge_method") != "S256" || q.Get("prompt") != "login" || q.Get("login_hint") != "employee" || q.Get("client_id") != "enterprise-client" || !strings.Contains(q.Get("scope"), "openid") {
					t.Fatalf("authorization options missing for %s", id)
				}
				cb, e := url.Parse(q.Get("redirect_uri"))
				must(e)
				code := rand.Text()
				idp.mu.Lock()
				idp.codes[code] = ssoCode{q.Get("nonce"), q.Get("code_challenge"), cb.String(), email, sub, style, mode}
				idp.mu.Unlock()
				query := url.Values{"code": {code}, "state": {q.Get("state")}}
				c := w.Result().Cookies()[0]
				return pending{c.Name + "=" + c.Value, strings.TrimPrefix(cb.Path, "/identity/") + "?" + query.Encode(), code}
			}
			finish := func(a *auth.Auth, f pending) *httptest.ResponseRecorder { return call(a, "GET", f.path, f.cookie, nil) }
			target := func(w *httptest.ResponseRecorder, want string) {
				t.Helper()
				if w.Code != 302 || w.Header().Get("Location") != "https://service.test"+want {
					t.Fatalf("callback: got %d %s %s want %s", w.Code, w.Header().Get("Location"), w.Body.String(), want)
				}
			}
			withID := map[string]any{"providerId": "acme"}
			f := start(one, "acme", "employee@example.test", "employee", "client_secret_basic", "", map[string]any{"email": "hello@sub.acme.example"})
			bad := f
			bad.path = strings.Replace(bad.path, "/acme?", "/staff?", 1)
			target(finish(two, bad), "/identity/error?error=state_mismatch")
			bad = f
			bad.cookie = ""
			target(finish(two, bad), "/identity/error?error=state_mismatch")
			w := finish(two, f)
			target(w, "/welcome")
			cookie := ""
			for _, c := range w.Result().Cookies() {
				if strings.Contains(c.Name, "session_token") && c.Value != "" {
					cookie = c.Name + "=" + c.Value
				}
			}
			var session auth.SessionResult
			must(json.Unmarshal(call(one, "GET", "get-session", cookie, nil).Body.Bytes(), &session))
			if session.User.Email != "employee@example.test" || session.User.EmailVerified || session.Session.Token == "" {
				t.Fatalf("invalid issued session %+v", session)
			}
			target(finish(two, f), "/identity/error?error=state_mismatch")
			count := func(q string, args ...any) int {
				var n int
				must(first.db.QueryRowContext(ctx, first.bind(q), args...).Scan(&n))
				return n
			}
			if count(`SELECT COUNT(*) FROM "member" WHERE "organizationId"='tenant' AND "userId"=? AND "role"='member'`, session.User.ID) != 1 {
				t.Fatal("missing membership")
			}
			if count(`SELECT COUNT(*) FROM "account" WHERE "providerId"='acme' AND "accessToken"='access-employee'`) != 0 {
				t.Fatal("stored unencrypted credential")
			}
			exec(`UPDATE "member" SET "role"='admin' WHERE "userId"=?`, session.User.ID)
			target(finish(one, start(two, "acme", "employee@example.test", "employee", "client_secret_basic", "", map[string]any{"organizationSlug": "company"})), "/home")
			// A slug naming no organization counts as none, as in another
			// runtime: the email still selects the provider, and a request
			// naming nothing else is refused.
			target(finish(one, start(two, "acme", "employee@example.test", "employee", "client_secret_basic", "", map[string]any{"organizationSlug": "missing", "email": "hello@sub.acme.example"})), "/home")
			if w := call(one, "POST", "sign-in/sso", "", map[string]any{"organizationSlug": "missing", "callbackURL": "/home"}); w.Code != 400 || !strings.Contains(w.Body.String(), "providerId, orgId or domain is required") {
				t.Fatal("a sign-in naming only an unknown organization was not refused", w.Code, w.Body.String())
			}
			// Without SAML a found provider names the protocol it lacks, an
			// unknown one is not found and an unknown type fails validation.
			for _, c := range []struct {
				body   map[string]any
				status int
				text   string
			}{
				{map[string]any{"providerId": "acme", "providerType": "saml", "callbackURL": "/home"}, 400, "SAML provider is not configured"},
				{map[string]any{"providerId": "absent", "providerType": "saml", "callbackURL": "/home"}, 404, "No provider found for the issuer"},
				{map[string]any{"providerId": "acme", "providerType": "ldap", "callbackURL": "/home"}, 400, `[body.providerType] Invalid option: expected one of "oidc"|"saml"`},
				{map[string]any{"providerId": "acme", "providerType": "", "callbackURL": "/home"}, 400, `[body.providerType] Invalid option: expected one of "oidc"|"saml"`},
				{map[string]any{"providerId": "acme", "providerType": nil, "callbackURL": "/home"}, 400, `[body.providerType] Invalid option: expected one of "oidc"|"saml"`},
				{map[string]any{"providerId": "acme", "providerType": 5, "callbackURL": "/home"}, 400, `[body.providerType] Invalid option: expected one of "oidc"|"saml"`},
			} {
				w := call(one, "POST", "sign-in/sso", "", c.body)
				var e struct{ Message string }
				json.Unmarshal(w.Body.Bytes(), &e)
				if w.Code != c.status || e.Message != c.text {
					t.Fatal("a providerType on a host without SAML was not answered as another runtime answers it", c.body, w.Code, w.Body.String())
				}
			}
			if count(`SELECT COUNT(*) FROM "member" WHERE "userId"=? AND "role"='admin'`, session.User.ID) != 1 {
				t.Fatal("existing role changed")
			}
			exec(`INSERT INTO "invitation" ("id","organizationId","inviterId","email","role","status","expiresAt","createdAt") VALUES (?,?,?,?,?,?,?,?)`, "inv", "tenant", "owner", "invited@example.test", "admin", "pending", first.date(now.Add(time.Hour)), first.date(now))
			target(finish(two, start(one, "acme", "invited@example.test", "invited", "client_secret_basic", "", withID)), "/welcome")
			if count(`SELECT COUNT(*) FROM "member" WHERE "organizationId"='tenant'`) != 1 {
				t.Fatal("pending invite ignored")
			}
			target(finish(two, start(one, "acme", "existing@example.test", "someone", "client_secret_basic", "", withID)), "/retry?error=account+not+linked")
			shared := host(other, true, false, false)
			g := start(shared, "staff", "irrelevant@example.test", "person", "client_secret_post", "", map[string]any{"domain": "staff.example"})
			if !strings.HasPrefix(g.path, "sso/callback?") {
				t.Fatal("shared callback missing")
			}
			target(finish(shared, g), "/welcome")
			target(finish(shared, start(shared, "staff", "else@example.test", "disagree", "client_secret_post", "", map[string]any{"providerId": "staff"})), "/retry?error=invalid_provider")
			target(finish(shared, start(shared, "staff", "ignored@example.test", "userinfo-only", "client_secret_post", "userinfo-only", map[string]any{"providerId": "staff"})), "/welcome")
			if count(`SELECT COUNT(*) FROM "user" WHERE "email"='userinfo-only@userinfo.example'`) != 1 {
				t.Fatal("missing UserInfo identity")
			}
			for _, mode := range []string{"azp", "nonce", "future", "expired", "mismatch", "missing-sub", "signature"} {
				target(finish(two, start(one, "acme", mode+"@example.test", mode, "client_secret_basic", mode, withID)), "/retry?error=invalid_provider")
			}
			for _, settings := range []struct{ disable, implicit bool }{{true, false}, {false, true}} {
				a := host(other, false, settings.disable, settings.implicit)
				target(finish(a, start(a, "acme", "disabled@example.test", "disabled", "client_secret_basic", "", withID)), "/retry?error=signup+disabled")
				// Without an error callback the failure goes to the error page,
				// as in another runtime.
				target(finish(a, start(a, "acme", "disabled@example.test", "disabled", "client_secret_basic", "", map[string]any{"providerId": "acme", "errorCallbackURL": nil})), "/identity/error?error=signup+disabled")
			}
			implicit := host(other, false, false, true)
			target(finish(implicit, start(implicit, "acme", "explicit@example.test", "explicit", "client_secret_basic", "", map[string]any{"providerId": "acme", "requestSignUp": true})), "/welcome")
			ch := start(one, "acme", "changed@example.test", "changed", "client_secret_basic", "", withID)
			exec(`UPDATE "ssoProvider" SET "domain"='changed.example' WHERE "providerId"='acme'`)
			before := idp.tokens.Load()
			target(finish(two, ch), "/retry?error=invalid_state&error_description=sso_provider_changed_during_authentication")
			if idp.tokens.Load() != before {
				t.Fatal("changed provider reached token endpoint")
			}
			mid := start(one, "acme", "interrupted@example.test", "interrupted", "client_secret_basic", "pause", withID)
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- finish(two, mid) }()
			select {
			case <-idp.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("token request missing")
			}
			exec(`UPDATE "ssoProvider" SET "domain"='latest.example' WHERE "providerId"='acme'`)
			close(idp.release)
			target(<-done, "/retry?error=SSO_PROVIDER_CHANGED&error_description=SSO+provider+changed+while+account+linking+was+in+progress")
			if count(`SELECT COUNT(*) FROM "user" WHERE "email"=?`, "interrupted@example.test") != 0 {
				t.Fatal("changed provider committed a user")
			}
			race := start(one, "acme", "once@example.test", "once", "client_secret_basic", "", withID)
			for i := 0; i < 2; i++ {
				go func() { done <- finish(two, race) }()
			}
			locations := map[string]int{}
			for i := 0; i < 2; i++ {
				resp := <-done
				locations[resp.Header().Get("Location")]++
			}
			if locations["https://service.test/welcome"] != 1 || locations["https://service.test/identity/error?error=state_mismatch"] != 1 {
				t.Fatal(locations)
			}
			// An ordinary OAuth node shares the database but verifies a different
			// identity authority under the same public "acme" name.
			staticProfile := auth.OAuthProfile{}
			static, e := auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", Store: other, Secret: strings.Repeat("k", 32), RateLimit: new(bool), SocialProviders: map[string]auth.OAuthProvider{
				"acme": {Config: oauth2.Config{ClientID: "different-client", Endpoint: oauth2.Endpoint{AuthURL: "https://social.example/authorize", TokenURL: "https://social.example/token"}}, Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) { return staticProfile, nil }, VerifyIDToken: func(context.Context, string, string) (auth.OAuthProfile, time.Time, error) {
					return staticProfile, time.Now().Add(time.Minute), nil
				}},
			}})
			must(e)
			socialLogin := func(sub, email string) *httptest.ResponseRecorder {
				staticProfile = auth.OAuthProfile{Subject: sub, Name: "Static identity", Email: email}
				return call(static, "POST", "sign-in/social", "", map[string]any{"provider": "acme", "idToken": map[string]string{"token": rand.Text(), "nonce": rand.Text()}})
			}
			if got := socialLogin("employee", "unrelated@social.example"); got.Code != 401 || !strings.Contains(got.Body.String(), "ACCOUNT_NOT_LINKED") {
				t.Fatalf("static node accepted managed identity: %d %s", got.Code, got.Body.String())
			}
			if got := socialLogin("static-subject", "social@elsewhere.example"); got.Code != 200 {
				t.Fatalf("independent static login failed: %d %s", got.Code, got.Body.String())
			}
			target(finish(two, start(one, "acme", "another@enterprise.example", "static-subject", "client_secret_basic", "", withID)), "/retry?error=account+not+linked")
			var managedID string
			must(first.db.QueryRowContext(ctx, first.bind(`SELECT "id" FROM "account" WHERE "providerId"='acme' AND "accountId"='employee'`)).Scan(&managedID))
			selection := auth.AccountSelection{UserID: session.User.ID, AccountID: managedID}
			if _, err := static.GetAccessToken(ctx, nil, selection); err == nil {
				t.Fatal("static node released an enterprise access token")
			}
			if _, err := static.RefreshToken(ctx, nil, selection); err == nil {
				t.Fatal("static node refreshed an enterprise credential")
			}
			if _, err := static.AccountInfo(ctx, nil, selection); err == nil {
				t.Fatal("static node used an enterprise credential for profile resolution")
			}
			if _, err := other.ProviderCredential(ctx, session.User.ID, managedID); !errors.Is(err, auth.ErrNotFound) {
				t.Fatalf("store exposed cross-source credentials: %v", err)
			}
			if _, err := other.UpdateProviderCredential(ctx, session.User.ID, managedID, func(auth.ProviderAccountCredential) (auth.ProviderAccountCredential, bool, error) {
				t.Fatal("cross-source refresh callback reached")
				return auth.ProviderAccountCredential{}, false, nil
			}); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal(err)
			}
			// Targeted removal and an existing employee signing back in may serialize
			// either way. All engines must complete both operations under contention.
			exec(`INSERT INTO "member" ("id","userId","organizationId","role","createdAt") VALUES ('directory-owner','owner','tenant','owner',?)`, first.date(now))
			ownerSession := auth.StoredSession{Session: auth.Session{ID: "owner-session", Token: "owner-token", UserID: "owner", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			must(first.CreateSession(ctx, ownerSession))
			for n := 0; n < 4; n++ {
				target(finish(one, start(two, "acme", "employee@example.test", "employee", "client_secret_basic", "", withID)), "/home")
				login := start(one, "acme", "employee@example.test", "employee", "client_secret_basic", "", withID)
				barrier := make(chan struct{})
				removed := make(chan error, 1)
				go func() {
					<-barrier
					_, err := first.RemoveOrganizationMember(ctx, "owner", "owner-token", "tenant", "employee@example.test")
					removed <- err
				}()
				go func() { <-barrier; done <- finish(two, login) }()
				close(barrier)
				must(<-removed)
				target(<-done, "/home")
				if count(`SELECT COUNT(*) FROM "member" WHERE "organizationId"='tenant' AND "userId"=?`, session.User.ID) > 1 {
					t.Fatal("duplicate membership after competing login and removal")
				}
			}

			// Administrator bans use the same gate and do not mint a new session.
			sessions := count(`SELECT COUNT(*) FROM "session" WHERE "userId"=?`, session.User.ID)
			exec(`UPDATE "user" SET "banned"=? WHERE "id"=?`, true, session.User.ID)
			target(finish(two, start(one, "acme", "employee@example.test", "employee", "client_secret_basic", "", withID)), "/retry?error=access_denied")
			if count(`SELECT COUNT(*) FROM "session" WHERE "userId"=?`, session.User.ID) != sessions {
				t.Fatal("banned account gained a session")
			}
			// Fill the tenant and confirm the failed membership rolls back the new identity.
			population := count(`SELECT COUNT(*) FROM "member" WHERE "organizationId"='tenant'`)
			for n := population; n < 100; n++ {
				id := fmt.Sprintf("seat-%d", n)
				create(id)
				exec(`INSERT INTO "member" ("id","userId","organizationId","role","createdAt") VALUES (?,?,'tenant','member',?)`, id, id, first.date(now))
			}
			full := finish(two, start(one, "acme", "capacity@example.test", "capacity", "client_secret_basic", "", withID))
			target(full, "/retry?error=access_denied")
			if count(`SELECT COUNT(*) FROM "user" WHERE "email"='capacity@example.test'`) != 0 || count(`SELECT COUNT(*) FROM "account" WHERE "providerId"='acme' AND "accountId"='capacity'`) != 0 {
				t.Fatal("membership denial left partial identity rows")
			}

			expired := start(one, "acme", "expiredstate@example.test", "expiredstate", "client_secret_basic", "", withID)
			u, _ := url.Parse(expired.path)
			exec(`UPDATE "verification" SET "expiresAt"=? WHERE "id"=?`, first.date(now.Add(-time.Hour)), u.Query().Get("state"))
			target(finish(two, expired), "/identity/error?error=state_mismatch")
			var h *httptest.ResponseRecorder
			for _, body := range []map[string]any{{"providerId": "acme", "callbackURL": "https://outside.example"}, {"providerId": "acme", "callbackURL": "/home", "additionalParams": map[string]any{"state": "x"}}} {
				h = call(one, "POST", "sign-in/sso", "", body)
				if h.Code < 400 {
					t.Fatal("invalid authorization accepted")
				}
			}
			issuer, e := oauthprovider.New(oauthprovider.Options{Scopes: []string{"read"}, Authorization: oauthprovider.BrowserAuthorizationOptions{LoginPage: "/login", ConsentPage: "/approve"}})
			must(e)
			issuing, peer := host(first, false, false, false, issuer), host(other, false, false, false, issuer)
			const clientCallback = "https://client.example.test/finish"
			exec(`INSERT INTO "oauthClient" ("id","clientId","applicationType","redirectUris","tokenEndpointAuthMethod","scopes") VALUES ('app-row','rp','native',?,'none',?)`, `["https://client.example.test/finish"]`, `["read"]`)
			params := url.Values{"response_type": {"code"}, "client_id": {"rp"}, "redirect_uri": {clientCallback}, "state": {"original-state"}, "scope": {"read"}, "prompt": {"login consent"}, "code_challenge_method": {"S256"}, "code_challenge": {oauth2.S256ChallengeFromVerifier(oauth2.GenerateVerifier())}}
			page, e := url.Parse(call(issuing, "GET", "oauth2/authorize?"+params.Encode(), "", nil).Header().Get("Location"))
			must(e)
			if page.Path != "/login" {
				t.Fatal("missing signed issuer login page", page.Path)
			}
			verified, e := issuing.VerifyOAuthPageQuery(page.RawQuery)
			must(e)
			rpRequest := verified.Encode()
			issuerSDK, e := client.New("https://service.test/identity", &http.Client{Transport: guestTransport{issuing}})
			must(e)
			reply, e := issuerSDK.SignInSSO(ctx, client.SSOSignInRequest{ProviderID: "staff", CallbackURL: "/home", OAuthQuery: rpRequest})
			must(e)
			upstream, e := url.Parse(reply.URL)
			must(e)
			var stored string
			state := upstream.Query().Get("state")
			must(first.db.QueryRowContext(ctx, first.bind(`SELECT "value" FROM "verification" WHERE "id"=?`), state).Scan(&stored))
			var flow auth.OAuthFlow
			must(json.Unmarshal([]byte(stored), &flow))
			if flow.IssuerLoginQuery != rpRequest || state == "original-state" || upstream.Query().Has("oauth_query") {
				t.Fatal("the native client did not preserve the verified issuer request in provider state")
			}
			begin := func() pending {
				return start(issuing, "staff", "member@enterprise.test", "issuer-member", "client_secret_post", "", map[string]any{"providerId": "staff", "oauth_query": rpRequest})
			}
			priorExchanges := idp.tokens.Load()
			pendingLogin := begin()
			noCookie := pendingLogin
			noCookie.cookie = ""
			target(finish(peer, noCookie), "/identity/error?error=state_mismatch")
			// The identity provider's error comes back with its description, or
			// the error itself when it sends none.
			denial := pendingLogin
			denial.path += "&error=access_denied"
			target(finish(peer, denial), "/retry?error=access_denied&error_description=access_denied")
			bare := start(issuing, "staff", "member@enterprise.test", "issuer-member", "client_secret_post", "", map[string]any{"providerId": "staff", "errorCallbackURL": nil})
			bare.path += "&error=access_denied"
			target(finish(peer, bare), "/identity/error?error=access_denied&error_description=access_denied")
			target(finish(peer, pendingLogin), "/identity/error?error=state_mismatch")
			for _, c := range []struct{ query, want string }{
				{"&error=consent_required&error_description=Ask+an+administrator", "/retry?error=consent_required&error_description=Ask+an+administrator"},
				{"", "/retry?error=invalid_request&error_description=authorization_code_not_found"},
			} {
				login := begin()
				login.path = strings.Replace(login.path, "code=", "ignored=", 1) + c.query
				w := finish(peer, login)
				if w.Code != 302 || w.Header().Get("Location") != "https://service.test"+c.want {
					t.Fatal("the callback did not send the identity provider's error back", c.query, w.Header().Get("Location"))
				}
			}
			pendingLogin = begin()
			disabled := finish(two, pendingLogin)
			if disabled.Code != 400 || !strings.Contains(disabled.Body.String(), "issuer login is unavailable") {
				t.Fatal("callback resumed with the issuer disabled", disabled.Code, disabled.Body.String())
			}
			pendingLogin = begin()
			callback, e := url.Parse(pendingLogin.path)
			must(e)
			state = callback.Query().Get("state")
			must(first.db.QueryRowContext(ctx, first.bind(`SELECT "value" FROM "verification" WHERE "id"=?`), state).Scan(&stored))
			must(json.Unmarshal([]byte(stored), &flow))
			flow.IssuerLoginQuery = issuing.SignOAuthQuery(verified, time.Now().Add(-time.Minute))
			expiredRecord, e := json.Marshal(flow)
			must(e)
			exec(`UPDATE "verification" SET "value"=? WHERE "id"=?`, string(expiredRecord), state)
			out := finish(peer, pendingLogin)
			if out.Code != 400 || !strings.Contains(out.Body.String(), "invalid_signature") || idp.tokens.Load() != priorExchanges {
				t.Fatal("invalid issuer login reached the provider exchange", out.Code, out.Body.String())
			}
			pendingLogin = begin()
			out = finish(peer, pendingLogin)
			var next struct {
				URL      string
				Redirect bool
			}
			must(json.Unmarshal(out.Body.Bytes(), &next))
			destination, e := url.Parse(next.URL)
			must(e)
			if out.Code != 200 || !next.Redirect || destination.Path != "/approve" || destination.Query().Get("state") != "original-state" || idp.tokens.Load() != priorExchanges+1 {
				t.Fatal("cross-instance callback did not resume consent", out.Code, out.Body.String(), destination.Path)
			}
			target(finish(peer, pendingLogin), "/identity/error?error=state_mismatch")
		})
	}
}
