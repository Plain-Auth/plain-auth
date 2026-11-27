package sqlstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
	jose "github.com/go-jose/go-jose/v4"
)

// stubDiscovery resolves https client IDs by registering a fixed public
// document, or answers nil or an error, and counts its calls.
type stubDiscovery struct {
	calls atomic.Int32
	mode  atomic.Value
	// keys is the JWK set of a client ID naming keys.example.test, which
	// authenticates with private_key_jwt.
	keys string
}

func (d *stubDiscovery) discovery(id string) op.ClientDiscovery {
	return op.ClientDiscovery{ID: id, Matches: func(clientID string) bool { return strings.HasPrefix(clientID, "https://") },
		Resolve: func(ctx context.Context, req op.DiscoveryRequest) (*op.DiscoveredClient, error) {
			d.calls.Add(1)
			switch d.mode.Load() {
			case "nil":
				return nil, nil
			case "stored":
				return req.Existing, nil
			case "error":
				return nil, &auth.OAuthError{Status: 400, Code: "invalid_client", Description: "metadata document unavailable"}
			}
			raw := `{"client_id":"` + req.ClientID + `","client_name":"Doc App","redirect_uris":["http://127.0.0.1:41234/cb"],"grant_types":["authorization_code","refresh_token","urn:test:grant"]}`
			if strings.Contains(req.ClientID, "keys.example.test") {
				raw = `{"client_id":"` + req.ClientID + `","grant_types":["client_credentials"],"token_endpoint_auth_method":"private_key_jwt","jwks":` + d.keys + `}`
			}
			doc, err := op.ParseClientMetadataDocument([]byte(raw))
			if err != nil {
				return nil, err
			}
			result, err := req.Register(ctx, doc)
			if err != nil {
				return nil, err
			}
			return &result.Client, nil
		}, Metadata: map[string]any{"client_id_metadata_document_supported": true}}
}

// Client discoveries resolve unknown client IDs at authorize, the directory,
// prelogin and the provider API of an extension grant, a stored client
// through its own discovery at the token, refresh and revocation
// endpoints, never a local client,
// and fail closed when the owning discovery resolves nothing, is removed
// or no longer matches; an unknown ID tries each discovery in order and a
// Resolve error is the endpoint's, on SQLite, PostgreSQL and MySQL.
func TestClientDiscoveryLookups(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			s, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"oauth-provider", "jwt"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			write := func(q string, args ...any) {
				t.Helper()
				_, err := s.db.ExecContext(ctx, s.bind(q), args...)
				must(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			write(`INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES ('owner','Owner','owner@example.test',?,?,?)`, true, s.date(now), s.date(now))
			write(`INSERT INTO "session" ("id","userId","token","createdAt","updatedAt","expiresAt") VALUES ('sid','owner','browser',?,?,?)`, s.date(now), s.date(now), s.date(now.Add(time.Hour)))
			const base = "https://issuer.example.test"
			first, second := &stubDiscovery{}, &stubDiscovery{}
			var opts op.Options
			const api = "https://api.example.test"
			opaqueTokens := false
			host := func(discoveries ...op.ClientDiscovery) *auth.Auth {
				t.Helper()
				// The extension grant reads clients through the provider's API.
				grant := func(in op.GrantInput) (op.TokenResponse, error) {
					client, err := in.Provider.AuthenticateClient(op.ClientAuthenticationRequest{AllowPublic: true})
					if err != nil {
						return op.TokenResponse{}, err
					}
					other, err := in.Provider.Client(in.Form.Get("other"))
					if err != nil || other == nil {
						return op.TokenResponse{}, &auth.OAuthError{Status: 400, Code: "invalid_request", Description: "other client not found"}
					}
					return op.TokenResponse{AccessToken: "x", TokenType: "Bearer", Fields: map[string]any{"client": client.ClientID, "other": *other.Name}}, nil
				}
				opts = op.Options{Scopes: []string{"openid", "offline_access", "read"}, Extensions: []op.Extension{{ClientDiscoveries: discoveries, Grants: map[string]op.GrantHandler{"urn:test:grant": grant}}},
					Authorization:    op.BrowserAuthorizationOptions{LoginPage: "/login", ConsentPage: "/consent", AllowPublicClientPrelogin: true},
					ClientPrivileges: func(context.Context, op.ClientAccess) (bool, error) { return true, nil },
					Resources:        []op.ResourceDefinition{{Identifier: api}}}
				opts.Assertions.AllowKeyRotation = true
				opts.Registration.DefaultResources = []string{api}
				opts.Tokens.OpaqueResourceTokens = opaqueTokens
				p, err := op.New(opts)
				must(err)
				off := false
				signing, err := auth.NewJWT(auth.JWTOptions{})
				must(err)
				h, err := auth.New(auth.Options{BaseURL: base, Secret: strings.Repeat("c", 40), Plugins: []auth.Plugin{p, signing}, Store: s, RateLimit: &off})
				must(err)
				return h
			}
			h := host(first.discovery("stub"))
			mainOptions := opts
			verifier := strings.Repeat("v", 64)
			sum := sha256.Sum256([]byte(verifier))
			authorize := func(h *auth.Auth, clientID, scope string, resources ...string) url.Values {
				t.Helper()
				q := url.Values{"client_id": {clientID}, "response_type": {"code"}, "redirect_uri": {"http://127.0.0.1:41234/cb"}, "scope": {scope}, "state": {"saved"},
					"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "prompt": {"none"}, "resource": resources}
				req := httptest.NewRequest("GET", base+"/api/auth/oauth2/authorize?"+q.Encode(), nil)
				req.AddCookie(h.SessionCookie("browser", true))
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				u, err := url.Parse(out.Header().Get("Location"))
				must(err)
				if out.Code != 302 {
					t.Fatal("authorize did not redirect", out.Code, out.Body.String())
				}
				values := u.Query()
				values.Set("host", u.Host)
				return values
			}
			post := func(h *auth.Auth, path string, form url.Values) (int, map[string]any) {
				t.Helper()
				req := httptest.NewRequest("POST", base+"/api/auth"+path, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				var body map[string]any
				json.Unmarshal(out.Body.Bytes(), &body)
				return out.Code, body
			}
			const app = "https://app.example.test/client.json"
			// The first authorize registers the document and asks for consent.
			if got := authorize(h, app, "openid offline_access read"); got.Get("error") != "consent_required" || got.Get("host") != "127.0.0.1:41234" || first.calls.Load() != 1 {
				t.Fatal("the discovered client was not resolved at authorize", got, first.calls.Load())
			}
			var owner string
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "clientDiscoveryId" FROM "oauthClient" WHERE "clientId"=?`), app).Scan(&owner))
			if owner != "stub" {
				t.Fatal("the client was not stored for its discovery", owner)
			}
			// The directory resolves it too.
			req := httptest.NewRequest("GET", base+"/api/auth/oauth2/public-client?client_id="+url.QueryEscape(app), nil)
			req.AddCookie(h.SessionCookie("browser", true))
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			if out.Code != 200 || !strings.Contains(out.Body.String(), `"client_name":"Doc App"`) {
				t.Fatal("public-client did not serve the discovered client", out.Code, out.Body.String())
			}
			// A login page reads a new discovered client before any session.
			const early = "https://early.example.test/client.json"
			raw, err := json.Marshal(map[string]any{"client_id": early, "oauth_query": h.SignOAuthQuery(url.Values{"client_id": {early}}, time.Now().Add(time.Minute))})
			must(err)
			req = httptest.NewRequest("POST", base+"/api/auth/oauth2/public-client-prelogin", strings.NewReader(string(raw)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", base)
			out = httptest.NewRecorder()
			h.ServeHTTP(out, req)
			if out.Code != 200 || !strings.Contains(out.Body.String(), `"client_name":"Doc App"`) {
				t.Fatal("prelogin did not resolve a discovered client", out.Code, out.Body.String())
			}
			// An extension grant authenticates a discovered client and looks up
			// a new one through the provider's API.
			const looked = "https://looked.example.test/client.json"
			if status, body := post(h, "/oauth2/token", url.Values{"grant_type": {"urn:test:grant"}, "client_id": {app}, "other": {looked}}); status != 200 || body["client"] != app || body["other"] != "Doc App" {
				t.Fatal("the extension grant did not resolve discovered clients", status, body)
			}
			// A client resolved once in a request is not resolved again.
			calls := first.calls.Load()
			if status, body := post(h, "/oauth2/token", url.Values{"grant_type": {"urn:test:grant"}, "client_id": {app}, "other": {app}}); status != 200 || first.calls.Load() != calls+1 {
				t.Fatal("a client was resolved twice in one request", status, body, first.calls.Load()-calls)
			}
			// With consent, a code exchanges, refreshes and revokes.
			write(`INSERT INTO "oauthConsent" ("id","clientId","userId","scopes","createdAt","updatedAt") VALUES ('approval',?,'owner',?,?,?)`, app, `["openid","offline_access","read"]`, s.date(now), s.date(now))
			got := authorize(h, app, "openid offline_access read")
			if got.Get("code") == "" {
				t.Fatal("a consented discovered client got no code", got)
			}
			status, token := post(h, "/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {app}, "code": {got.Get("code")}, "code_verifier": {verifier}, "redirect_uri": {"http://127.0.0.1:41234/cb"}})
			if status != 200 || token["access_token"] == nil || token["refresh_token"] == nil {
				t.Fatal("the code exchange failed", status, token)
			}
			status, refreshed := post(h, "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {app}, "refresh_token": {token["refresh_token"].(string)}})
			if status != 200 || refreshed["refresh_token"] == nil {
				t.Fatal("the refresh failed", status, refreshed)
			}
			if status, body := post(h, "/oauth2/revoke", url.Values{"client_id": {app}, "token": {refreshed["refresh_token"].(string)}}); status != 200 {
				t.Fatal("the client could not revoke its token", status, body)
			}
			// A local resource server introspects the client's resource tokens,
			// opaque and signed, and UserInfo reads its grant.
			rsSecret := sha256.Sum256([]byte("rs-secret"))
			write(`INSERT INTO "oauthClient" ("id","clientId","clientSecret","tokenEndpointAuthMethod","redirectUris","grantTypes") VALUES ('rs','rs',?,'client_secret_post','[]',?)`,
				base64.RawURLEncoding.EncodeToString(rsSecret[:]), `["client_credentials"]`)
			write(`INSERT INTO "oauthClientResource" ("id","resourceId","clientId") VALUES ('rs-link',?,'rs')`, api)
			write(`UPDATE "oauthConsent" SET "resources"=? WHERE "id"='approval'`, `["`+api+`"]`)
			boundToken := func(h *auth.Auth) string {
				t.Helper()
				got := authorize(h, app, "openid read", api)
				status, body := post(h, "/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {app}, "code": {got.Get("code")}, "code_verifier": {verifier}, "redirect_uri": {"http://127.0.0.1:41234/cb"}, "resource": {api}})
				if status != 200 {
					t.Fatal("a resource code exchange failed", got, status, body)
				}
				return body["access_token"].(string)
			}
			introspect := func(h *auth.Auth, token string) any {
				t.Helper()
				status, body := post(h, "/oauth2/introspect", url.Values{"client_id": {"rs"}, "client_secret": {"rs-secret"}, "token": {token}})
				if status != 200 {
					t.Fatal("introspection failed", status, body)
				}
				return body["active"]
			}
			userInfo := func(h *auth.Auth, token string) int {
				req := httptest.NewRequest("GET", base+"/api/auth/oauth2/userinfo", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				return out.Code
			}
			signedToken := boundToken(h)
			opaqueTokens = true
			opaqueToken := boundToken(host(first.discovery("stub")))
			opaqueTokens = false
			if strings.Count(signedToken, ".") != 2 || strings.Count(opaqueToken, ".") == 2 {
				t.Fatal("the resource tokens were not one signed and one opaque", signedToken, opaqueToken)
			}
			if introspect(h, signedToken) != true || introspect(h, opaqueToken) != true {
				t.Fatal("a resource server could not introspect a discovered client's tokens")
			}
			if code := userInfo(h, token["access_token"].(string)); code != 200 {
				t.Fatal("UserInfo refused a discovered client's grant", code)
			}
			// Without the discovery the tokens are inactive and UserInfo refuses.
			bare := host(op.ClientDiscovery{ID: "other", Matches: func(string) bool { return true }, Resolve: func(context.Context, op.DiscoveryRequest) (*op.DiscoveredClient, error) {
				t.Fatal("another discovery was asked about a stored client")
				return nil, nil
			}})
			if introspect(bare, signedToken) != false || introspect(bare, opaqueToken) != false || userInfo(bare, token["access_token"].(string)) != 401 {
				t.Fatal("tokens of an unconfigured discovery's client were served")
			}
			// The user updates the consent of a discovered client.
			req = httptest.NewRequest("POST", base+"/api/auth/oauth2/update-consent", strings.NewReader(`{"id":"approval","update":{"scopes":["openid","read"]}}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", base)
			req.AddCookie(h.SessionCookie("browser", true))
			out = httptest.NewRecorder()
			h.ServeHTTP(out, req)
			if out.Code != 200 {
				t.Fatal("the consent of a discovered client could not be updated", out.Code, out.Body.String())
			}
			req = httptest.NewRequest("POST", base+"/api/auth/oauth2/update-consent", strings.NewReader(`{"id":"approval","update":{"scopes":["read"]}}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", base)
			req.AddCookie(bare.SessionCookie("browser", true))
			out = httptest.NewRecorder()
			bare.ServeHTTP(out, req)
			if out.Code != 404 || !strings.Contains(out.Body.String(), "client not found") {
				t.Fatal("the consent of an unconfigured discovery's client was updated", out.Code, out.Body.String())
			}
			// A discovered client with keys authenticates to introspection.
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			must(err)
			set, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, Algorithm: "EdDSA", Use: "sig", KeyID: "k"}}})
			must(err)
			first.keys = string(set)
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, (&jose.SignerOptions{}).WithHeader("kid", "k"))
			must(err)
			const keyed = "https://keys.example.test/client.json"
			claims, err := json.Marshal(map[string]any{"iss": keyed, "sub": keyed, "aud": base + "/api/auth", "exp": time.Now().Unix() + 60, "jti": "introspect-1"})
			must(err)
			signed, err := signer.Sign(claims)
			must(err)
			assertion, err := signed.CompactSerialize()
			must(err)
			if status, body := post(h, "/oauth2/introspect", url.Values{"client_assertion": {assertion}, "client_assertion_type": {op.ClientAssertionType}, "token": {"unknown"}}); status != 200 || body["active"] != false {
				t.Fatal("a discovered client could not introspect", status, body)
			}
			// An owner cannot delete a discovered client, its keys are rotated
			// where it publishes them, an admin sets its machine scopes without
			// moving updatedAt, and end-session finds it.
			jsonPost := func(path string, body map[string]any) (int, map[string]any) {
				t.Helper()
				raw, err := json.Marshal(body)
				must(err)
				req := httptest.NewRequest("POST", base+"/api/auth"+path, strings.NewReader(string(raw)))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", base)
				req.AddCookie(h.SessionCookie("browser", true))
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				var reply map[string]any
				json.Unmarshal(out.Body.Bytes(), &reply)
				return out.Code, reply
			}
			if status, body := jsonPost("/oauth2/delete-client", map[string]any{"client_id": app}); status != 401 {
				t.Fatal("an owner deleted a discovered client", status, body)
			}
			if status, body := jsonPost("/oauth2/update-client", map[string]any{"client_id": app, "update": map[string]any{"client_name": "Renamed"}}); status != 401 {
				t.Fatal("an owner updated a discovered client", status, body)
			}
			var public map[string]any
			must(json.Unmarshal([]byte(first.keys), &public))
			claims, err = json.Marshal(map[string]any{"iss": keyed, "sub": keyed, "aud": base + "/api/auth/oauth2/client/rotate-keys", "exp": time.Now().Unix() + 60, "jti": "rotate-1"})
			must(err)
			signed, err = signer.Sign(claims)
			must(err)
			rotation, err := signed.CompactSerialize()
			must(err)
			if status, body := jsonPost("/oauth2/client/rotate-keys", map[string]any{"client_assertion": rotation, "client_assertion_type": op.ClientAssertionType, "jwks": public}); status/100 != 4 ||
				body["error_description"] != "client keys are not stored inline; rotate them where the client publishes them" {
				t.Fatal("a discovered client's keys were rotated", status, body)
			}
			first.mode.Store("stored")
			before := now.Add(-time.Hour)
			write(`UPDATE "oauthClient" SET "updatedAt"=? WHERE "clientId"=?`, s.date(before), keyed)
			manager, err := op.NewClientManager(h, s, mainOptions)
			must(err)
			header := http.Header{"Cookie": {h.SessionCookie("browser", true).String()}}
			if granted, err := manager.SetClientCredentialsScopes(ctx, header, keyed, []string{"read"}); err != nil || len(granted) != 1 || granted[0] != "read" {
				t.Fatal("an admin could not set a discovered client's machine scopes", granted, err)
			}
			var after time.Time
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "updatedAt" FROM "oauthClient" WHERE "clientId"=?`), keyed).Scan(&after))
			if !after.Equal(before) {
				t.Fatal("setting machine scopes moved a discovered client's updatedAt", before, after)
			}
			var refusal auth.StatusOnlyError
			if _, err := manager.UpdateClient(ctx, header, app, op.ClientAdminUpdate{Fields: map[string]any{"client_name": "Renamed"}}); !errors.As(err, &refusal) || refusal != http.StatusUnauthorized {
				t.Fatal("an admin update of an unowned discovered client was not refused as unowned", err)
			}
			first.mode.Store("")
			req = httptest.NewRequest("GET", base+"/api/auth/oauth2/end-session?client_id="+url.QueryEscape(app), nil)
			req.Header.Set("Accept", "application/json")
			out = httptest.NewRecorder()
			h.ServeHTTP(out, req)
			if out.Code != 401 || !strings.Contains(out.Body.String(), "The client is not allowed to initiate logout") {
				t.Fatal("end-session did not find the discovered client", out.Code, out.Body.String())
			}
			// A local https client never reaches the discovery.
			write(`INSERT INTO "oauthClient" ("id","clientId","applicationType","redirectUris","scopes","tokenEndpointAuthMethod") VALUES ('local','https://local.example.test/app','native',?,?,'none')`,
				`["http://127.0.0.1:41234/cb"]`, `["read"]`)
			calls = first.calls.Load()
			if got := authorize(h, "https://local.example.test/app", "read"); got.Get("error") != "consent_required" || first.calls.Load() != calls {
				t.Fatal("a local client went to the discovery", got, first.calls.Load())
			}
			// The owner resolving nothing hides the row.
			first.mode.Store("nil")
			if got := authorize(h, app, "read"); got.Get("error") != "invalid_client" || got.Get("host") == "127.0.0.1:41234" {
				t.Fatal("an unresolved discovered client was served at authorize", got)
			}
			if status, body := post(h, "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {app}, "refresh_token": {"x"}}); status != 401 && status != 400 || body["error"] != "invalid_client" {
				t.Fatal("an unresolved discovered client was served at the token endpoint", status, body)
			}
			// A Resolve error is the endpoint's.
			first.mode.Store("error")
			if status, body := post(h, "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {app}, "refresh_token": {"x"}}); status != 400 || body["error_description"] != "metadata document unavailable" {
				t.Fatal("a Resolve error was not returned", status, body)
			}
			first.mode.Store("")
			// With its discovery removed, or not matching, the row stays hidden.
			other := op.ClientDiscovery{ID: "other", Matches: func(string) bool { return true }, Resolve: func(context.Context, op.DiscoveryRequest) (*op.DiscoveredClient, error) {
				t.Fatal("another discovery was asked about a stored client")
				return nil, nil
			}}
			if got := authorize(host(other), app, "read"); got.Get("error") != "invalid_client" {
				t.Fatal("a client of a removed discovery was served", got)
			}
			blind := first.discovery("stub")
			blind.Matches = func(id string) bool { return id != app }
			if got := authorize(host(blind, other), app, "read"); got.Get("error") != "invalid_client" {
				t.Fatal("a client its discovery no longer matches was served", got)
			}
			// An unknown ID tries each discovery in order.
			first.mode.Store("nil")
			calls = first.calls.Load()
			two := host(first.discovery("stub"), second.discovery("second"))
			const fresh = "https://fresh.example.test/client.json"
			if got := authorize(two, fresh, "read"); got.Get("error") != "consent_required" || first.calls.Load() != calls+1 || second.calls.Load() != 1 {
				t.Fatal("the discoveries were not tried in order", got, first.calls.Load(), second.calls.Load())
			}
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "clientDiscoveryId" FROM "oauthClient" WHERE "clientId"=?`), fresh).Scan(&owner))
			if owner != "second" {
				t.Fatal("the second discovery did not own the client", owner)
			}
			// The first discovery to resolve wins.
			first.mode.Store("")
			calls = second.calls.Load()
			if got := authorize(two, "https://won.example.test/client.json", "read"); got.Get("error") != "consent_required" || second.calls.Load() != calls {
				t.Fatal("a later discovery was asked after an earlier one resolved", got, second.calls.Load())
			}
		})
	}
}
