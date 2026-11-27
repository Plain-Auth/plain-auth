package sqlstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
			s, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"oauth-provider"}, schema.Options{})
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
				p, err := op.New(op.Options{Scopes: []string{"offline_access", "read"}, Extensions: []op.Extension{{ClientDiscoveries: discoveries, Grants: map[string]op.GrantHandler{"urn:test:grant": grant}}},
					Authorization: op.BrowserAuthorizationOptions{LoginPage: "/login", ConsentPage: "/consent", AllowPublicClientPrelogin: true}})
				must(err)
				off := false
				h, err := auth.New(auth.Options{BaseURL: base, Secret: strings.Repeat("c", 40), Plugins: []auth.Plugin{p}, Store: s, RateLimit: &off})
				must(err)
				return h
			}
			h := host(first.discovery("stub"))
			verifier := strings.Repeat("v", 64)
			sum := sha256.Sum256([]byte(verifier))
			authorize := func(h *auth.Auth, clientID, scope string) url.Values {
				t.Helper()
				q := url.Values{"client_id": {clientID}, "response_type": {"code"}, "redirect_uri": {"http://127.0.0.1:41234/cb"}, "scope": {scope}, "state": {"saved"},
					"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "prompt": {"none"}}
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
			if got := authorize(h, app, "offline_access read"); got.Get("error") != "consent_required" || got.Get("host") != "127.0.0.1:41234" || first.calls.Load() != 1 {
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
			// With consent, a code exchanges, refreshes and revokes.
			write(`INSERT INTO "oauthConsent" ("id","clientId","userId","scopes","createdAt","updatedAt") VALUES ('approval',?,'owner',?,?,?)`, app, `["offline_access","read"]`, s.date(now), s.date(now))
			got := authorize(h, app, "offline_access read")
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
			// A local https client never reaches the discovery.
			write(`INSERT INTO "oauthClient" ("id","clientId","applicationType","redirectUris","scopes","tokenEndpointAuthMethod") VALUES ('local','https://local.example.test/app','native',?,?,'none')`,
				`["http://127.0.0.1:41234/cb"]`, `["read"]`)
			calls := first.calls.Load()
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
