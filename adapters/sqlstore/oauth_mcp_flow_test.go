package sqlstore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/mcp"
	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// The MCP composition end to end: the plugin seeds and publishes its
// resource; authorize refuses unknown and unlinked resources; a code for
// the MCP resource exchanges
// into a signed access token bound to it, which RequireAuth accepts and
// answers with 403 when a scope is missing until a consented step-up adds
// it; a refresh keeps the resource;
// and a DPoP-bound code gives a token the guard accepts only with the DPoP
// scheme and a proof, spent once across the database, on SQLite,
// PostgreSQL and MySQL.
func TestMCPResourceFlow(t *testing.T) {
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
			s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider", "jwt"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			write := func(q string, args ...any) {
				t.Helper()
				_, err := s.db.ExecContext(ctx, s.bind(q), args...)
				must(err)
			}
			const resource = "https://mcp.example.test/mcp"
			now := time.Now().UTC().Truncate(time.Second)
			write(`INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES ('owner','Owner','owner@example.test',?,?,?)`, true, s.date(now), s.date(now))
			write(`INSERT INTO "session" ("id","userId","token","createdAt","updatedAt","expiresAt") VALUES ('sid','owner','browser',?,?,?)`, s.date(now), s.date(now), s.date(now.Add(time.Hour)))
			write(`INSERT INTO "oauthClient" ("id","clientId","applicationType","redirectUris","scopes","tokenEndpointAuthMethod","skipConsent") VALUES ('app','app','native',?,?,'none',?)`,
				`["http://127.0.0.1:41234/cb"]`, `["openid","offline_access","mcp:read","mcp:write"]`, false)
			const unlinked = "https://mcp.example.test/other"
			write(`INSERT INTO "oauthResource" ("id","identifier","name") VALUES ('other',?,'Other')`, unlinked)
			write(`INSERT INTO "oauthConsent" ("id","clientId","userId","scopes","resources","createdAt","updatedAt") VALUES ('approval','app','owner',?,?,?,?)`,
				`["openid","offline_access","mcp:read"]`, `["`+resource+`"]`, s.date(now), s.date(now))
			provider, err := mcp.New(mcp.Options{Options: oauthprovider.Options{Scopes: []string{"openid", "offline_access", "mcp:read", "mcp:write"},
				Authorization: oauthprovider.BrowserAuthorizationOptions{LoginPage: "/login", ConsentPage: "/consent"}}, Resource: resource})
			must(err)
			signing, err := auth.NewJWT(auth.JWTOptions{})
			must(err)
			const origin = "https://mcp.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("f", 40), Store: s, Plugins: []auth.Plugin{provider, signing}, RateLimit: &off})
			must(err)
			tokenURL := origin + "/api/auth/oauth2/token"
			verifier := strings.Repeat("v", 64)
			sum := sha256.Sum256([]byte(verifier))
			// authorize asks for a code with the browser session and no prompt.
			authorize := func(scope, jkt string, resources ...string) url.Values {
				t.Helper()
				q := url.Values{"client_id": {"app"}, "response_type": {"code"}, "redirect_uri": {"http://127.0.0.1:41234/cb"}, "scope": {scope}, "state": {"saved"},
					"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "prompt": {"none"}, "resource": resources}
				if jkt != "" {
					q.Set("dpop_jkt", jkt)
				}
				req := httptest.NewRequest("GET", origin+"/api/auth/oauth2/authorize?"+q.Encode(), nil)
				req.AddCookie(h.SessionCookie("browser", true))
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				u, err := url.Parse(out.Header().Get("Location"))
				must(err)
				if out.Code != 302 || u.Host != "127.0.0.1:41234" {
					t.Fatal("authorize did not return to the client", out.Code, out.Header(), out.Body.String())
				}
				return u.Query()
			}
			code := func(scope, jkt string) string {
				t.Helper()
				got := authorize(scope, jkt, resource)
				if got.Get("code") == "" {
					t.Fatal("authorize issued no code", got)
				}
				return got.Get("code")
			}
			// Unknown and unlinked resources are refused at authorize.
			for _, target := range []string{"https://unknown.example.test/mcp", unlinked, resource} {
				if got := authorize("openid mcp:read", "", target); got.Get("error") != "invalid_target" || got.Has("code") {
					t.Fatal("a resource outside the client was accepted", target, got)
				}
			}
			// The plugin seeded the MCP resource on the first request, and its
			// metadata names it; the client is then linked to it.
			var seeded int
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "oauthResource" WHERE "identifier"=?`), resource).Scan(&seeded))
			if seeded != 1 {
				t.Fatal("the plugin did not seed the MCP resource", seeded)
			}
			metadata := httptest.NewRecorder()
			h.ServeHTTP(metadata, httptest.NewRequest("GET", origin+"/.well-known/oauth-protected-resource/mcp", nil))
			var published map[string]any
			if metadata.Code != 200 || json.Unmarshal(metadata.Body.Bytes(), &published) != nil || published["resource"] != resource {
				t.Fatal("the protected resource metadata did not name the resource", metadata.Code, metadata.Body.String())
			}
			write(`INSERT INTO "oauthClientResource" ("id","resourceId","clientId") VALUES ('link',?,'app')`, resource)
			post := func(form url.Values, proof string) map[string]any {
				t.Helper()
				req := httptest.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if proof != "" {
					req.Header.Set("DPoP", proof)
				}
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				var body map[string]any
				must(json.Unmarshal(out.Body.Bytes(), &body))
				if out.Code != 200 {
					t.Fatal("the token request failed", out.Code, body)
				}
				return body
			}
			claimsOf := func(token string) map[string]any {
				t.Helper()
				parts := strings.Split(token, ".")
				if len(parts) != 3 {
					t.Fatal("not a signed token", token)
				}
				raw, err := base64.RawURLEncoding.DecodeString(parts[1])
				must(err)
				var claims map[string]any
				must(json.Unmarshal(raw, &claims))
				return claims
			}
			audience := func(claims map[string]any) []any {
				if one, ok := claims["aud"].(string); ok {
					return []any{one}
				}
				list, _ := claims["aud"].([]any)
				return list
			}
			// The code exchanges into a token bound to the resource.
			exchange := func(code, proof string) map[string]any {
				t.Helper()
				return post(url.Values{"grant_type": {"authorization_code"}, "client_id": {"app"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {"http://127.0.0.1:41234/cb"}, "resource": {resource}}, proof)
			}
			body := exchange(code("openid offline_access mcp:read", ""), "")
			claims := claimsOf(body["access_token"].(string))
			if !slices.Contains(audience(claims), any(resource)) || claims["azp"] != "app" || claims["scope"] != "openid offline_access mcp:read" {
				t.Fatal("the access token was not bound to the MCP resource", claims)
			}
			// The guard accepts it and asks for a missing scope.
			var seen map[string]any
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen, _ = mcp.AccessTokenClaims(r.Context())
				w.WriteHeader(204)
			})
			guard := func(opts mcp.AuthOptions) http.Handler {
				t.Helper()
				opts.Resource = resource
				g, err := mcp.RequireAuth(h, s, next, opts)
				must(err)
				return g
			}
			call := func(g http.Handler, authorization, proof string) *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", resource, nil)
				r.Header.Set("Authorization", authorization)
				if proof != "" {
					r.Header.Set("DPoP", proof)
				}
				w := httptest.NewRecorder()
				g.ServeHTTP(w, r)
				return w
			}
			if w := call(guard(mcp.AuthOptions{}), "Bearer "+body["access_token"].(string), ""); w.Code != 204 || seen["sub"] != "owner" {
				t.Fatal("the guard refused the MCP token", w.Code, w.Header())
			}
			if w := call(guard(mcp.AuthOptions{RequiredScopes: []string{"mcp:write"}}), "Bearer "+body["access_token"].(string), ""); w.Code != 403 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `scope="mcp:write"`) {
				t.Fatal("a missing scope was not asked for", w.Code, w.Header())
			}
			// Step-up: the wider scope needs consent, then passes the scoped guard.
			if got := authorize("openid offline_access mcp:read mcp:write", "", resource); got.Get("error") != "consent_required" {
				t.Fatal("a wider scope skipped consent", got)
			}
			write(`UPDATE "oauthConsent" SET "scopes"=? WHERE "id"='approval'`, `["openid","offline_access","mcp:read","mcp:write"]`)
			wider := exchange(code("openid offline_access mcp:read mcp:write", ""), "")
			if w := call(guard(mcp.AuthOptions{RequiredScopes: []string{"mcp:write"}}), "Bearer "+wider["access_token"].(string), ""); w.Code != 204 {
				t.Fatal("the stepped-up token was refused", w.Code, w.Header())
			}
			// A refresh without resource keeps the resource.
			refreshed := post(url.Values{"grant_type": {"refresh_token"}, "client_id": {"app"}, "refresh_token": {body["refresh_token"].(string)}}, "")
			if !slices.Contains(audience(claimsOf(refreshed["access_token"].(string))), any(resource)) {
				t.Fatal("the refresh dropped the resource", claimsOf(refreshed["access_token"].(string)))
			}
			// A DPoP-bound code gives a token the guard accepts only with a proof.
			key := newDPoPKey(t)
			bound := exchange(code("openid mcp:read", key.thumb), key.proof(t, tokenURL))
			access := bound["access_token"].(string)
			if cnf, _ := claimsOf(access)["cnf"].(map[string]any); bound["token_type"] != "DPoP" || cnf["jkt"] != key.thumb {
				t.Fatal("the DPoP-bound code did not bind the token", bound)
			}
			if w := call(guard(mcp.AuthOptions{}), "Bearer "+access, ""); w.Code != 401 || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "DPoP ") {
				t.Fatal("a bound token was accepted as Bearer", w.Code, w.Header())
			}
			ath := sha256.Sum256([]byte(access))
			payload, _ := json.Marshal(map[string]any{"htm": "POST", "htu": resource, "iat": time.Now().Unix(), "jti": rand.Text(), "ath": base64.RawURLEncoding.EncodeToString(ath[:])})
			signed, err := key.signer.Sign(payload)
			must(err)
			proof, err := signed.CompactSerialize()
			must(err)
			if w := call(guard(mcp.AuthOptions{}), "DPoP "+access, proof); w.Code != 204 {
				t.Fatal("a bound token with its proof was refused", w.Code, w.Header())
			}
			other, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider", "jwt"}, schema.Options{})
			must(err)
			t.Cleanup(func() { other.Close() })
			replay, err := mcp.RequireAuth(h, other, next, mcp.AuthOptions{Resource: resource})
			must(err)
			if w := call(replay, "DPoP "+access, proof); w.Code != 401 {
				t.Fatal("a spent proof was accepted through another pool", w.Code)
			}
		})
	}
}
