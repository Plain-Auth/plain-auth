package sqlstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/Plain-Org/plain-auth/plugins/cimd"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
	jose "github.com/go-jose/go-jose/v4"
)

// documents serves metadata documents and key sets by URL and counts the
// fetches of each.
type documents struct {
	mu      sync.Mutex
	bodies  map[string]string
	fetched map[string]int
}

func (d *documents) RoundTrip(r *http.Request) (*http.Response, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fetched[r.URL.String()]++
	body, ok := d.bodies[r.URL.String()]
	if !ok {
		return &http.Response{StatusCode: 404, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	h := http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}}
	return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1}, nil
}

func (d *documents) set(url, body string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.bodies[url] = body
}

func (d *documents) count(url string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.fetched[url]
}

// A client identified by its metadata document authorizes, consents,
// exchanges a code with PKCE, reads UserInfo and refreshes; a refetched
// document replaces its fields and keeps the server-owned flags; a
// private_key_jwt client's same-origin jwks_uri authenticates; a local https
// client is never fetched; a document for another URL is refused; and the
// issuer advertises metadata documents, on SQLite, PostgreSQL and MySQL.
func TestCIMDClients(t *testing.T) {
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
			const app = "https://app.example.test/client.json"
			docs := &documents{bodies: map[string]string{}, fetched: map[string]int{}}
			docs.set(app, `{"client_id":"`+app+`","client_name":"Doc App","redirect_uris":["http://127.0.0.1:41234/cb"],"grant_types":["authorization_code","refresh_token"]}`)
			discovery, err := cimd.NewClientDiscovery(cimd.Options{Transport: docs})
			must(err)
			p, err := op.New(op.Options{Scopes: []string{"openid", "offline_access", "read"}, Extensions: []op.Extension{{ClientDiscoveries: []op.ClientDiscovery{discovery}}},
				Authorization: op.BrowserAuthorizationOptions{LoginPage: "/login", ConsentPage: "/consent"}})
			must(err)
			signing, err := auth.NewJWT(auth.JWTOptions{})
			must(err)
			const base = "https://issuer.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: base, Secret: strings.Repeat("d", 40), Plugins: []auth.Plugin{p, signing}, Store: s, RateLimit: &off})
			must(err)
			verifier := strings.Repeat("v", 64)
			sum := sha256.Sum256([]byte(verifier))
			authorize := func(clientID string) (int, url.Values) {
				t.Helper()
				q := url.Values{"client_id": {clientID}, "response_type": {"code"}, "redirect_uri": {"http://127.0.0.1:41234/cb"}, "scope": {"openid offline_access read"}, "state": {"s"},
					"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "prompt": {"none"}}
				req := httptest.NewRequest("GET", base+"/api/auth/oauth2/authorize?"+q.Encode(), nil)
				req.AddCookie(h.SessionCookie("browser", true))
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				u, _ := url.Parse(out.Header().Get("Location"))
				values := u.Query()
				values.Set("host", u.Host)
				values.Set("body", out.Body.String())
				return out.Code, values
			}
			post := func(path string, form url.Values) (int, map[string]any) {
				t.Helper()
				req := httptest.NewRequest("POST", base+"/api/auth"+path, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				var body map[string]any
				json.Unmarshal(out.Body.Bytes(), &body)
				return out.Code, body
			}
			// The first authorize stores the client and asks for consent.
			if code, got := authorize(app); code != 302 || got.Get("error") != "consent_required" || docs.count(app) != 1 {
				t.Fatal("the document client was not resolved", code, got)
			}
			var owner string
			var applicationType *string
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "clientDiscoveryId","applicationType" FROM "oauthClient" WHERE "clientId"=?`), app).Scan(&owner, &applicationType))
			if owner != cimd.DiscoveryID || applicationType != nil {
				t.Fatal("the client was not stored for the discovery", owner, applicationType)
			}
			// With consent: a code, a PKCE exchange, UserInfo and a refresh.
			write(`INSERT INTO "oauthConsent" ("id","clientId","userId","scopes","createdAt","updatedAt") VALUES ('approval',?,'owner',?,?,?)`, app, `["openid","offline_access","read"]`, s.date(now), s.date(now))
			_, got := authorize(app)
			status, token := post("/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {app}, "code": {got.Get("code")}, "code_verifier": {verifier}, "redirect_uri": {"http://127.0.0.1:41234/cb"}})
			if status != 200 || token["access_token"] == nil || token["id_token"] == nil {
				t.Fatal("the code exchange failed", status, token)
			}
			req := httptest.NewRequest("GET", base+"/api/auth/oauth2/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+token["access_token"].(string))
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			if out.Code != 200 || !strings.Contains(out.Body.String(), `"sub":"owner"`) {
				t.Fatal("UserInfo failed", out.Code, out.Body.String())
			}
			if status, body := post("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {app}, "refresh_token": {token["refresh_token"].(string)}}); status != 200 {
				t.Fatal("the refresh failed", status, body)
			}
			// A refetched document replaces its fields and keeps the server-owned ones.
			write(`UPDATE "oauthClient" SET "skipConsent"=?,"clientCredentialsScopes"=? WHERE "clientId"=?`, true, `["read"]`, app)
			docs.set(app, `{"client_id":"`+app+`","client_name":"Renamed","redirect_uris":["http://127.0.0.1:41234/cb"],"grant_types":["authorization_code","refresh_token"]}`)
			authorize(app)
			var name string
			var skip bool
			var ceiling []byte
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "name","skipConsent","clientCredentialsScopes" FROM "oauthClient" WHERE "clientId"=?`), app).Scan(&name, &skip, &ceiling))
			if name != "Renamed" || !skip || !strings.Contains(string(ceiling), "read") {
				t.Fatal("a refetch did not replace the document fields alone", name, skip, string(ceiling))
			}
			// A private_key_jwt client's keys on its own origin authenticate.
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			must(err)
			set, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, Algorithm: "EdDSA", Use: "sig", KeyID: "k"}}})
			must(err)
			const keyed = "https://keys.example.test/client.json"
			docs.set(keyed, `{"client_id":"`+keyed+`","grant_types":["client_credentials"],"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://keys.example.test/jwks"}`)
			docs.set("https://keys.example.test/jwks", string(set))
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, (&jose.SignerOptions{}).WithHeader("kid", "k"))
			must(err)
			claims, _ := json.Marshal(map[string]any{"iss": keyed, "sub": keyed, "aud": base + "/api/auth", "exp": time.Now().Unix() + 60, "jti": "cimd-1"})
			signed, err := signer.Sign(claims)
			must(err)
			assertion, _ := signed.CompactSerialize()
			if status, body := post("/oauth2/introspect", url.Values{"client_assertion": {assertion}, "client_assertion_type": {op.ClientAssertionType}, "token": {"unknown"}}); status != 200 || docs.count("https://keys.example.test/jwks") != 1 {
				t.Fatal("a document client's same-origin keys did not authenticate", status, body)
			}
			// A local https client is never fetched.
			write(`INSERT INTO "oauthClient" ("id","clientId","applicationType","redirectUris","scopes","tokenEndpointAuthMethod") VALUES ('local','https://local.example.test/app','native',?,?,'none')`,
				`["http://127.0.0.1:41234/cb"]`, `["read"]`)
			authorize("https://local.example.test/app")
			if docs.count("https://local.example.test/app") != 0 {
				t.Fatal("a local client's ID was fetched")
			}
			// A document for another URL is refused.
			const wrong = "https://wrong.example.test/client.json"
			docs.set(wrong, `{"client_id":"https://elsewhere.example.test/client.json","redirect_uris":["http://127.0.0.1:41234/cb"]}`)
			if code, got := authorize(wrong); code == 302 && got.Get("host") == "127.0.0.1:41234" || !strings.Contains(got.Get("body"), "does not match the metadata document URL") {
				t.Fatal("a mismatched document was accepted", code, got)
			}
			// The issuer advertises metadata documents.
			raw, _ := h.WellKnownJSON("/.well-known/oauth-authorization-server/api/auth")
			if !strings.Contains(string(raw), `"client_id_metadata_document_supported":true`) {
				t.Fatal("the issuer did not advertise metadata documents", string(raw))
			}
		})
	}
}
