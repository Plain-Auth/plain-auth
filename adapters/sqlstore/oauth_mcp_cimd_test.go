package sqlstore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/cimd"
	"github.com/Plain-Org/plain-auth/plugins/mcp"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// Metadata document clients under the MCP profile with the MCP provider:
// discovery advertises documents and no registration endpoint, a document
// without client_name or redirect_uris is refused, and a full one
// authorizes, consents and gets a token for the MCP resource that the
// route's guard accepts, on SQLite, PostgreSQL and MySQL.
func TestMCPMetadataDocumentClients(t *testing.T) {
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
			const resource = "https://mcp.example.test/mcp"
			const app = "https://agent.example.test/client.json"
			docs := &documents{bodies: map[string]string{}, fetched: map[string]int{}}
			docs.set(app, `{"client_id":"`+app+`","client_name":"Agent","redirect_uris":["http://127.0.0.1:41234/cb"]}`)
			docs.set("https://nameless.example.test/client.json", `{"client_id":"https://nameless.example.test/client.json","redirect_uris":["http://127.0.0.1:41234/cb"]}`)
			docs.set("https://nowhere.example.test/client.json", `{"client_id":"https://nowhere.example.test/client.json","client_name":"Nowhere"}`)
			discovery, err := cimd.NewClientDiscovery(cimd.Options{Transport: docs, Profile: cimd.ProfileMCP20260728})
			must(err)
			provider, err := mcp.New(mcp.Options{Resource: resource, Options: op.Options{Scopes: []string{"openid", "mcp:read"},
				Extensions:    []op.Extension{{ClientDiscoveries: []op.ClientDiscovery{discovery}}},
				Authorization: op.BrowserAuthorizationOptions{LoginPage: "/login", ConsentPage: "/consent"}}})
			must(err)
			signing, err := auth.NewJWT(auth.JWTOptions{})
			must(err)
			const origin = "https://mcp.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("m", 40), Plugins: []auth.Plugin{provider, signing}, Store: s, RateLimit: &off})
			must(err)
			raw, _ := h.WellKnownJSON("/.well-known/oauth-authorization-server/api/auth")
			if !strings.Contains(string(raw), `"client_id_metadata_document_supported":true`) || strings.Contains(string(raw), "registration_endpoint") {
				t.Fatal("discovery did not advertise metadata documents alone", string(raw))
			}
			verifier := strings.Repeat("v", 64)
			sum := sha256.Sum256([]byte(verifier))
			authorize := func(clientID string) (int, url.Values) {
				t.Helper()
				q := url.Values{"client_id": {clientID}, "response_type": {"code"}, "redirect_uri": {"http://127.0.0.1:41234/cb"}, "scope": {"mcp:read"}, "state": {"s"},
					"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "prompt": {"none"}, "resource": {resource}}
				req := httptest.NewRequest("GET", origin+"/api/auth/oauth2/authorize?"+q.Encode(), nil)
				req.AddCookie(h.SessionCookie("browser", true))
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				u, _ := url.Parse(out.Header().Get("Location"))
				values := u.Query()
				values.Set("body", out.Body.String())
				return out.Code, values
			}
			for clientID, want := range map[string]string{"https://nameless.example.test/client.json": "client_name must be a non-empty string",
				"https://nowhere.example.test/client.json": "redirect_uris must be a non-empty array"} {
				if _, got := authorize(clientID); got.Get("code") != "" || !strings.Contains(got.Get("body"), want) {
					t.Fatal("an incomplete MCP document was accepted", clientID, got)
				}
			}
			// A complete document is linked to the MCP resource and gets a token for it.
			if _, got := authorize(app); got.Get("error") != "consent_required" {
				t.Fatal("the document client was not resolved", got)
			}
			write(`INSERT INTO "oauthConsent" ("id","clientId","userId","scopes","resources","createdAt","updatedAt") VALUES ('approval',?,'owner',?,?,?,?)`, app, `["mcp:read"]`, `["`+resource+`"]`, s.date(now), s.date(now))
			_, got := authorize(app)
			form := url.Values{"grant_type": {"authorization_code"}, "client_id": {app}, "code": {got.Get("code")}, "code_verifier": {verifier}, "redirect_uri": {"http://127.0.0.1:41234/cb"}, "resource": {resource}}
			req := httptest.NewRequest("POST", origin+"/api/auth/oauth2/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			var token map[string]any
			must(json.Unmarshal(out.Body.Bytes(), &token))
			access, _ := token["access_token"].(string)
			if out.Code != 200 || strings.Count(access, ".") != 2 {
				t.Fatal("the code exchange failed", out.Code, token)
			}
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
			guard, err := mcp.RequireAuth(h, s, next, mcp.AuthOptions{Resource: resource})
			must(err)
			req = httptest.NewRequest("POST", resource, nil)
			req.Header.Set("Authorization", "Bearer "+access)
			out = httptest.NewRecorder()
			guard.ServeHTTP(out, req)
			if out.Code != 204 {
				t.Fatal("the guard refused a document client's token", out.Code, out.Header())
			}
		})
	}
}
