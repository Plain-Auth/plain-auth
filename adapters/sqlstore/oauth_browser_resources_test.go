package sqlstore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// Resource indicators at /oauth2/authorize: each must be configured,
// enabled and linked to the client, unless unlinked resources are allowed,
// and leave at least one requested scope; failures go to the callback with
// state and iss. Approved consent must cover every requested resource, an
// accepted consent records them, and the code value carries them once each.
func TestBrowserAuthorizationResources(t *testing.T) {
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
			write(`INSERT INTO "oauthClient" ("id","clientId","applicationType","redirectUris","scopes","tokenEndpointAuthMethod","skipConsent") VALUES ('app','app','native',?,?,'none',?)`, `["http://127.0.0.1:3000/cb"]`, `["reports","billing"]`, false)
			for _, r := range []struct {
				id      string
				allowed any
				linked  bool
			}{{"urn:reports", `["reports"]`, true}, {"urn:billing", `["billing"]`, true}, {"urn:audit", nil, true}, {"urn:off", nil, true}, {"urn:loose", nil, false}} {
				write(`INSERT INTO "oauthResource" ("id","identifier","name","allowedScopes") VALUES (?,?,?,?)`, r.id, r.id, r.id, r.allowed)
				if r.linked {
					write(`INSERT INTO "oauthClientResource" ("id","resourceId","clientId") VALUES (?,?,'app')`, "link-"+r.id, r.id)
				}
			}
			write(`UPDATE "oauthResource" SET "disabled"=? WHERE "identifier"='urn:off'`, true)
			write(`INSERT INTO "oauthConsent" ("id","clientId","userId","scopes","createdAt","updatedAt") VALUES ('approval','app','owner',?,?,?)`, `["reports"]`, s.date(now), s.date(now))
			const base = "https://issuer.example.test"
			verifier := strings.Repeat("v", 64)
			sum := sha256.Sum256([]byte(verifier))
			challenge := base64.RawURLEncoding.EncodeToString(sum[:])
			host := func(allowUnlinked bool) *auth.Auth {
				t.Helper()
				p, err := op.New(op.Options{Scopes: []string{"reports", "billing"}, Tokens: op.TokenOptions{AllowUnlinkedResources: allowUnlinked},
					Authorization: op.BrowserAuthorizationOptions{ConsentPage: "/consent"}})
				must(err)
				off := false
				h, err := auth.New(auth.Options{BaseURL: base, Secret: strings.Repeat("r", 40), Plugins: []auth.Plugin{p}, Store: s, RateLimit: &off})
				must(err)
				return h
			}
			h := host(false)
			authorize := func(prompt string, resources ...string) *url.URL {
				t.Helper()
				q := url.Values{"client_id": {"app"}, "response_type": {"code"}, "redirect_uri": {"http://127.0.0.1:41234/cb"}, "scope": {"reports"}, "state": {"saved"},
					"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": resources}
				if prompt != "" {
					q.Set("prompt", prompt)
				}
				req := httptest.NewRequest("GET", base+"/api/auth/oauth2/authorize?"+q.Encode(), nil)
				req.AddCookie(h.SessionCookie("browser", true))
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				u, err := url.Parse(out.Header().Get("Location"))
				must(err)
				if out.Code != 302 {
					t.Fatal("authorize did not redirect", out.Code, out.Body.String())
				}
				return u
			}
			refused := func(u *url.URL, code string) {
				t.Helper()
				if u.Host != "127.0.0.1:41234" || u.Query().Get("error") != code || u.Query().Get("state") != "saved" || u.Query().Get("iss") != base+"/api/auth" || u.Query().Has("code") {
					t.Fatal("wanted a callback refusal", code, u)
				}
			}
			refused(authorize("none", "urn:missing"), "invalid_target")
			refused(authorize("none", "urn:off"), "invalid_target")
			refused(authorize("none", "urn:loose"), "invalid_target")
			refused(authorize("none", "urn:billing"), "invalid_scope")
			// The consent covers the scope but not the resource.
			refused(authorize("none", "urn:reports"), "consent_required")
			// Allowing unlinked resources lets an unlinked one through.
			h = host(true)
			refused(authorize("none", "urn:loose"), "consent_required")
			h = host(false)
			// Covered consent issues a code whose value names each resource once.
			write(`UPDATE "oauthConsent" SET "resources"=? WHERE "id"='approval'`, `["urn:reports"]`)
			codeValue := func(u *url.URL) []string {
				t.Helper()
				if u.Query().Get("code") == "" {
					t.Fatal("no authorization code", u)
				}
				var raw string
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT "value" FROM "verification" WHERE "identifier"<>'oauth-browser-consent'`)).Scan(&raw))
				var value struct {
					Resource []string `json:"resource"`
				}
				must(json.Unmarshal([]byte(raw), &value))
				return value.Resource
			}
			if got := codeValue(authorize("none", "urn:reports", "urn:reports")); !slices.Equal(got, []string{"urn:reports"}) {
				t.Fatal("the code value did not carry the resource once", got)
			}
			// Without a covering consent the consent page opens, signed with
			// the resources, and accepting records them.
			write(`DELETE FROM "verification"`)
			page := authorize("", "urn:audit")
			if page.Path != "/consent" || !slices.Equal(page.Query()["resource"], []string{"urn:audit"}) {
				t.Fatal("the consent page did not carry the resource", page)
			}
			body, _ := json.Marshal(map[string]any{"accept": true, "oauth_query": page.RawQuery})
			req := httptest.NewRequest("POST", base+"/api/auth/oauth2/consent", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", base)
			req.AddCookie(h.SessionCookie("browser", true))
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			var accepted struct {
				URL string `json:"url"`
			}
			must(json.Unmarshal(out.Body.Bytes(), &accepted))
			done, err := url.Parse(accepted.URL)
			must(err)
			if got := codeValue(done); !slices.Equal(got, []string{"urn:audit"}) {
				t.Fatal("the consented code did not carry the resource", got, out.Body.String())
			}
			var resources string
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "resources" FROM "oauthConsent" WHERE "id"='approval'`)).Scan(&resources))
			if !sameJSON(resources, `["urn:audit"]`) {
				t.Fatal("accepted consent did not record the resources", resources)
			}
		})
	}
}
