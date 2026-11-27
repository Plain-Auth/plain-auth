package sqlstore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// Redeeming a resource-targeted code: the token's resources are the
// requested ones, which the code must have authorized, or the code's;
// each must still be configured, enabled and linked; allowed scopes narrow
// the grant and the resources' lifetimes cap the tokens; and a refused
// redemption leaves the code usable.
func TestAuthorizationCodeResources(t *testing.T) {
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
			secret := "code-resource-secret"
			secretDigest := sha256.Sum256([]byte(secret))
			write(`INSERT INTO "oauthClient" ("id","clientId","clientSecret","tokenEndpointAuthMethod","redirectUris","scopes","grantTypes") VALUES ('app','app',?,'client_secret_post','[]',?,?)`,
				base64.RawURLEncoding.EncodeToString(secretDigest[:]), `["openid","reports","billing","offline_access"]`, `["authorization_code","refresh_token"]`)
			for _, r := range []struct {
				id              string
				allowed         any
				access, refresh any
				linked          bool
			}{{"urn:reports", `["openid","reports","offline_access"]`, 120, 600, true}, {"urn:audit", nil, nil, nil, true}, {"urn:loose", nil, nil, nil, false}} {
				write(`INSERT INTO "oauthResource" ("id","identifier","name","allowedScopes","accessTokenTtl","refreshTokenTtl") VALUES (?,?,?,?,?,?)`, r.id, r.id, r.id, r.allowed, r.access, r.refresh)
				if r.linked {
					write(`INSERT INTO "oauthClientResource" ("id","resourceId","clientId") VALUES (?,?,'app')`, "link-"+r.id, r.id)
				}
			}
			const origin = "https://issuer.example.test"
			p, err := op.New(op.Options{Scopes: []string{"openid", "reports", "billing", "offline_access"}})
			must(err)
			signing, err := auth.NewJWT(auth.JWTOptions{})
			must(err)
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("c", 40), Store: s, Plugins: []auth.Plugin{p, signing}, RateLimit: &off})
			must(err)
			userInfo := origin + "/api/auth/oauth2/userinfo"
			verifier := strings.Repeat("v", 64)
			sum := sha256.Sum256([]byte(verifier))
			code := func(scope string, value map[string]any) string {
				t.Helper()
				raw := rand.Text()
				digest := sha256.Sum256([]byte(raw))
				query := map[string]any{"client_id": "app", "scope": scope, "code_challenge_method": "S256", "code_challenge": base64.RawURLEncoding.EncodeToString(sum[:])}
				if legacy, ok := value["legacy"]; ok {
					query["resource"] = legacy
					delete(value, "legacy")
				}
				value["type"], value["userId"], value["sessionId"], value["authTime"], value["query"] = "authorization_code", "owner", "sid", now.UnixMilli(), query
				encoded, err := json.Marshal(value)
				must(err)
				write(`INSERT INTO "verification" ("id","identifier","value","createdAt","updatedAt","expiresAt") VALUES (?,?,?,?,?,?)`,
					rand.Text(), base64.RawURLEncoding.EncodeToString(digest[:]), string(encoded), s.date(now), s.date(now), s.date(now.Add(time.Minute)))
				return raw
			}
			exchange := func(raw string, resources ...string) (int, map[string]any) {
				t.Helper()
				form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"app"}, "client_secret": {secret}, "code": {raw}, "code_verifier": {verifier}, "resource": resources}
				req := httptest.NewRequest("POST", origin+"/api/auth/oauth2/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				var body map[string]any
				must(json.Unmarshal(out.Body.Bytes(), &body))
				return out.Code, body
			}
			stored := func(table, column, token string) string {
				t.Helper()
				digest := sha256.Sum256([]byte(token))
				var v *string
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT "`+column+`" FROM "`+table+`" WHERE "token"=?`), base64.RawURLEncoding.EncodeToString(digest[:])).Scan(&v))
				if v == nil {
					return ""
				}
				return *v
			}
			// Allowed scopes narrow the grant and the resource's lifetimes cap
			// both tokens, which carry the resource.
			status, body := exchange(code("openid reports billing offline_access", map[string]any{"resource": []string{"urn:reports"}}))
			if status != 200 || body["scope"] != "openid reports offline_access" || body["expires_in"] != float64(120) || body["refresh_token"] == nil || body["id_token"] == nil {
				t.Fatal("the resource policy was not applied", status, body)
			}
			access, refresh := body["access_token"].(string), body["refresh_token"].(string)
			if !sameJSON(stored("oauthAccessToken", "resources", access), `["urn:reports"]`) || !sameJSON(stored("oauthRefreshToken", "resources", refresh), `["urn:reports"]`) {
				t.Fatal("the tokens did not carry the resource")
			}
			var refreshExpires time.Time
			digest := sha256.Sum256([]byte(refresh))
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "expiresAt" FROM "oauthRefreshToken" WHERE "token"=?`), base64.RawURLEncoding.EncodeToString(digest[:])).Scan(&refreshExpires))
			if d := refreshExpires.Sub(now); d < 590*time.Second || d > 610*time.Second {
				t.Fatal("the refresh lifetime was not capped by the resource", d)
			}
			// Introspection names the resource and, for openid, UserInfo.
			form := url.Values{"token": {access}, "client_id": {"app"}, "client_secret": {secret}}
			req := httptest.NewRequest("POST", origin+"/api/auth/oauth2/introspect", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			var introspected struct {
				Active bool `json:"active"`
				Aud    any  `json:"aud"`
			}
			must(json.Unmarshal(out.Body.Bytes(), &introspected))
			audiences, _ := introspected.Aud.([]any)
			if !introspected.Active || len(audiences) != 2 || audiences[0] != "urn:reports" || audiences[1] != userInfo {
				t.Fatal("introspection did not name the resource and UserInfo", out.Body.String())
			}
			// A requested subset becomes the token's resources; the refresh
			// token keeps those the code authorized.
			status, body = exchange(code("reports offline_access", map[string]any{"resource": []string{"urn:reports", "urn:audit"}}), "urn:audit")
			if status != 200 || !sameJSON(stored("oauthAccessToken", "resources", body["access_token"].(string)), `["urn:audit"]`) ||
				!sameJSON(stored("oauthRefreshToken", "resources", body["refresh_token"].(string)), `["urn:reports","urn:audit"]`) {
				t.Fatal("a requested subset was not applied", status, body)
			}
			// A resource the code did not authorize, a disabled or an unlinked
			// one is refused, and the code stays usable.
			refused := func(raw string, resources ...string) {
				t.Helper()
				if status, body := exchange(raw, resources...); status != 400 || body["error"] != "invalid_target" {
					t.Fatal("a resource was not refused", resources, status, body)
				}
			}
			raw := code("reports", map[string]any{"resource": []string{"urn:reports"}})
			refused(raw, "urn:audit")
			if status, body := exchange(raw); status != 200 {
				t.Fatal("a refused redemption spent the code", status, body)
			}
			raw = code("reports", map[string]any{"resource": []string{"urn:audit"}})
			write(`UPDATE "oauthResource" SET "disabled"=? WHERE "identifier"='urn:audit'`, true)
			refused(raw)
			write(`UPDATE "oauthResource" SET "disabled"=? WHERE "identifier"='urn:audit'`, false)
			if status, body := exchange(raw); status != 200 {
				t.Fatal("the code was spent by a refused redemption", status, body)
			}
			refused(code("reports", map[string]any{"resource": []string{"urn:loose"}}))
			// A code without resources may name any linked resource, and a
			// legacy query.resource is read.
			if status, body := exchange(code("reports", map[string]any{"resource": []string{}}), "urn:audit"); status != 200 ||
				!sameJSON(stored("oauthAccessToken", "resources", body["access_token"].(string)), `["urn:audit"]`) {
				t.Fatal("a code without resources could not name one", status, body)
			}
			if status, body := exchange(code("reports", map[string]any{"legacy": "urn:audit"})); status != 200 ||
				!sameJSON(stored("oauthAccessToken", "resources", body["access_token"].(string)), `["urn:audit"]`) {
				t.Fatal("a legacy query.resource was not read", status, body)
			}
		})
	}
}
