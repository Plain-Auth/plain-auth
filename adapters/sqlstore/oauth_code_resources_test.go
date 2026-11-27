package sqlstore

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"net/http"
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
// redemption leaves the code usable. Refresh exchanges keep the family's
// resources and apply the same policy, from rotation.
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
			}{{"urn:reports", `["openid","reports","offline_access"]`, 120, 600, true}, {"urn:audit", nil, nil, nil, true}, {"urn:loose", nil, nil, nil, false}, {"urn:narrow", `["reports"]`, nil, nil, true}} {
				write(`INSERT INTO "oauthResource" ("id","identifier","name","allowedScopes","accessTokenTtl","refreshTokenTtl") VALUES (?,?,?,?,?,?)`, r.id, r.id, r.id, r.allowed, r.access, r.refresh)
				if r.linked {
					write(`INSERT INTO "oauthClientResource" ("id","resourceId","clientId") VALUES (?,?,'app')`, "link-"+r.id, r.id)
				}
			}
			const origin = "https://issuer.example.test"
			// The opaque tokens show the stored resources; signed ones follow.
			newHost := func(opaque bool, allowUnlinked ...bool) *auth.Auth {
				t.Helper()
				p, err := op.New(op.Options{Scopes: []string{"openid", "reports", "billing", "offline_access"}, Tokens: op.TokenOptions{OpaqueResourceTokens: opaque, AllowUnlinkedResources: len(allowUnlinked) > 0}})
				must(err)
				signing, err := auth.NewJWT(auth.JWTOptions{})
				must(err)
				off := false
				h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("c", 40), Store: s, Plugins: []auth.Plugin{p, signing}, RateLimit: &off})
				must(err)
				return h
			}
			h := newHost(true)
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
			family := body["refresh_token"].(string)
			// A refresh exchange keeps the family's resources and policy.
			rotate := func(token string, resources ...string) (int, map[string]any) {
				t.Helper()
				form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"app"}, "client_secret": {secret}, "refresh_token": {token}, "resource": resources}
				req := httptest.NewRequest("POST", origin+"/api/auth/oauth2/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				var reply map[string]any
				must(json.Unmarshal(out.Body.Bytes(), &reply))
				return out.Code, reply
			}
			status, body = rotate(refresh)
			if status != 200 || body["scope"] != "openid reports offline_access" || body["expires_in"] != float64(120) ||
				!sameJSON(stored("oauthAccessToken", "resources", body["access_token"].(string)), `["urn:reports"]`) ||
				!sameJSON(stored("oauthRefreshToken", "resources", body["refresh_token"].(string)), `["urn:reports"]`) {
				t.Fatal("a refresh did not keep the family's resources and policy", status, body)
			}
			digest = sha256.Sum256([]byte(body["refresh_token"].(string)))
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "expiresAt" FROM "oauthRefreshToken" WHERE "token"=?`), base64.RawURLEncoding.EncodeToString(digest[:])).Scan(&refreshExpires))
			if d := time.Until(refreshExpires); d < 580*time.Second || d > 610*time.Second {
				t.Fatal("the rotated refresh token was not capped by the resource from rotation", d)
			}
			// A resource outside the family is refused and the parent stays usable.
			if status, reply := rotate(family, "urn:loose"); status != 400 || reply["error"] != "invalid_target" || reply["error_description"] != "requested resource invalid" {
				t.Fatal("a resource outside the family was accepted", status, reply)
			}
			// A requested subset narrows the access token; the rotated token
			// keeps the family, and a resource without a lifetime gives the
			// default one.
			status, body = rotate(family, "urn:audit")
			if status != 200 || body["expires_in"] != float64(3600) || !sameJSON(stored("oauthAccessToken", "resources", body["access_token"].(string)), `["urn:audit"]`) ||
				!sameJSON(stored("oauthRefreshToken", "resources", body["refresh_token"].(string)), `["urn:reports","urn:audit"]`) {
				t.Fatal("a refresh subset was not applied", status, body)
			}
			family = body["refresh_token"].(string)
			// A disabled resource refuses the refresh and keeps the parent.
			write(`UPDATE "oauthResource" SET "disabled"=? WHERE "identifier"='urn:reports'`, true)
			if status, reply := rotate(family); status != 400 || reply["error"] != "invalid_target" {
				t.Fatal("a disabled resource did not refuse the refresh", status, reply)
			}
			write(`UPDATE "oauthResource" SET "disabled"=? WHERE "identifier"='urn:reports'`, false)
			// An unlinked family resource refuses the refresh too.
			write(`DELETE FROM "oauthClientResource" WHERE "id"='link-urn:audit'`)
			if status, reply := rotate(family); status != 400 || reply["error"] != "invalid_target" || !strings.Contains(reply["error_description"].(string), "not linked") {
				t.Fatal("an unlinked family resource did not refuse the refresh", status, reply)
			}
			write(`INSERT INTO "oauthClientResource" ("id","resourceId","clientId") VALUES ('link-urn:audit','urn:audit','app')`)
			status, body = rotate(family)
			if status != 200 {
				t.Fatal("a refused refresh spent the parent", status, body)
			}
			// Reuse of the rotated parent ends the family even when the
			// resources' policy would refuse it.
			write(`UPDATE "oauthResource" SET "disabled"=? WHERE "identifier"='urn:audit'`, true)
			if status, reply := rotate(family); status != 400 || reply["error"] != "invalid_grant" {
				t.Fatal("reuse under a refusing policy was not treated as reuse", status, reply)
			}
			write(`UPDATE "oauthResource" SET "disabled"=? WHERE "identifier"='urn:audit'`, false)
			if status, reply := rotate(body["refresh_token"].(string)); status != 400 {
				t.Fatal("reuse did not end the family", status, reply)
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
			// With the jwt plugin and no OpaqueResourceTokens, the access
			// token is an at+jwt for the resources and UserInfo, not stored,
			// whose hash the ID token carries; UserInfo and introspection
			// accept it, also after its refresh token is revoked.
			h = newHost(false)
			status, body = exchange(code("openid reports offline_access", map[string]any{"resource": []string{"urn:reports"}}))
			if status != 200 {
				t.Fatal("the signed exchange failed", status, body)
			}
			jwtAccess := body["access_token"].(string)
			claims, err := h.VerifyJWT(ctx, jwtAccess, auth.JWTVerifyOptions{Issuer: h.OAuthIssuer(), Audience: "urn:reports", Subject: "owner"})
			must(err)
			header, err := base64.RawURLEncoding.DecodeString(strings.Split(jwtAccess, ".")[0])
			must(err)
			aud, _ := claims["aud"].([]any)
			if !strings.Contains(string(header), `"typ":"at+jwt"`) || len(aud) != 2 || aud[0] != "urn:reports" || aud[1] != userInfo || claims["client_id"] != "app" ||
				claims["azp"] != "app" || claims["scope"] != "openid reports offline_access" || claims["sid"] != "sid" || claims["jti"] == nil || body["expires_in"] != float64(120) {
				t.Fatal("the signed access token had the wrong claims", string(header), claims, body)
			}
			var signedRows int
			jwtDigest := sha256.Sum256([]byte(jwtAccess))
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "oauthAccessToken" WHERE "token"=?`), base64.RawURLEncoding.EncodeToString(jwtDigest[:])).Scan(&signedRows))
			if signedRows != 0 {
				t.Fatal("a signed access token was stored")
			}
			idParts := strings.Split(body["id_token"].(string), ".")
			idPayload, err := base64.RawURLEncoding.DecodeString(idParts[1])
			must(err)
			idHeader, err := base64.RawURLEncoding.DecodeString(idParts[0])
			must(err)
			var idClaims map[string]any
			must(json.Unmarshal(idPayload, &idClaims))
			var atHash []byte
			if strings.Contains(string(idHeader), `"EdDSA"`) || strings.Contains(string(idHeader), `"ES512"`) {
				sum := sha512.Sum512([]byte(jwtAccess))
				atHash = sum[:32]
			} else {
				sum := sha256.Sum256([]byte(jwtAccess))
				atHash = sum[:16]
			}
			if idClaims["at_hash"] != base64.RawURLEncoding.EncodeToString(atHash) {
				t.Fatal("the ID token's at_hash did not cover the signed access token", idClaims["at_hash"])
			}
			call := func(req *http.Request) (int, map[string]any) {
				t.Helper()
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				var reply map[string]any
				_ = json.Unmarshal(out.Body.Bytes(), &reply)
				return out.Code, reply
			}
			profileReq := httptest.NewRequest("GET", origin+"/api/auth/oauth2/userinfo", nil)
			profileReq.Header.Set("Authorization", "Bearer "+jwtAccess)
			if status, profile := call(profileReq); status != 200 || profile["sub"] != "owner" {
				t.Fatal("UserInfo refused the signed access token", status, profile)
			}
			introspect := func(token string) bool {
				t.Helper()
				form := url.Values{"token": {token}, "client_id": {"app"}, "client_secret": {secret}}
				req := httptest.NewRequest("POST", origin+"/api/auth/oauth2/introspect", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				_, reply := call(req)
				return reply["active"] == true
			}
			status, body = rotate(body["refresh_token"].(string))
			if status != 200 || len(strings.Split(body["access_token"].(string), ".")) != 3 || !introspect(body["access_token"].(string)) {
				t.Fatal("a signed refresh did not give an active at+jwt", status, body)
			}
			revokeForm := url.Values{"token": {body["refresh_token"].(string)}, "client_id": {"app"}, "client_secret": {secret}}
			revokeReq := httptest.NewRequest("POST", origin+"/api/auth/oauth2/revoke", strings.NewReader(revokeForm.Encode()))
			revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if status, reply := call(revokeReq); status != 200 || !introspect(body["access_token"].(string)) {
				t.Fatal("revoking the refresh token deactivated its signed access token", status, reply)
			}
			h = newHost(true)
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
			// AllowUnlinkedResources admits an unlinked resource at the code
			// exchange and at refresh.
			h = newHost(true, true)
			status, body = exchange(code("reports offline_access", map[string]any{"resource": []string{"urn:loose"}}))
			if status != 200 {
				t.Fatal("an allowed unlinked resource was refused at the exchange", status, body)
			}
			if status, reply := rotate(body["refresh_token"].(string)); status != 200 {
				t.Fatal("an allowed unlinked resource was refused at refresh", status, reply)
			}
			// A resource that narrows away offline_access still gets the code a
			// refresh token, bound to the session, as in another runtime.
			h = newHost(true)
			status, body = exchange(code("reports offline_access", map[string]any{"resource": []string{"urn:narrow"}}))
			if status != 200 || body["scope"] != "reports" || body["refresh_token"] == nil || !sameJSON(stored("oauthRefreshToken", "scopes", body["refresh_token"].(string)), `["reports"]`) {
				t.Fatal("a narrowing resource dropped the refresh token", status, body)
			}
			bound := body["refresh_token"].(string)
			if status, reply := rotate(bound); status != 200 || reply["refresh_token"] != nil {
				t.Fatal("a session-bound refresh token did not refresh without rotating", status, reply)
			}
			write(`DELETE FROM "session" WHERE "id"='sid'`)
			if status, reply := rotate(bound); status != 400 || reply["error"] != "invalid_grant" {
				t.Fatal("a session-bound refresh token outlived its session", status, reply)
			}
		})
	}
}
