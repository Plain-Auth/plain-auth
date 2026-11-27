package sqlstore

import (
	"context"
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

// Within RefreshReuseInterval of a rotation, the rotated refresh token
// presented again with the same scopes, resources and DPoP key gets the same
// response, ID token and host fields included, with expires_in counted from
// now; any other reuse is refused and keeps the family; after the interval,
// or without one, reuse ends the family, even with a failed DPoP proof or,
// for an offline family, scopes narrowed after its session ended.
func TestRefreshReuseInterval(t *testing.T) {
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
			secret := "replay-secret"
			secretDigest := sha256.Sum256([]byte(secret))
			write(`INSERT INTO "oauthClient" ("id","clientId","clientSecret","tokenEndpointAuthMethod","redirectUris","grantTypes") VALUES ('app','app',?,'client_secret_post','[]',?)`,
				base64.RawURLEncoding.EncodeToString(secretDigest[:]), `["authorization_code","refresh_token"]`)
			const origin = "https://issuer.example.test"
			host := func(interval time.Duration) *auth.Auth {
				t.Helper()
				p, err := op.New(op.Options{Scopes: []string{"openid", "reports", "offline_access"}, Tokens: op.TokenOptions{RefreshReuseInterval: interval,
					CustomTokenResponseFields: func(context.Context, op.TokenResponseInput) (map[string]any, error) {
						return map[string]any{"tenant": "acme"}, nil
					}}})
				must(err)
				signing, err := auth.NewJWT(auth.JWTOptions{})
				must(err)
				off := false
				h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("r", 40), Store: s, Plugins: []auth.Plugin{p, signing}, RateLimit: &off})
				must(err)
				return h
			}
			h := host(30 * time.Second)
			tokenURL := origin + "/api/auth/oauth2/token"
			verifier := strings.Repeat("v", 64)
			sum := sha256.Sum256([]byte(verifier))
			post := func(form url.Values, proof string) (int, map[string]any) {
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
				return out.Code, body
			}
			// grant redeems a fresh code and returns its refresh token.
			grant := func(proof string) string {
				t.Helper()
				raw := rand.Text()
				digest := sha256.Sum256([]byte(raw))
				value, err := json.Marshal(map[string]any{"type": "authorization_code", "userId": "owner", "sessionId": "sid", "authTime": now.UnixMilli(),
					"query": map[string]any{"client_id": "app", "scope": "openid reports offline_access", "code_challenge_method": "S256", "code_challenge": base64.RawURLEncoding.EncodeToString(sum[:])}})
				must(err)
				write(`INSERT INTO "verification" ("id","identifier","value","createdAt","updatedAt","expiresAt") VALUES (?,?,?,?,?,?)`,
					rand.Text(), base64.RawURLEncoding.EncodeToString(digest[:]), string(value), s.date(now), s.date(now), s.date(now.Add(time.Minute)))
				status, body := post(url.Values{"grant_type": {"authorization_code"}, "client_id": {"app"}, "client_secret": {secret}, "code": {raw}, "code_verifier": {verifier}}, proof)
				if status != 200 {
					t.Fatal("the code exchange failed", status, body)
				}
				return body["refresh_token"].(string)
			}
			refresh := func(token, scope, proof string) (int, map[string]any) {
				form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"app"}, "client_secret": {secret}, "refresh_token": {token}}
				if scope != "" {
					form.Set("scope", scope)
				}
				return post(form, proof)
			}
			parent := grant("")
			status, first := refresh(parent, "", "")
			if status != 200 || first["id_token"] == nil || first["tenant"] != "acme" {
				t.Fatal("the rotation failed", status, first)
			}
			// An identical retry gets the same response.
			status, again := refresh(parent, "", "")
			if status != 200 || again["access_token"] != first["access_token"] || again["refresh_token"] != first["refresh_token"] || again["id_token"] != first["id_token"] ||
				again["tenant"] != "acme" || again["expires_at"] != first["expires_at"] || again["expires_in"].(float64) > first["expires_in"].(float64) {
				t.Fatal("an identical retry did not get the same response", status, again, first)
			}
			// A different retry is refused and keeps the family.
			if status, body := refresh(parent, "reports offline_access", ""); status != 400 || body["error"] != "invalid_grant" {
				t.Fatal("a narrowed retry was replayed", status, body)
			}
			if status, body := refresh(first["refresh_token"].(string), "", ""); status != 200 {
				t.Fatal("a refused retry ended the family", status, body)
			}
			// After the interval, reuse ends the family.
			parent = grant("")
			status, first = refresh(parent, "", "")
			digest := sha256.Sum256([]byte(parent))
			write(`UPDATE "oauthRefreshToken" SET "rotationReplayExpiresAt"=? WHERE "token"=?`, s.date(now.Add(-time.Minute)), base64.RawURLEncoding.EncodeToString(digest[:]))
			if status, body := refresh(parent, "", ""); status != 400 || body["error"] != "invalid_grant" {
				t.Fatal("reuse after the interval was replayed", status, body)
			}
			if status, body := refresh(first["refresh_token"].(string), "", ""); status != 400 {
				t.Fatal("reuse after the interval kept the family", status, body)
			}
			// A DPoP family replays only for the same key.
			key, other := newDPoPKey(t), newDPoPKey(t)
			parent = grant(key.proof(t, tokenURL))
			status, first = refresh(parent, "", key.proof(t, tokenURL))
			if status != 200 || first["token_type"] != "DPoP" {
				t.Fatal("the bound rotation failed", status, first)
			}
			if status, body := refresh(parent, "", other.proof(t, tokenURL)); status != 400 || body["error"] != "invalid_dpop_proof" {
				t.Fatal("another key was replayed", status, body)
			}
			if status, body := refresh(parent, "", key.proof(t, tokenURL)); status != 200 || body["access_token"] != first["access_token"] {
				t.Fatal("the same key was not replayed", status, body)
			}
			// Without an interval, any reuse ends the family.
			h = host(0)
			parent = grant("")
			status, first = refresh(parent, "", "")
			if status, body := refresh(parent, "", ""); status != 400 || body["error"] != "invalid_grant" {
				t.Fatal("reuse without an interval was replayed", status, body)
			}
			if status, body := refresh(first["refresh_token"].(string), "", ""); status != 400 {
				t.Fatal("reuse without an interval kept the family", status, body)
			}
			// A failed DPoP proof on a live token is refused and keeps it.
			parent = grant("")
			if status, body := refresh(parent, "", "not-a-proof"); status != 400 || body["error"] != "invalid_dpop_proof" {
				t.Fatal("a failed proof was not refused", status, body)
			}
			if status, body := refresh(parent, "", ""); status != 200 {
				t.Fatal("a failed proof spent the refresh token", status, body)
			}
			// Reuse with a failed DPoP proof still ends the family.
			parent = grant(key.proof(t, tokenURL))
			status, first = refresh(parent, "", key.proof(t, tokenURL))
			if status != 200 {
				t.Fatal("the bound rotation failed", status, first)
			}
			if status, body := refresh(parent, "", "not-a-proof"); status != 400 || body["error"] != "invalid_grant" {
				t.Fatal("reuse with a failed proof was not refused as reuse", status, body)
			}
			if status, body := refresh(first["refresh_token"].(string), "", key.proof(t, tokenURL)); status != 400 || body["error"] != "invalid_grant" {
				t.Fatal("reuse with a failed proof kept the family", status, body)
			}
			// An unknown token answers invalid_grant whatever its proof.
			if status, body := refresh("unknown", "", "not-a-proof"); status != 400 || body["error"] != "invalid_grant" {
				t.Fatal("an unknown token with a failed proof was not invalid_grant", status, body)
			}
			// Reuse after the session ended, with scopes narrowed past
			// offline_access, still ends an offline family.
			parent = grant("")
			status, first = refresh(parent, "", "")
			if status != 200 {
				t.Fatal("the rotation failed", status, first)
			}
			write(`UPDATE "session" SET "expiresAt"=? WHERE "id"='sid'`, s.date(now.Add(-time.Minute)))
			if status, body := refresh(parent, "reports", ""); status != 400 || body["error"] != "invalid_grant" {
				t.Fatal("narrowed reuse after the session ended was not refused", status, body)
			}
			if status, body := refresh(first["refresh_token"].(string), "", ""); status != 400 {
				t.Fatal("narrowed reuse after the session ended kept the family", status, body)
			}
		})
	}
}
