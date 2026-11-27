package sqlstore

import (
	"crypto"
	"crypto/ed25519"
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
	jose "github.com/go-jose/go-jose/v4"
)

// dpopKey signs DPoP proofs with one key.
type dpopKey struct {
	thumb  string
	signer jose.Signer
}

func newDPoPKey(t *testing.T) dpopKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := (&jose.JSONWebKey{Key: key}).Public()
	fingerprint, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, new(jose.SignerOptions).WithType("dpop+jwt").WithHeader("jwk", public))
	if err != nil {
		t.Fatal(err)
	}
	return dpopKey{thumb: base64.RawURLEncoding.EncodeToString(fingerprint), signer: signer}
}

func (k dpopKey) proof(t *testing.T, target string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"iat": time.Now().Unix(), "jti": rand.Text(), "htm": "POST", "htu": target})
	signed, err := k.signer.Sign(body)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// DPoP-bound delegated grants: a code with dpop_jkt, a client that requires
// DPoP or a resource that requires it needs a proof at the exchange; the
// proof's key must match the code's or the refresh family's; both tokens
// are bound to it; and a refused exchange leaves the code or parent usable.
func TestDPoPBoundDelegatedGrants(t *testing.T) {
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
			secret := "dpop-grant-secret"
			secretDigest := sha256.Sum256([]byte(secret))
			for _, id := range []string{"app", "strict"} {
				write(`INSERT INTO "oauthClient" ("id","clientId","clientSecret","tokenEndpointAuthMethod","redirectUris","grantTypes","dpopBoundAccessTokens") VALUES (?,?,?,'client_secret_post','[]',?,?)`,
					id, id, base64.RawURLEncoding.EncodeToString(secretDigest[:]), `["authorization_code","refresh_token"]`, id == "strict")
			}
			write(`INSERT INTO "oauthResource" ("id","identifier","name","dpopBoundAccessTokensRequired") VALUES ('bound','urn:bound','Bound',?)`, true)
			write(`INSERT INTO "oauthClientResource" ("id","resourceId","clientId") VALUES ('link','urn:bound','app')`)
			const origin = "https://issuer.example.test"
			p, err := op.New(op.Options{Scopes: []string{"reports", "offline_access"}})
			must(err)
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("d", 40), Store: s, Plugins: []auth.Plugin{p}, RateLimit: &off})
			must(err)
			tokenURL := origin + "/api/auth/oauth2/token"
			key, other := newDPoPKey(t), newDPoPKey(t)
			verifier := strings.Repeat("v", 64)
			sum := sha256.Sum256([]byte(verifier))
			challenge := base64.RawURLEncoding.EncodeToString(sum[:])
			code := func(client string, query map[string]any, value map[string]any) string {
				t.Helper()
				raw := rand.Text()
				digest := sha256.Sum256([]byte(raw))
				q := map[string]any{"client_id": client, "scope": "reports offline_access", "code_challenge_method": "S256", "code_challenge": challenge}
				for k, v := range query {
					q[k] = v
				}
				if value == nil {
					value = map[string]any{}
				}
				value["type"], value["userId"], value["sessionId"], value["authTime"], value["query"] = "authorization_code", "owner", "sid", now.UnixMilli(), q
				encoded, err := json.Marshal(value)
				must(err)
				write(`INSERT INTO "verification" ("id","identifier","value","createdAt","updatedAt","expiresAt") VALUES (?,?,?,?,?,?)`,
					rand.Text(), base64.RawURLEncoding.EncodeToString(digest[:]), string(encoded), s.date(now), s.date(now), s.date(now.Add(time.Minute)))
				return raw
			}
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
			exchange := func(client, raw, proof string, resources ...string) (int, map[string]any) {
				return post(url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "client_secret": {secret}, "code": {raw}, "code_verifier": {verifier}, "resource": resources}, proof)
			}
			refresh := func(client, token, proof string) (int, map[string]any) {
				return post(url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "client_secret": {secret}, "refresh_token": {token}}, proof)
			}
			refused := func(status int, body map[string]any, description string) {
				t.Helper()
				if status != 400 || body["error"] != "invalid_dpop_proof" || body["error_description"] != description {
					t.Fatal("wanted a DPoP refusal", description, status, body)
				}
			}
			confirmation := func(table, token string) string {
				t.Helper()
				digest := sha256.Sum256([]byte(token))
				var v *string
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT "confirmation" FROM "`+table+`" WHERE "token"=?`), base64.RawURLEncoding.EncodeToString(digest[:])).Scan(&v))
				if v == nil {
					return ""
				}
				return *v
			}
			bound := `{"jkt":"` + key.thumb + `"}`
			// A code bound with dpop_jkt needs a proof by that key; a refused
			// exchange keeps the code.
			raw := code("app", map[string]any{"dpop_jkt": key.thumb}, nil)
			status, body := exchange("app", raw, "")
			refused(status, body, "DPoP proof header is required")
			status, body = exchange("app", raw, other.proof(t, tokenURL))
			refused(status, body, "DPoP proof key does not match the bound token")
			status, body = exchange("app", raw, key.proof(t, tokenURL))
			if status != 200 || body["token_type"] != "DPoP" || !sameJSON(confirmation("oauthAccessToken", body["access_token"].(string)), bound) ||
				!sameJSON(confirmation("oauthRefreshToken", body["refresh_token"].(string)), bound) {
				t.Fatal("the bound exchange did not bind both tokens", status, body)
			}
			// Introspection names the key.
			form := url.Values{"token": {body["access_token"].(string)}, "client_id": {"app"}, "client_secret": {secret}}
			req := httptest.NewRequest("POST", origin+"/api/auth/oauth2/introspect", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			var introspected struct {
				TokenType string            `json:"token_type"`
				Cnf       map[string]string `json:"cnf"`
			}
			must(json.Unmarshal(out.Body.Bytes(), &introspected))
			if introspected.TokenType != "DPoP" || introspected.Cnf["jkt"] != key.thumb {
				t.Fatal("introspection did not name the DPoP key", out.Body.String())
			}
			// A refresh needs the family's key, and the rotated token keeps it.
			family := body["refresh_token"].(string)
			status, body = refresh("app", family, "")
			refused(status, body, "DPoP proof header is required")
			status, body = refresh("app", family, other.proof(t, tokenURL))
			refused(status, body, "DPoP proof key does not match the bound token")
			status, body = refresh("app", family, key.proof(t, tokenURL))
			if status != 200 || body["token_type"] != "DPoP" || !sameJSON(confirmation("oauthRefreshToken", body["refresh_token"].(string)), bound) {
				t.Fatal("a bound refresh did not keep the family's key", status, body)
			}
			// A client that requires DPoP binds without dpop_jkt.
			raw = code("strict", nil, nil)
			status, body = exchange("strict", raw, "")
			refused(status, body, "DPoP proof header is required")
			if status, body := exchange("strict", raw, other.proof(t, tokenURL)); status != 200 || body["token_type"] != "DPoP" {
				t.Fatal("a DPoP-required client did not bind", status, body)
			}
			// A resource that requires DPoP forces a proof.
			raw = code("app", nil, map[string]any{"resource": []string{"urn:bound"}})
			status, body = exchange("app", raw, "")
			refused(status, body, "DPoP proof header is required")
			if status, body := exchange("app", raw, key.proof(t, tokenURL)); status != 200 || body["token_type"] != "DPoP" {
				t.Fatal("a DPoP-required resource did not bind", status, body)
			}
			// A refused resource is the answer before a failed proof.
			raw = code("app", nil, map[string]any{"resource": []string{"urn:bound"}})
			status, body = exchange("app", raw, key.proof(t, tokenURL))
			if status != 200 {
				t.Fatal("the bound resource exchange failed", status, body)
			}
			write(`UPDATE "oauthResource" SET "disabled"=? WHERE "identifier"='urn:bound'`, true)
			if status, body := refresh("app", body["refresh_token"].(string), "not-a-proof"); status != 400 || body["error"] != "invalid_target" {
				t.Fatal("a disabled resource was not refused before the proof", status, body)
			}
			write(`UPDATE "oauthResource" SET "disabled"=? WHERE "identifier"='urn:bound'`, false)
			// An unbound exchange gets Bearer tokens.
			if status, body := exchange("app", code("app", nil, nil), ""); status != 200 || body["token_type"] != "Bearer" || confirmation("oauthAccessToken", body["access_token"].(string)) != "" {
				t.Fatal("an unbound exchange was bound", status, body)
			}
		})
	}
}
