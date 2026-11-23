package sqlstore

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/schema"
	"golang.org/x/oauth2"
)

func TestOpenIDGrantRetry(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) { testOpenIDGrantRetry(t, dialect) })
	}
}

func testOpenIDGrantRetry(t *testing.T, dialect string) {
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
	write := func(query string, args ...any) {
		t.Helper()
		_, err := s.db.ExecContext(ctx, s.bind(query), args...)
		must(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	start := now.Add(-3 * time.Hour)
	write(`INSERT INTO "user" ("id","email","name","emailVerified","createdAt","updatedAt") VALUES ('person','user@example.test','User',?,?,?)`, true, s.date(start), s.date(start))
	write(`INSERT INTO "session" ("id","token","userId","createdAt","updatedAt","expiresAt") VALUES ('sid','browser','person',?,?,?)`, s.date(start), s.date(start), s.date(now.Add(time.Hour)))
	write(`INSERT INTO "oauthClient" ("id","clientId","tokenEndpointAuthMethod","redirectUris","scopes","enableEndSession") VALUES ('app','app','none',?,?,?)`, `["https://reader.example.test/return"]`, `["openid","offline_access"]`, true)
	verifier := oauth2.GenerateVerifier()
	seed := func(code, scopes, claims string) {
		t.Helper()
		query := map[string]string{"client_id": "app", "scope": scopes, "code_challenge": oauth2.S256ChallengeFromVerifier(verifier), "code_challenge_method": "S256", "nonce": "first-nonce"}
		if claims != "" {
			query["claims"] = claims
		}
		b, err := json.Marshal(map[string]any{"type": "authorization_code", "userId": "person", "sessionId": "sid", "query": query})
		must(err)
		write(`INSERT INTO "verification" ("id","identifier","value","createdAt","updatedAt","expiresAt") VALUES (?,?,?,?,?,?)`, rand.Text(), oauth2.S256ChallengeFromVerifier(code), string(b), s.date(now), s.date(now), s.date(now.Add(time.Hour)))
	}
	var beforeRotation func()
	issuer, err := op.New(op.Options{Scopes: []string{"openid", "offline_access"}, Tokens: op.TokenOptions{GenerateRefreshToken: func(context.Context) (string, error) {
		if beforeRotation != nil {
			beforeRotation()
		}
		return rand.Text(), nil
	}}})
	must(err)
	jwt, err := auth.NewJWT(auth.JWTOptions{})
	must(err)
	host := func(plugins ...auth.Plugin) *auth.Auth {
		h, err := auth.New(auth.Options{Store: s, Secret: strings.Repeat("s", 40), BaseURL: "https://issuer.example.test", Plugins: plugins, RateLimit: new(bool)})
		must(err)
		return h
	}
	h := host(issuer, jwt)
	exchange := func(server *auth.Auth, grant, credential string, status int, problem string) op.DelegatedToken {
		t.Helper()
		form := url.Values{"client_id": {"app"}, "grant_type": {grant}}
		if grant == "authorization_code" {
			form.Set("code", credential)
			form.Set("code_verifier", verifier)
		} else {
			form.Set("refresh_token", credential)
		}
		req := httptest.NewRequest("POST", server.OAuthIssuer()+"/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		out := httptest.NewRecorder()
		server.ServeHTTP(out, req)
		var body struct {
			op.DelegatedToken
			Error string
		}
		must(json.Unmarshal(out.Body.Bytes(), &body))
		if out.Code != status || problem != "" && body.Error != problem {
			t.Fatalf("expected HTTP %d %s, got %d %s", status, problem, out.Code, body.Error)
		}
		if status != 200 && (body.AccessToken != "" || body.RefreshToken != "" || body.IDToken != "") {
			t.Fatal("unsuccessful exchange disclosed a token")
		}
		return body.DelegatedToken
	}
	keys, err := h.PublicJWKS(ctx)
	must(err)
	keyID := keys.Keys[0].KeyID
	var private string
	must(s.db.QueryRowContext(ctx, s.bind(`SELECT "privateKey" FROM "jwks" WHERE "id"=?`), keyID).Scan(&private))
	setKey := func(value string) { write(`UPDATE "jwks" SET "privateKey"=? WHERE "id"=?`, value, keyID) }
	verify := func(tokens op.DelegatedToken, nonce, sid any) {
		t.Helper()
		claims, err := h.VerifyJWT(ctx, tokens.IDToken, auth.JWTVerifyOptions{Issuer: h.OAuthIssuer(), Audience: "app", Subject: "person"})
		must(err)
		if claims["auth_time"] != float64(start.Unix()) || claims["nonce"] != nonce || claims["sid"] != sid || tokens.AccessToken == "" {
			t.Fatal("wrong session or original authentication time on ID token", claims)
		}
	}
	seed("impossible", "openid", `{"id_token":{"acr":{"essential":true,"value":"2"}}}`)
	exchange(h, "authorization_code", "impossible", 400, "invalid_grant")
	seed("single", "openid", "")
	exchange(host(issuer), "authorization_code", "single", 501, "server_error")
	setKey(`"unavailable"`)
	exchange(h, "authorization_code", "single", 500, "")
	setKey(private)
	verify(exchange(h, "authorization_code", "single", 200, ""), "first-nonce", "sid")

	// A change to the client's logout policy invalidates the prepared ID token.
	seed("offline", "openid offline_access", "")
	beforeRotation = func() { write(`UPDATE "oauthClient" SET "enableEndSession"=? WHERE "id"='app'`, false) }
	exchange(h, "authorization_code", "offline", 400, "invalid_grant")
	beforeRotation = nil
	write(`UPDATE "oauthClient" SET "enableEndSession"=? WHERE "id"='app'`, true)
	parent := exchange(h, "authorization_code", "offline", 200, "")
	verify(parent, "first-nonce", "sid")
	setKey(`"unavailable"`)
	exchange(h, "refresh_token", parent.RefreshToken, 500, "")
	setKey(private)
	// Expiry during signing must never publish an ID token tied to the old session.
	beforeRotation = func() { write(`UPDATE "session" SET "expiresAt"=? WHERE "id"='sid'`, s.date(now.Add(-time.Minute))) }
	exchange(h, "refresh_token", parent.RefreshToken, 400, "invalid_grant")
	beforeRotation = nil
	verify(exchange(h, "refresh_token", parent.RefreshToken, 200, ""), nil, nil)
	for _, table := range []string{"oauthAccessToken", "oauthRefreshToken"} {
		var count int
		must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "`+table+`" WHERE "authorizationCodeId"=?`), oauth2.S256ChallengeFromVerifier("offline")).Scan(&count))
		if count != 2 {
			t.Fatalf("%s has %d records for two successful exchanges", table, count)
		}
	}
}
