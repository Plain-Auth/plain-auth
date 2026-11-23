package sqlstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
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
	fields := map[string]auth.UserField{
		"tier":        {Type: auth.FieldString, Column: "plan_tier"},
		"allowClaims": {Type: auth.FieldBoolean, Column: "claims_allowed", ServerOnly: true, Hidden: true},
	}
	s, err := OpenWithAdditionalFields(ctx, dialect, organizationTestDSN(t, dialect), []string{"oauth-provider", "jwt", "admin"}, schema.AdditionalFields{User: fields})
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
	var warnings bytes.Buffer
	privatePolicy := errors.New("private membership policy")
	var observedPolicy bool
	host := func(plugins ...auth.Plugin) *auth.Auth {
		h, err := auth.New(auth.Options{Store: s, Logger: slog.New(slog.NewTextHandler(&warnings, nil)),
			OnAPIError: func(_ auth.ErrorContext, err error) error {
				if errors.Is(err, privatePolicy) {
					observedPolicy = true
				}
				return nil
			}, UserAdditionalFields: fields, Secret: strings.Repeat("s", 40), BaseURL: "https://issuer.example.test", Plugins: plugins, RateLimit: new(bool)})
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
		if strings.Contains(out.Body.String(), "private membership policy") {
			t.Fatal("exposed private callback error")
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
	// Claims callbacks can complete independent store work without holding the grant locks.
	write(`UPDATE "session" SET "expiresAt"=? WHERE "id"='sid'`, s.date(now.Add(time.Hour)))
	write(`UPDATE "user" SET "plan_tier"='reader',"claims_allowed"=? WHERE "id"='person'`, true)
	write(`UPDATE "oauthClient" SET "subjectType"='pairwise',"metadata"=? WHERE "id"='app'`, `{"version":1,"custom":{"large":9007199254740993}}`)
	var duringClaims func()
	var inputs []op.IDTokenClaimsInput
	var expectAdmin bool
	var noMetadata bool
	custom, err := op.New(op.Options{PairwiseSecret: strings.Repeat("p", 32), Tokens: op.TokenOptions{CustomIDTokenClaims: func(ctx context.Context, in op.IDTokenClaimsInput) (map[string]any, error) {
		if duringClaims != nil {
			duringClaims()
		}
		inputs = append(inputs, in)
		if string(in.UserFields["allowClaims"]) != "true" {
			return nil, privatePolicy
		}
		if (in.User.AdminUserFields != nil) != expectAdmin {
			t.Fatal("received admin data outside the installed schema")
		}
		if _, present := in.UserFields["banReason"]; present != expectAdmin {
			t.Fatal("admin attribute did not match the active plugin")
		}
		if (in.Metadata == nil) != noMetadata {
			t.Fatal("wrong metadata presence", in.Metadata)
		}
		if in.User.ID != "person" || !slices.Contains(in.Scopes, "openid") {
			t.Fatal("invalid callback identity or scope", in.User.ID, in.Scopes)
		}
		if _, present := in.User.AdditionalField("allowClaims"); present {
			t.Fatal("hidden field on public profile")
		}
		if value, ok := in.User.AdditionalField("tier"); !ok || value == "" {
			t.Fatal("missing logical profile field")
		}
		out := map[string]any{"https://app.example/tier": in.UserFields["tier"], "app_version": in.Metadata["version"], "custom": in.Metadata["custom"], "email": in.User.Email, "sub": "wrong", "sid": "wrong", "amr": "wrong", "at_hash": "wrong"}
		in.Scopes[0] = "mutated"
		delete(in.Metadata, "version")
		return out, nil
	}}})
	must(err)
	customHost := host(custom, jwt)
	seed("claims-code", "openid offline_access", "")
	duringClaims = func() { write(`UPDATE "user" SET "plan_tier"='writer' WHERE "id"='person'`) }
	exchange(customHost, "authorization_code", "claims-code", 400, "invalid_grant")
	duringClaims = nil
	first := exchange(customHost, "authorization_code", "claims-code", 200, "")
	inspect := func(tok op.DelegatedToken, tier string, version float64) {
		t.Helper()
		claims, err := h.VerifyJWT(ctx, tok.IDToken, auth.JWTVerifyOptions{Issuer: h.OAuthIssuer(), Audience: "app"})
		must(err)
		if claims["https://app.example/tier"] != tier || claims["app_version"] != version || claims["email"] != "user@example.test" || claims["sub"] == "person" || claims["sub"] == "wrong" || claims["sid"] != "sid" || claims["at_hash"] == "wrong" || claims["amr"] != nil || claims["allowClaims"] != nil {
			t.Fatal("incorrect custom or protected claim", claims)
		}
	}
	inspect(first, "writer", 1)
	write(`UPDATE "user" SET "claims_allowed"=? WHERE "id"='person'`, false)
	exchange(customHost, "refresh_token", first.RefreshToken, 500, "")
	write(`UPDATE "user" SET "plan_tier"='editor',"claims_allowed"=? WHERE "id"='person'`, true)
	duringClaims = func() {
		encoded, err := json.Marshal(`{"version":2,"custom":{"large":9007199254740993}}`)
		must(err)
		write(`UPDATE "oauthClient" SET "metadata"=? WHERE "id"='app'`, string(encoded))
	}
	exchange(customHost, "refresh_token", first.RefreshToken, 400, "invalid_grant")
	duringClaims = nil
	second := exchange(customHost, "refresh_token", first.RefreshToken, 200, "")
	inspect(second, "editor", 2)
	if len(inputs) != 5 {
		t.Fatalf("callback ran %d times for five prepared exchanges", len(inputs))
	}

	admin, err := auth.NewAdmin(auth.AdminOptions{})
	must(err)
	withAdmin := host(custom, jwt, admin)
	expectAdmin = true
	noMetadata = true
	write(`UPDATE "oauthClient" SET "metadata"=NULL WHERE "id"='app'`)
	write(`UPDATE "user" SET "role"='admin' WHERE "id"='person'`)
	seed("active-schema", "openid", "")
	exchange(withAdmin, "authorization_code", "active-schema", 200, "")
	if inputs[len(inputs)-1].User.Role != "admin" {
		t.Fatal("enabled admin role missing from callback")
	}

	if !observedPolicy || !strings.Contains(warnings.String(), "amr at_hash sid sub") || strings.Contains(warnings.String(), "wrong") || strings.Contains(warnings.String(), "private membership policy") {
		t.Fatal("missing server diagnostics or private value in warning")
	}

}
