package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// Host fields join code, refresh and client_credentials responses without
// replacing the standard fields, the callback sees the account, client
// metadata and code value, and a failing callback leaves the code and the
// refresh token usable.
func TestTokenResponseFields(t *testing.T) {
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
			var inputs []op.TokenResponseInput
			var fail bool
			var between func()
			p, err := op.New(op.Options{Scopes: []string{"reports", "offline_access", "audit"}, Registration: op.RegistrationOptions{Enabled: true},
				Tokens: op.TokenOptions{CustomTokenResponseFields: func(_ context.Context, in op.TokenResponseInput) (map[string]any, error) {
					if fail {
						return nil, errors.New("fields unavailable")
					}
					if between != nil {
						between()
					}
					inputs = append(inputs, in)
					return map[string]any{"tenant": "acme", "access_token": "forged", "id_token": "forged", "scope": "forged", "refresh_token": "forged"}, nil
				}}})
			must(err)
			const origin = "https://fields.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("f", 40), Store: s, EmailAndPassword: true, Plugins: []auth.Plugin{p}, RateLimit: &off})
			must(err)
			owner, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
			must(err)
			signed, err := owner.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@fields.test", Password: "local fields test password"})
			must(err)
			var sid string
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "id" FROM "session" WHERE "userId"=?`), signed.User.ID).Scan(&sid))
			app, err := owner.RegisterOAuthClient(ctx, op.RegistrationMetadata{RedirectURIs: []string{"https://app.example.test/cb"}, TokenEndpointAuthMethod: "none",
				GrantTypes: []string{"authorization_code", "refresh_token"}, Scope: "reports offline_access"})
			must(err)
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "oauthClient" SET "metadata"=? WHERE "clientId"=?`), `{"tier":"gold"}`, app.ClientID)
			must(err)
			verifier := strings.Repeat("v", 64)
			sum := sha256.Sum256([]byte(verifier))
			seed := func(scope string) string {
				t.Helper()
				raw := rand.Text()
				digest := sha256.Sum256([]byte(raw))
				now := time.Now().UTC()
				value, err := json.Marshal(map[string]any{"type": "authorization_code", "userId": signed.User.ID, "sessionId": sid,
					"query": map[string]any{"client_id": app.ClientID, "scope": scope, "code_challenge_method": "S256", "code_challenge": base64.RawURLEncoding.EncodeToString(sum[:])}})
				must(err)
				_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","createdAt","updatedAt","expiresAt") VALUES (?,?,?,?,?,?)`),
					rand.Text(), base64.RawURLEncoding.EncodeToString(digest[:]), string(value), s.date(now), s.date(now), s.date(now.Add(time.Minute)))
				must(err)
				return raw
			}
			raw := seed("reports offline_access")
			exchange := func(form url.Values) (int, map[string]any) {
				t.Helper()
				req := httptest.NewRequest("POST", origin+"/api/auth/oauth2/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				var body map[string]any
				must(json.Unmarshal(out.Body.Bytes(), &body))
				return out.Code, body
			}
			standard := func(body map[string]any, scope string) bool {
				access, _ := body["access_token"].(string)
				return body["tenant"] == "acme" && access != "" && access != "forged" && body["scope"] == scope && body["id_token"] == nil
			}
			codeForm := url.Values{"grant_type": {"authorization_code"}, "client_id": {app.ClientID}, "code": {raw}, "code_verifier": {verifier}}
			// A failing callback leaves the code redeemable.
			fail = true
			if status, _ := exchange(codeForm); status != 500 {
				t.Fatal("a failing callback did not fail the code exchange", status)
			}
			fail = false
			status, first := exchange(codeForm)
			if status != 200 || !standard(first, "reports offline_access") || first["refresh_token"] == "forged" || first["refresh_token"] == nil {
				t.Fatal("the code response did not merge the host fields under its own", status, first)
			}
			if len(inputs) != 1 || inputs[0].GrantType != "authorization_code" || inputs[0].User == nil || inputs[0].User.ID != signed.User.ID ||
				string(inputs[0].Metadata["tier"]) != `"gold"` || !strings.Contains(string(inputs[0].VerificationValue), `"authorization_code"`) {
				t.Fatal("the code exchange input was incomplete", inputs)
			}
			// A code without a refresh or ID token still runs the callback
			// outside the grant transaction.
			if status, body := exchange(url.Values{"grant_type": {"authorization_code"}, "client_id": {app.ClientID}, "code": {seed("reports")}, "code_verifier": {verifier}}); status != 200 || !standard(body, "reports") || body["refresh_token"] != nil {
				t.Fatal("an access-only code response did not merge the host fields", status, body)
			}
			// A failing callback leaves the refresh token unrotated.
			refreshForm := url.Values{"grant_type": {"refresh_token"}, "client_id": {app.ClientID}, "refresh_token": {first["refresh_token"].(string)}}
			fail = true
			if status, _ := exchange(refreshForm); status != 500 {
				t.Fatal("a failing callback did not fail the refresh exchange", status)
			}
			fail = false
			if status, body := exchange(refreshForm); status != 200 || !standard(body, "reports offline_access") {
				t.Fatal("the refresh response did not merge the host fields", status, body)
			}
			if last := inputs[len(inputs)-1]; last.GrantType != "refresh_token" || last.User == nil || last.User.ID != signed.User.ID || last.VerificationValue != nil {
				t.Fatal("the refresh exchange input was incomplete", last)
			}
			// A client_credentials response carries the client's metadata.
			secret := "machine-secret"
			secretDigest := sha256.Sum256([]byte(secret))
			_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO "oauthClient" ("id","clientId","clientSecret","tokenEndpointAuthMethod","grantTypes","clientCredentialsScopes","redirectUris","metadata") VALUES (?,?,?,?,?,?,?,?)`),
				"machine", "machine", base64.RawURLEncoding.EncodeToString(secretDigest[:]), "client_secret_post", `["client_credentials"]`, `["reports"]`, `[]`, `{"tier":"machine"}`)
			must(err)
			if status, body := exchange(url.Values{"grant_type": {"client_credentials"}, "client_id": {"machine"}, "client_secret": {secret}}); status != 200 || !standard(body, "reports") {
				t.Fatal("the client_credentials response did not merge the host fields", status, body)
			}
			if last := inputs[len(inputs)-1]; last.GrantType != "client_credentials" || last.User != nil || string(last.Metadata["tier"]) != `"machine"` || len(last.Scopes) != 1 {
				t.Fatal("the client_credentials input was incomplete", last)
			}
			// The fields describe the first read's scopes, so a scope change
			// before the token is stored refuses the request.
			tokens := func() (n int) {
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "oauthAccessToken" WHERE "clientId"='machine'`)).Scan(&n))
				return n
			}
			before := tokens()
			between = func() {
				_, err := s.db.ExecContext(ctx, s.bind(`UPDATE "oauthClient" SET "clientCredentialsScopes"=? WHERE "clientId"='machine'`), `["reports","audit"]`)
				must(err)
			}
			if status, body := exchange(url.Values{"grant_type": {"client_credentials"}, "client_id": {"machine"}, "client_secret": {secret}}); status != 400 ||
				body["error_description"] != "client scopes changed during issuance, retry the request" || tokens() != before {
				t.Fatal("a scope change during issuance was not refused", status, body)
			}
			between = nil
		})
	}
}
