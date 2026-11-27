package sqlstore

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
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
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// With DisableJWTPlugin, code and refresh exchanges sign ID tokens with
// HS256 keyed by the client secret, discovery advertises HS256 without a
// key set, a public client gets its access token without an ID token, and
// the jwt plugin cannot also be installed.
func TestSecretSignedIDTokens(t *testing.T) {
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
			const origin = "https://secret-signed.example.test"
			var grants []string
			// Extension claims join the ID token only where it has no such
			// claim and never as protocol or standard profile claims.
			extension := op.Extension{
				IDTokenClaims: func(_ context.Context, in op.TokenClaimsInput) (map[string]any, error) {
					grants = append(grants, in.GrantType)
					return map[string]any{"team": "blue", "sub": "forged", "email": "forged", "name": "forged", "acr": "forged", "user": in.User.Email}, nil
				},
				UserInfoClaims: func(context.Context, op.UserInfoInput) (map[string]any, error) {
					return map[string]any{"team": "blue", "sub": "forged"}, nil
				},
			}
			opts := op.Options{Scopes: []string{"openid", "reports", "offline_access"}, DisableJWTPlugin: true, Registration: op.RegistrationOptions{Enabled: true}, Extensions: []op.Extension{extension}}
			p, err := op.New(opts)
			must(err)
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("h", 40), Store: s, EmailAndPassword: true, Plugins: []auth.Plugin{p}, RateLimit: &off})
			must(err)
			jwtPlugin, err := auth.NewJWT(auth.JWTOptions{})
			must(err)
			if _, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("h", 40), Store: s, Plugins: []auth.Plugin{p, jwtPlugin}, RateLimit: &off}); err == nil || !strings.Contains(err.Error(), "DisableJWTPlugin cannot be used with the jwt plugin") {
				t.Fatal("DisableJWTPlugin was accepted with the jwt plugin installed", err)
			}
			doc, err := op.GetOpenIDConfig(h)
			must(err)
			if len(doc.IDTokenSigningAlgorithms) != 1 || doc.IDTokenSigningAlgorithms[0] != "HS256" || doc.JWKSURI != "" || doc.Issuer != origin+"/api/auth" {
				t.Fatal("discovery did not advertise secret-signed ID tokens", doc.IDTokenSigningAlgorithms, doc.JWKSURI, doc.Issuer)
			}
			owner, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
			must(err)
			signed, err := owner.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@secret-signed.test", Password: "local id token test password"})
			must(err)
			var sid string
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "id" FROM "session" WHERE "userId"=?`), signed.User.ID).Scan(&sid))
			register := func(method string) op.RegisteredClient {
				t.Helper()
				app, err := owner.RegisterOAuthClient(ctx, op.RegistrationMetadata{RedirectURIs: []string{"https://app.example.test/cb"}, TokenEndpointAuthMethod: method,
					GrantTypes: []string{"authorization_code", "refresh_token"}, Scope: "openid reports offline_access"})
				must(err)
				return app
			}
			verifier := strings.Repeat("v", 64)
			sum := sha256.Sum256([]byte(verifier))
			code := func(clientID string) string {
				t.Helper()
				raw := rand.Text()
				digest := sha256.Sum256([]byte(raw))
				now := time.Now().UTC()
				value, err := json.Marshal(map[string]any{"type": "authorization_code", "userId": signed.User.ID, "sessionId": sid, "authTime": now.UnixMilli(),
					"query": map[string]any{"client_id": clientID, "scope": "openid reports offline_access", "code_challenge_method": "S256", "code_challenge": base64.RawURLEncoding.EncodeToString(sum[:])}})
				must(err)
				_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","createdAt","updatedAt","expiresAt") VALUES (?,?,?,?,?,?)`),
					rand.Text(), base64.RawURLEncoding.EncodeToString(digest[:]), string(value), s.date(now), s.date(now), s.date(now.Add(time.Minute)))
				must(err)
				return raw
			}
			exchange := func(form url.Values) map[string]any {
				t.Helper()
				req := httptest.NewRequest("POST", origin+"/api/auth/oauth2/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				var body map[string]any
				must(json.Unmarshal(out.Body.Bytes(), &body))
				if out.Code != 200 {
					t.Fatal("the exchange failed", out.Code, out.Body.String())
				}
				return body
			}
			// The ID token verifies with the client secret and carries the
			// access token's at_hash.
			check := func(body map[string]any, app op.RegisteredClient) {
				t.Helper()
				token, _ := body["id_token"].(string)
				parts := strings.Split(token, ".")
				if len(parts) != 3 {
					t.Fatal("no secret-signed ID token", body)
				}
				mac := hmac.New(sha256.New, []byte(app.ClientSecret))
				mac.Write([]byte(parts[0] + "." + parts[1]))
				header, _ := base64.RawURLEncoding.DecodeString(parts[0])
				payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
				var claims map[string]any
				must(json.Unmarshal(payload, &claims))
				access := sha256.Sum256([]byte(body["access_token"].(string)))
				if string(header) != `{"alg":"HS256"}` || base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) != parts[2] || claims["aud"] != app.ClientID ||
					claims["iss"] != origin+"/api/auth" || claims["at_hash"] != base64.RawURLEncoding.EncodeToString(access[:16]) {
					t.Fatal("the ID token was not signed with the client secret", string(header), claims)
				}
				if claims["team"] != "blue" || claims["user"] != "owner@secret-signed.test" || claims["sub"] == "forged" || claims["acr"] != "0" || claims["email"] != nil || claims["name"] != nil {
					t.Fatal("extension ID token claims were not added only where allowed", claims)
				}
			}
			confidential := register("client_secret_post")
			first := exchange(url.Values{"grant_type": {"authorization_code"}, "client_id": {confidential.ClientID}, "client_secret": {confidential.ClientSecret}, "code": {code(confidential.ClientID)}, "code_verifier": {verifier}})
			check(first, confidential)
			refreshed := exchange(url.Values{"grant_type": {"refresh_token"}, "client_id": {confidential.ClientID}, "client_secret": {confidential.ClientSecret}, "refresh_token": {first["refresh_token"].(string)}})
			check(refreshed, confidential)
			if len(grants) != 2 || grants[0] != "authorization_code" || grants[1] != "refresh_token" {
				t.Fatal("extension ID token claims did not see the grant type", grants)
			}
			// UserInfo adds the extension's claims under the standard ones.
			req := httptest.NewRequest("GET", origin+"/api/auth/oauth2/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+refreshed["access_token"].(string))
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			var profile map[string]any
			must(json.Unmarshal(out.Body.Bytes(), &profile))
			if out.Code != 200 || profile["team"] != "blue" || profile["sub"] == "forged" {
				t.Fatal("UserInfo did not add the extension's claims", out.Code, profile)
			}
			public := register("none")
			if body := exchange(url.Values{"grant_type": {"authorization_code"}, "client_id": {public.ClientID}, "code": {code(public.ClientID)}, "code_verifier": {verifier}}); body["access_token"] == nil || body["id_token"] != nil {
				t.Fatal("a public client received a secret-signed ID token", body)
			}
		})
	}
}
