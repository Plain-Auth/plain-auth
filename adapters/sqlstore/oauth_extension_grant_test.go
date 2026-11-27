package sqlstore

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// An extension grant: registration and discovery accept its grant type, the
// token endpoint hands it the request before reading credentials, and its
// handler authenticates the client through the provider API, which checks
// the credentials, the registered scopes and the client's grant types,
// looks clients up and hashes tokens. Its response keeps the standard
// members over its added fields.
func TestExtensionGrantDispatch(t *testing.T) {
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
			const grant = "urn:test:grant"
			var lookups []*op.ClientDetails
			var hashed string
			// refusedStatus is the status of the error AuthenticateClient returned.
			var refusedStatus int
			handler := func(in op.GrantInput) (op.TokenResponse, error) {
				if in.GrantType != grant || in.Form.Get("grant_type") != grant {
					t.Error("the handler did not get its grant", in.GrantType)
				}
				client, err := in.Provider.AuthenticateClient(op.ClientAuthenticationRequest{Scopes: strings.Fields(in.Form.Get("scope")), AllowPublic: in.Form.Get("public") == "yes"})
				if err != nil {
					var problem *auth.OAuthError
					if errors.As(err, &problem) {
						refusedStatus = problem.Status
					}
					return op.TokenResponse{}, err
				}
				found, err := in.Provider.Client(client.ClientID)
				if err != nil {
					return op.TokenResponse{}, err
				}
				missing, err := in.Provider.Client("unknown")
				if err != nil {
					return op.TokenResponse{}, err
				}
				lookups = []*op.ClientDetails{found, missing}
				if hashed, err = in.Provider.HashToken("refresh-value", op.StoredRefreshToken); err != nil {
					return op.TokenResponse{}, err
				}
				return op.TokenResponse{AccessToken: "minted-" + client.ClientID, TokenType: "Bearer", ExpiresIn: 60, Scope: in.Form.Get("scope"),
					Fields: map[string]any{"tenant": "acme", "access_token": "replaced", "method": client.Method}}, nil
			}
			p, err := op.New(op.Options{Scopes: []string{"reports", "billing"}, Registration: op.RegistrationOptions{Enabled: true}, Extensions: []op.Extension{{Grants: map[string]op.GrantHandler{grant: handler}}},
				ClientPrivileges: func(context.Context, op.ClientAccess) (bool, error) { return true, nil }})
			must(err)
			const origin = "https://grant.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("g", 40), Store: s, EmailAndPassword: true, PasswordHash: testPasswordHash, PasswordVerify: testPasswordVerify, Plugins: []auth.Plugin{p}, RateLimit: &off})
			must(err)
			owner, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
			must(err)
			_, err = owner.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@grant.test", Password: "local grant password"})
			must(err)
			// Registration accepts the extension grant and refuses an unknown one.
			registered, err := owner.CreateOAuthClient(ctx, op.RegistrationMetadata{GrantTypes: []string{grant}, Scope: "reports"})
			must(err)
			if !slices.Equal(registered.GrantTypes, []string{grant}) || registered.ClientSecret == "" {
				t.Fatal("the extension grant was not registered", registered)
			}
			if _, err := owner.CreateOAuthClient(ctx, op.RegistrationMetadata{GrantTypes: []string{"urn:test:unknown"}}); err == nil {
				t.Fatal("an unknown grant type was registered")
			}
			// Dynamic registration keeps the extension grant among those asked for.
			dynamic, err := owner.RegisterOAuthClient(ctx, op.RegistrationMetadata{GrantTypes: []string{grant, "urn:test:unknown"}})
			must(err)
			if !slices.Equal(dynamic.GrantTypes, []string{grant}) {
				t.Fatal("dynamic registration did not keep the extension grant", dynamic.GrantTypes)
			}
			public, err := owner.CreateOAuthClient(ctx, op.RegistrationMetadata{GrantTypes: []string{grant}, TokenEndpointAuthMethod: "none"})
			must(err)
			other, err := owner.CreateOAuthClient(ctx, op.RegistrationMetadata{GrantTypes: []string{"client_credentials"}})
			must(err)
			post := func(form url.Values, user, password string) (int, map[string]any, http.Header) {
				t.Helper()
				form.Set("grant_type", grant)
				req := httptest.NewRequest("POST", origin+"/api/auth/oauth2/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if user != "" {
					req.SetBasicAuth(user, password)
				}
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				var body map[string]any
				_ = json.Unmarshal(out.Body.Bytes(), &body)
				return out.Code, body, out.Header()
			}
			id, secret := registered.ClientID, registered.ClientSecret
			status, body, header := post(url.Values{"scope": {"reports"}}, id, secret)
			if status != 200 || body["access_token"] != "minted-"+id || body["tenant"] != "acme" || body["method"] != "client_secret_basic" || header.Get("Cache-Control") != "no-store" {
				t.Fatal("the extension grant did not answer", status, body, header)
			}
			if lookups[0] == nil || lookups[0].ClientID != id || lookups[1] != nil {
				t.Fatal("the provider's client lookup was wrong", lookups)
			}
			sum := sha256.Sum256([]byte("refresh-value"))
			if hashed != base64.RawURLEncoding.EncodeToString(sum[:]) {
				t.Fatal("HashToken did not return the stored form", hashed)
			}
			refusal := func(status int, body map[string]any, code, description string) {
				t.Helper()
				if body["error"] != code || body["error_description"] != description {
					t.Fatal("wanted", code, description, "got", status, body)
				}
			}
			status, body, header = post(url.Values{}, id, "wrong")
			refusal(status, body, "invalid_client", "invalid client_secret")
			if status != 401 || !strings.HasPrefix(header.Get("WWW-Authenticate"), "Basic") || refusedStatus != 401 {
				t.Fatal("a wrong secret was not challenged", status, header, refusedStatus)
			}
			status, body, _ = post(url.Values{"client_id": {id}}, "", "")
			refusal(status, body, "invalid_client", "Missing required client credentials")
			status, body, _ = post(url.Values{}, "", "")
			refusal(status, body, "invalid_request", "Missing required client_id")
			status, body, _ = post(url.Values{"scope": {"billing"}}, id, secret)
			refusal(status, body, "invalid_scope", "client does not allow scope billing")
			status, body, _ = post(url.Values{}, other.ClientID, other.ClientSecret)
			refusal(status, body, "unauthorized_client", "client is not authorized to use grant type "+grant)
			// A public client needs the handler's AllowPublic.
			status, body, _ = post(url.Values{"client_id": {public.ClientID}}, "", "")
			refusal(status, body, "invalid_client", "Missing required client credentials")
			if status, body, _ := post(url.Values{"client_id": {public.ClientID}, "public": {"yes"}}, "", ""); status != 200 || body["method"] != "none" {
				t.Fatal("a public client was refused with AllowPublic", status, body)
			}
			// Discovery lists the grant; an unknown grant is unsupported.
			doc, err := op.GetAuthorizationServerConfig(h)
			must(err)
			if !slices.Contains(doc.GrantTypesSupported, grant) {
				t.Fatal("discovery did not list the extension grant", doc.GrantTypesSupported)
			}
			form := url.Values{"grant_type": {"urn:test:unknown"}}
			req := httptest.NewRequest("POST", origin+"/api/auth/oauth2/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			if out.Code != 400 || !strings.Contains(out.Body.String(), "unsupported_grant_type") {
				t.Fatal("an unknown grant was not unsupported", out.Code, out.Body.String())
			}
		})
	}
}

// IssueTokens mints a client token for an extension grant: opaque without
// resources, bound by a given confirmation or a DPoP proof, refused for a
// client that requires DPoP without a key, and a signed at+jwt for a
// resource, whose policy narrows the scopes and caps the lifetime, with the
// grant's claims above the extensions' and below the host's and the
// resource's. Response fields keep the standard members; a client disabled
// after AuthenticateClient gets no token.
func TestExtensionGrantClientTokens(t *testing.T) {
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
			const grant = "urn:test:client"
			secret := "client-token-secret"
			digest := sha256.Sum256([]byte(secret))
			for _, id := range []string{"app", "strict", "plain", "off"} {
				grants := `["` + grant + `"]`
				if id == "plain" {
					grants = `["client_credentials"]`
				}
				write(`INSERT INTO "oauthClient" ("id","clientId","clientSecret","tokenEndpointAuthMethod","redirectUris","grantTypes","dpopBoundAccessTokens","disabled") VALUES (?,?,?,'client_secret_post','[]',?,?,?)`,
					id, id, base64.RawURLEncoding.EncodeToString(digest[:]), grants, id == "strict", id == "off")
			}
			// changePolicy edits the resource while the token is being signed.
			changePolicy := false
			write(`INSERT INTO "oauthResource" ("id","identifier","name","allowedScopes","accessTokenTtl","customClaims") VALUES ('api','urn:api','API',?,?,?)`, `["reports"]`, 120, `{"tier":"gold"}`)
			write(`INSERT INTO "oauthClientResource" ("id","resourceId","clientId") VALUES ('link','urn:api','app')`)
			handler := func(in op.GrantInput) (op.TokenResponse, error) {
				// A handler may issue for a client it did not authenticate.
				client := op.AuthenticatedClient{ClientID: in.Form.Get("issuefor")}
				if client.ClientID == "" {
					var err error
					if client, err = in.Provider.AuthenticateClient(op.ClientAuthenticationRequest{}); err != nil {
						return op.TokenResponse{}, err
					}
				}
				if in.Form.Get("disable") == "yes" {
					write(`UPDATE "oauthClient" SET "disabled"=? WHERE "clientId"=?`, true, client.ClientID)
				}
				if in.Form.Get("rotate") == "yes" {
					write(`UPDATE "oauthClient" SET "clientSecret"=? WHERE "clientId"=?`, "rotated", client.ClientID)
				}
				params := op.TokenIssueParams{ClientID: client.ClientID, Scopes: strings.Fields(in.Form.Get("scope")), Resources: in.Form["resource"],
					AccessTokenClaims: map[string]any{"per": "issue", "client_id": "forged"}, TokenResponse: map[string]any{"tenant": "handler", "access_token": "replaced"}}
				if v := in.Form.Get("x5t"); v != "" {
					params.Confirmation = &op.Confirmation{X5TS256: v}
				}
				if v := in.Form.Get("jkt"); v != "" {
					params.Confirmation = &op.Confirmation{JKT: v}
				}
				switch in.Form.Get("invalid") {
				case "confirmation":
					params.Confirmation = &op.Confirmation{JKT: "a", X5TS256: "b"}
				case "resource":
					params.Resources = []string{"relative"}
				case "client":
					params.ClientID = ""
				}
				return in.Provider.IssueTokens(params)
			}
			p, err := op.New(op.Options{Scopes: []string{"reports", "billing"},
				Extensions: []op.Extension{{Grants: map[string]op.GrantHandler{grant: handler},
					AccessTokenClaims: func(context.Context, op.TokenClaimsInput) (map[string]any, error) {
						return map[string]any{"per": "extension", "ext": "yes"}, nil
					}}},
				Tokens: op.TokenOptions{
					CustomTokenResponseFields: func(_ context.Context, in op.TokenResponseInput) (map[string]any, error) {
						return map[string]any{"tenant": "custom", "grant": in.GrantType}, nil
					},
					CustomAccessTokenClaims: func(context.Context, op.TokenClaimsInput) (map[string]any, error) {
						if changePolicy {
							write(`UPDATE "oauthResource" SET "accessTokenTtl"=? WHERE "identifier"='urn:api'`, 60)
						}
						return map[string]any{"tier": "custom", "plugin": "yes"}, nil
					}}})
			must(err)
			signing, err := auth.NewJWT(auth.JWTOptions{})
			must(err)
			const origin = "https://mint.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("m", 40), Store: s, Plugins: []auth.Plugin{p, signing}, RateLimit: &off})
			must(err)
			tokenURL := origin + "/api/auth/oauth2/token"
			call := func(path string, form url.Values, proof string) (int, map[string]any) {
				t.Helper()
				req := httptest.NewRequest("POST", origin+"/api/auth"+path, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if proof != "" {
					req.Header.Set("DPoP", proof)
				}
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				var body map[string]any
				_ = json.Unmarshal(out.Body.Bytes(), &body)
				return out.Code, body
			}
			mint := func(client string, extra url.Values, proof string) (int, map[string]any) {
				t.Helper()
				form := url.Values{"grant_type": {grant}, "client_id": {client}, "client_secret": {secret}}
				for k, v := range extra {
					form[k] = v
				}
				return call("/oauth2/token", form, proof)
			}
			introspect := func(token string) map[string]any {
				t.Helper()
				status, body := call("/oauth2/introspect", url.Values{"token": {token}, "client_id": {"app"}, "client_secret": {secret}}, "")
				if status != 200 || body["active"] != true {
					t.Fatal("the issued token did not introspect active", status, body)
				}
				return body
			}
			// An opaque client token.
			status, body := mint("app", url.Values{"scope": {"reports billing"}}, "")
			if status != 200 || body["token_type"] != "Bearer" || body["scope"] != "reports billing" || body["access_token"] == "replaced" ||
				body["tenant"] != "handler" || body["grant"] != grant || body["refresh_token"] != nil || body["id_token"] != nil {
				t.Fatal("the opaque client token was wrong", status, body)
			}
			if info := introspect(body["access_token"].(string)); info["client_id"] != "app" || info["cnf"] != nil || info["sub"] != nil {
				t.Fatal("the opaque client token introspected wrong", info)
			}
			// A certificate confirmation is kept; a DPoP key makes it DPoP.
			status, body = mint("app", url.Values{"scope": {"reports"}, "x5t": {"cert-thumbprint"}}, "")
			if info := introspect(body["access_token"].(string)); status != 200 || body["token_type"] != "Bearer" || !reflect.DeepEqual(info["cnf"], map[string]any{"x5t#S256": "cert-thumbprint"}) {
				t.Fatal("the certificate confirmation was not kept", status, body, info)
			}
			key := newDPoPKey(t)
			status, body = mint("app", url.Values{"scope": {"reports"}, "jkt": {key.thumb}}, "")
			if info := introspect(body["access_token"].(string)); status != 200 || body["token_type"] != "DPoP" || info["token_type"] != "DPoP" || !reflect.DeepEqual(info["cnf"], map[string]any{"jkt": key.thumb}) {
				t.Fatal("the DPoP confirmation was not kept", status, body, info)
			}
			status, body = mint("app", url.Values{"scope": {"reports"}}, key.proof(t, tokenURL))
			if info := introspect(body["access_token"].(string)); status != 200 || body["token_type"] != "DPoP" || !reflect.DeepEqual(info["cnf"], map[string]any{"jkt": key.thumb}) {
				t.Fatal("a DPoP proof did not bind the client token", status, body, info)
			}
			// A client that requires DPoP needs a key.
			if status, body := mint("strict", url.Values{"scope": {"reports"}, "x5t": {"cert-thumbprint"}}, ""); status != 400 || body["error"] != "invalid_dpop_proof" {
				t.Fatal("a DPoP-required client got an unbound token", status, body)
			}
			// A resource-targeted token is signed with the resource's policy.
			status, body = mint("app", url.Values{"scope": {"reports billing"}, "resource": {"urn:api"}, "x5t": {"cert-thumbprint"}}, "")
			if status != 200 || body["scope"] != "reports" || body["expires_in"] != float64(120) || body["token_type"] != "Bearer" {
				t.Fatal("the resource token was wrong", status, body)
			}
			parts := strings.Split(body["access_token"].(string), ".")
			if len(parts) != 3 {
				t.Fatal("the resource token was not signed", body["access_token"])
			}
			raw, err := base64.RawURLEncoding.DecodeString(parts[1])
			must(err)
			var claims map[string]any
			must(json.Unmarshal(raw, &claims))
			if claims["aud"] != "urn:api" || claims["sub"] != "app" || claims["client_id"] != "app" || claims["scope"] != "reports" ||
				claims["per"] != "issue" || claims["ext"] != "yes" || claims["plugin"] != "yes" || claims["tier"] != "gold" ||
				claims["exp"].(float64)-claims["iat"].(float64) != 120 || !reflect.DeepEqual(claims["cnf"], map[string]any{"x5t#S256": "cert-thumbprint"}) {
				t.Fatal("the resource token's claims were wrong", claims)
			}
			// Malformed parameters are refused.
			for invalid, want := range map[string]int{"confirmation": 500, "resource": 400, "client": 500} {
				if status, body := mint("app", url.Values{"scope": {"reports"}, "invalid": {invalid}}, ""); status != want || want == 400 && body["error"] != "invalid_request" {
					t.Fatal("malformed issue parameters were accepted", invalid, status, body)
				}
			}
			// The registration is checked again at issuance.
			for _, c := range []struct {
				form              url.Values
				code, description string
			}{
				{url.Values{"issuefor": {"plain"}}, "unauthorized_client", "client is not authorized to use grant type " + grant},
				{url.Values{"issuefor": {"off"}}, "invalid_client", "client is disabled"},
				{url.Values{"rotate": {"yes"}}, "invalid_client", "invalid client_secret"},
			} {
				c.form.Set("scope", "reports")
				if status, body := mint("app", c.form, ""); status != 400 || body["error"] != c.code || body["error_description"] != c.description {
					t.Fatal("issuance did not check the registration again", c.form, status, body)
				}
			}
			write(`UPDATE "oauthClient" SET "clientSecret"=? WHERE "clientId"='app'`, base64.RawURLEncoding.EncodeToString(digest[:]))
			// A resource policy that changes while the token is signed refuses it.
			changePolicy = true
			status, body = mint("app", url.Values{"scope": {"reports"}, "resource": {"urn:api"}}, "")
			changePolicy = false
			write(`UPDATE "oauthResource" SET "accessTokenTtl"=? WHERE "identifier"='urn:api'`, 120)
			if status != 400 || body["error_description"] != "resource policy changed during issuance, retry the request" {
				t.Fatal("a changed resource policy was signed", status, body)
			}
			// A client disabled after authentication gets no token.
			count := func() int {
				t.Helper()
				var n int
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "oauthAccessToken" WHERE "clientId"='app'`)).Scan(&n))
				return n
			}
			before := count()
			if status, body := mint("app", url.Values{"scope": {"reports"}, "disable": {"yes"}}, ""); status != 400 || body["error"] != "invalid_client" || body["error_description"] != "client is disabled" {
				t.Fatal("a disabled client got a token", status, body)
			}
			if count() != before {
				t.Fatal("a refused issuance stored a token")
			}
			// A record cannot carry two bindings.
			err = s.WithMachineResources(ctx, "strict", nil, func(op.MachineClient, map[string]op.MachineResource) (*op.ResourceMachineTokenRecord, error) {
				return &op.ResourceMachineTokenRecord{MachineTokenRecord: op.MachineTokenRecord{StoredToken: "x", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)},
					Thumbprint: "a", Confirmation: &op.Confirmation{JKT: "b"}}, nil
			})
			if err == nil {
				t.Fatal("a token with two bindings was stored")
			}
		})
	}
}

// IssueTokens with a user issues as a code exchange does without a code:
// an access token bound to the user and any live session of theirs, an ID
// token for openid with the grant's add-only claims, and a refresh token
// for offline_access when the client may refresh, which rotates through
// the refresh_token grant. A session that is another user's or expired, a
// missing user, and a user changed between the passes are refused. A
// resource gets a signed access token, which the ID token's at_hash covers.
func TestExtensionGrantUserTokens(t *testing.T) {
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
			start := now.Add(-time.Hour)
			for _, u := range []string{"owner", "someone"} {
				write(`INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`, u, u, u+"@example.test", true, s.date(now), s.date(now))
			}
			write(`INSERT INTO "session" ("id","userId","token","createdAt","updatedAt","expiresAt") VALUES ('sid','owner','a',?,?,?)`, s.date(start), s.date(now), s.date(now.Add(time.Hour)))
			write(`INSERT INTO "session" ("id","userId","token","createdAt","updatedAt","expiresAt") VALUES ('theirs','someone','b',?,?,?)`, s.date(now), s.date(now), s.date(now.Add(time.Hour)))
			write(`INSERT INTO "session" ("id","userId","token","createdAt","updatedAt","expiresAt") VALUES ('old','owner','c',?,?,?)`, s.date(start), s.date(start), s.date(now.Add(-time.Minute)))
			const grant = "urn:test:user"
			secret := "user-token-secret"
			digest := sha256.Sum256([]byte(secret))
			for id, grants := range map[string]string{"app": `["` + grant + `","refresh_token"]`, "noref": `["` + grant + `"]`, "strict": `["` + grant + `"]`} {
				write(`INSERT INTO "oauthClient" ("id","clientId","clientSecret","tokenEndpointAuthMethod","redirectUris","grantTypes","enableEndSession","dpopBoundAccessTokens") VALUES (?,?,?,'client_secret_post','[]',?,?,?)`,
					id, id, base64.RawURLEncoding.EncodeToString(digest[:]), grants, true, id == "strict")
			}
			write(`INSERT INTO "oauthResource" ("id","identifier","name","accessTokenTtl") VALUES ('api','urn:api','API',?)`, 120)
			write(`INSERT INTO "oauthClientResource" ("id","resourceId","clientId") VALUES ('link','urn:api','app')`)
			// changeUser renames the user while the tokens are made.
			changeUser := false
			handler := func(in op.GrantInput) (op.TokenResponse, error) {
				client, err := in.Provider.AuthenticateClient(op.ClientAuthenticationRequest{})
				if err != nil {
					return op.TokenResponse{}, err
				}
				params := op.TokenIssueParams{ClientID: client.ClientID, UserID: in.Form.Get("user"), SessionID: in.Form.Get("session"), Scopes: strings.Fields(in.Form.Get("scope")),
					Resources: in.Form["resource"], Nonce: "n-1", RequestedUserInfoClaims: []string{"email", "bogus"},
					IDTokenClaims: map[string]any{"shared": "issue", "grant_claim": "yes", "email": "forged", "nonce": "forged", "host": "issue"}}
				if v := in.Form.Get("x5t"); v != "" {
					params.Confirmation = &op.Confirmation{X5TS256: v}
				}
				return in.Provider.IssueTokens(params)
			}
			p, err := op.New(op.Options{Scopes: []string{"openid", "email", "reports", "offline_access"},
				Extensions: []op.Extension{{Grants: map[string]op.GrantHandler{grant: handler},
					IDTokenClaims: func(context.Context, op.TokenClaimsInput) (map[string]any, error) {
						return map[string]any{"shared": "extension", "wallet": "ext"}, nil
					}}},
				Tokens: op.TokenOptions{CustomIDTokenClaims: func(context.Context, op.IDTokenClaimsInput) (map[string]any, error) {
					return map[string]any{"host": "custom"}, nil
				}, CustomTokenResponseFields: func(_ context.Context, in op.TokenResponseInput) (map[string]any, error) {
					if changeUser {
						write(`UPDATE "user" SET "name"=? WHERE "id"='owner'`, "Renamed")
					}
					return map[string]any{"grant": in.GrantType, "user": in.User.ID}, nil
				}}})
			must(err)
			signing, err := auth.NewJWT(auth.JWTOptions{})
			must(err)
			const origin = "https://user.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("u", 40), Store: s, Plugins: []auth.Plugin{p, signing}, RateLimit: &off})
			must(err)
			tokenURL := origin + "/api/auth/oauth2/token"
			call := func(path string, form url.Values, proof string) (int, map[string]any) {
				t.Helper()
				req := httptest.NewRequest("POST", origin+"/api/auth"+path, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if proof != "" {
					req.Header.Set("DPoP", proof)
				}
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				var body map[string]any
				_ = json.Unmarshal(out.Body.Bytes(), &body)
				return out.Code, body
			}
			mint := func(client string, extra url.Values, proof string) (int, map[string]any) {
				t.Helper()
				form := url.Values{"grant_type": {grant}, "client_id": {client}, "client_secret": {secret}, "user": {"owner"}}
				for k, v := range extra {
					form[k] = v
				}
				return call("/oauth2/token", form, proof)
			}
			payload := func(token string) map[string]any {
				t.Helper()
				parts := strings.Split(token, ".")
				if len(parts) != 3 {
					t.Fatal("not a JWT", token)
				}
				raw, err := base64.RawURLEncoding.DecodeString(parts[1])
				must(err)
				var claims map[string]any
				must(json.Unmarshal(raw, &claims))
				return claims
			}
			row := func(table, token string) (user string, session, claims, confirmation *string) {
				t.Helper()
				digest := sha256.Sum256([]byte(token))
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT "userId","sessionId","requestedUserInfoClaims","confirmation" FROM "`+table+`" WHERE "token"=?`), base64.RawURLEncoding.EncodeToString(digest[:])).Scan(&user, &session, &claims, &confirmation))
				return
			}
			// A session-bound user grant with every token.
			status, body := mint("app", url.Values{"session": {"sid"}, "scope": {"openid email reports offline_access"}}, "")
			if status != 200 || body["refresh_token"] == nil || body["id_token"] == nil || body["token_type"] != "Bearer" || body["grant"] != grant || body["user"] != "owner" {
				t.Fatal("the user grant was wrong", status, body)
			}
			id := payload(body["id_token"].(string))
			if id["sub"] != "owner" || id["aud"] != "app" || id["nonce"] != "n-1" || id["sid"] != "sid" || id["auth_time"] != float64(start.Unix()) ||
				id["shared"] != "issue" || id["wallet"] != "ext" || id["grant_claim"] != "yes" || id["email"] == "forged" || id["at_hash"] == nil || id["host"] != "custom" {
				t.Fatal("the ID token's claims were wrong", id)
			}
			user, session, claims, _ := row("oauthAccessToken", body["access_token"].(string))
			if user != "owner" || session == nil || *session != "sid" || claims == nil || !sameJSON(*claims, `["email"]`) {
				t.Fatal("the access token row was wrong", user, session, claims)
			}
			// The refresh token rotates through the refresh_token grant.
			if status, rotated := call("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"app"}, "client_secret": {secret}, "refresh_token": {body["refresh_token"].(string)}}, ""); status != 200 || rotated["refresh_token"] == nil {
				t.Fatal("the grant's refresh token did not rotate", status, rotated)
			}
			// A client that may not refresh gets no refresh token, and a
			// grant without a session binds to none.
			status, body = mint("noref", url.Values{"scope": {"reports offline_access"}}, "")
			if status != 200 || body["refresh_token"] != nil || body["id_token"] != nil {
				t.Fatal("a client that may not refresh got a refresh token", status, body)
			}
			if _, session, _, _ := row("oauthAccessToken", body["access_token"].(string)); session != nil {
				t.Fatal("a grant without a session was bound to one", *session)
			}
			// A DPoP proof binds both tokens; a certificate confirmation is kept.
			key := newDPoPKey(t)
			status, body = mint("app", url.Values{"session": {"sid"}, "scope": {"reports offline_access"}}, key.proof(t, tokenURL))
			_, _, _, access := row("oauthAccessToken", body["access_token"].(string))
			_, _, _, refreshed := row("oauthRefreshToken", body["refresh_token"].(string))
			if status != 200 || body["token_type"] != "DPoP" || access == nil || refreshed == nil || !sameJSON(*access, `{"jkt":"`+key.thumb+`"}`) || !sameJSON(*refreshed, *access) {
				t.Fatal("the DPoP proof did not bind both tokens", status, body, access, refreshed)
			}
			status, body = mint("app", url.Values{"scope": {"reports"}, "x5t": {"cert"}}, "")
			if _, _, _, access := row("oauthAccessToken", body["access_token"].(string)); status != 200 || body["token_type"] != "Bearer" || access == nil || !sameJSON(*access, `{"x5t#S256":"cert"}`) {
				t.Fatal("the certificate confirmation was not kept", status, body, access)
			}
			// A client that requires DPoP needs a key.
			if status, body := mint("strict", url.Values{"scope": {"reports"}, "x5t": {"cert"}}, ""); status != 400 || body["error"] != "invalid_dpop_proof" {
				t.Fatal("a DPoP-required client got unbound user tokens", status, body)
			}
			// A resource gets a signed access token that is not stored,
			// covered by at_hash and carrying the confirmation.
			var stored, after int
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "oauthAccessToken"`)).Scan(&stored))
			status, body = mint("app", url.Values{"session": {"sid"}, "scope": {"openid reports"}, "resource": {"urn:api"}, "x5t": {"cert"}}, "")
			if status != 200 || body["expires_in"] != float64(120) {
				t.Fatal("the resource grant was wrong", status, body)
			}
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "oauthAccessToken"`)).Scan(&after))
			if after != stored {
				t.Fatal("the signed access token was stored")
			}
			signed := payload(body["access_token"].(string))
			if signed["sub"] != "owner" || signed["sid"] != "sid" || !reflect.DeepEqual(signed["aud"], []any{"urn:api", origin + "/api/auth/oauth2/userinfo"}) ||
				!reflect.DeepEqual(signed["cnf"], map[string]any{"x5t#S256": "cert"}) {
				t.Fatal("the signed access token was wrong", signed)
			}
			// The default EdDSA key hashes with SHA-512.
			sum := sha512.Sum512([]byte(body["access_token"].(string)))
			if payload(body["id_token"].(string))["at_hash"] != base64.RawURLEncoding.EncodeToString(sum[:32]) {
				t.Fatal("the ID token's at_hash did not cover the signed access token")
			}
			// Refusals.
			for _, c := range []struct {
				form              url.Values
				code, description string
			}{
				{url.Values{"session": {"theirs"}}, "invalid_request", "session no longer exists"},
				{url.Values{"session": {"old"}}, "invalid_request", "session no longer exists"},
				{url.Values{"user": {"missing"}}, "invalid_user", "missing user, user may have been deleted"},
			} {
				c.form.Set("scope", "reports")
				if status, body := mint("app", c.form, ""); status != 400 || body["error"] != c.code || body["error_description"] != c.description {
					t.Fatal("a user grant was not refused", c.form, status, body)
				}
			}
			changeUser = true
			status, body = mint("app", url.Values{"scope": {"reports"}}, "")
			changeUser = false
			if status != 400 || body["error_description"] != "grant changed during issuance, retry the request" {
				t.Fatal("a user changed during issuance was not refused", status, body)
			}
		})
	}
}

// ValidateAccessToken, inside an extension grant, sees an opaque or signed
// access token as the issuer does without a client, and as a client does at
// introspection with one: the issuer and a client linked to the token's
// resource see it active, another client inactive. A refresh token and an
// unknown token are inactive; RequireActiveAccessToken refuses inactive
// tokens with 401 invalid_token and a Bearer challenge. A pairwise client's
// subject is presented pairwise, and a DPoP token's key is returned
// without a proof.
func TestExtensionGrantValidateTokens(t *testing.T) {
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
			write(`INSERT INTO "session" ("id","userId","token","createdAt","updatedAt","expiresAt") VALUES ('sid','owner','a',?,?,?)`, s.date(now), s.date(now), s.date(now.Add(time.Hour)))
			const mintGrant, checkGrant = "urn:test:mint", "urn:test:check"
			secret := "validate-secret"
			digest := sha256.Sum256([]byte(secret))
			for _, id := range []string{"app", "linked", "stranger", "pairwise"} {
				subject := "public"
				if id == "pairwise" {
					subject = "pairwise"
				}
				write(`INSERT INTO "oauthClient" ("id","clientId","clientSecret","tokenEndpointAuthMethod","redirectUris","grantTypes","subjectType") VALUES (?,?,?,'client_secret_post',?,?,?)`,
					id, id, base64.RawURLEncoding.EncodeToString(digest[:]), `["https://`+id+`.example.test/cb"]`, `["`+mintGrant+`","refresh_token"]`, subject)
			}
			write(`INSERT INTO "oauthResource" ("id","identifier","name") VALUES ('api','urn:api','API')`)
			for _, id := range []string{"app", "linked", "pairwise"} {
				write(`INSERT INTO "oauthClientResource" ("id","resourceId","clientId") VALUES (?,'urn:api',?)`, "link-"+id, id)
			}
			mint := func(in op.GrantInput) (op.TokenResponse, error) {
				client, err := in.Provider.AuthenticateClient(op.ClientAuthenticationRequest{})
				if err != nil {
					return op.TokenResponse{}, err
				}
				return in.Provider.IssueTokens(op.TokenIssueParams{ClientID: client.ClientID, UserID: "owner", SessionID: "sid", Scopes: strings.Fields(in.Form.Get("scope")), Resources: in.Form["resource"]})
			}
			check := func(in op.GrantInput) (op.TokenResponse, error) {
				validate := in.Provider.ValidateAccessToken
				if in.Form.Get("require") == "yes" {
					validate = in.Provider.RequireActiveAccessToken
				}
				payload, err := validate(in.Form.Get("token"), in.Form.Get("caller"))
				if err != nil {
					return op.TokenResponse{}, err
				}
				return op.TokenResponse{AccessToken: "checked", TokenType: "Bearer", Fields: map[string]any{"payload": payload}}, nil
			}
			p, err := op.New(op.Options{Scopes: []string{"reports", "offline_access"}, PairwiseSecret: strings.Repeat("p", 32),
				Extensions: []op.Extension{{Grants: map[string]op.GrantHandler{mintGrant: mint, checkGrant: check}}}})
			must(err)
			signing, err := auth.NewJWT(auth.JWTOptions{})
			must(err)
			const origin = "https://validate.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("v", 40), Store: s, Plugins: []auth.Plugin{p, signing}, RateLimit: &off})
			must(err)
			tokenURL := origin + "/api/auth/oauth2/token"
			post := func(form url.Values, proof string) (int, map[string]any, http.Header) {
				t.Helper()
				req := httptest.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if proof != "" {
					req.Header.Set("DPoP", proof)
				}
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				var body map[string]any
				_ = json.Unmarshal(out.Body.Bytes(), &body)
				return out.Code, body, out.Header()
			}
			issue := func(client string, extra url.Values, proof string) map[string]any {
				t.Helper()
				form := url.Values{"grant_type": {mintGrant}, "client_id": {client}, "client_secret": {secret}}
				for k, v := range extra {
					form[k] = v
				}
				status, body, _ := post(form, proof)
				if status != 200 {
					t.Fatal("minting failed", status, body)
				}
				return body
			}
			validate := func(token, caller string) map[string]any {
				t.Helper()
				status, body, _ := post(url.Values{"grant_type": {checkGrant}, "token": {token}, "caller": {caller}}, "")
				if status != 200 {
					t.Fatal("validation failed", status, body)
				}
				return body["payload"].(map[string]any)
			}
			opaque := issue("app", url.Values{"scope": {"reports offline_access"}}, "")
			signed := issue("app", url.Values{"scope": {"reports"}, "resource": {"urn:api"}}, "")
			for _, c := range []struct {
				token, caller string
				active        bool
			}{
				{opaque["access_token"].(string), "", true},
				{opaque["access_token"].(string), "app", true},
				{opaque["access_token"].(string), "stranger", false},
				{signed["access_token"].(string), "", true},
				{signed["access_token"].(string), "linked", true},
				{signed["access_token"].(string), "stranger", false},
				{opaque["refresh_token"].(string), "", false},
				{opaque["refresh_token"].(string), "app", false},
				{"unknown", "", false},
			} {
				payload := validate(c.token, c.caller)
				if payload["active"] != c.active || c.active && (payload["sub"] != "owner" || payload["client_id"] != "app" || payload["sid"] != "sid") {
					t.Fatal("the token validated wrong", c.caller, c.active, payload)
				}
			}
			// A pairwise client's subject is presented pairwise, to the
			// issuer's view and to the client's, opaque or signed.
			pairwiseOpaque := issue("pairwise", url.Values{"scope": {"reports"}}, "")["access_token"].(string)
			pairwiseSigned := issue("pairwise", url.Values{"scope": {"reports"}, "resource": {"urn:api"}}, "")["access_token"].(string)
			for _, c := range [][2]string{{pairwiseOpaque, ""}, {pairwiseOpaque, "pairwise"}, {pairwiseSigned, ""}, {pairwiseSigned, "pairwise"}} {
				if payload := validate(c[0], c[1]); payload["active"] != true || payload["sub"] == "owner" || payload["sub"] == nil {
					t.Fatal("the pairwise subject was not presented", c[1], payload)
				}
			}
			// A DPoP token's key is returned without a proof.
			key := newDPoPKey(t)
			bound := issue("app", url.Values{"scope": {"reports"}}, key.proof(t, tokenURL))
			if payload := validate(bound["access_token"].(string), "app"); payload["token_type"] != "DPoP" || !reflect.DeepEqual(payload["cnf"], map[string]any{"jkt": key.thumb}) {
				t.Fatal("the DPoP key was not returned", payload)
			}
			// RequireActiveAccessToken refuses inactive tokens with a challenge.
			stored := sha256.Sum256([]byte(opaque["access_token"].(string)))
			write(`UPDATE "oauthAccessToken" SET "expiresAt"=? WHERE "token"=?`, s.date(now.Add(-time.Minute)), base64.RawURLEncoding.EncodeToString(stored[:]))
			for _, token := range []string{opaque["access_token"].(string), "unknown"} {
				status, body, header := post(url.Values{"grant_type": {checkGrant}, "token": {token}, "require": {"yes"}}, "")
				if status != 401 || body["error"] != "invalid_token" || body["error_description"] != "Invalid access token" ||
					header.Get("WWW-Authenticate") != `Bearer error="invalid_token", error_description="Invalid access token"` {
					t.Fatal("an inactive token was not refused", status, body, header)
				}
			}
			if status, body, _ := post(url.Values{"grant_type": {checkGrant}, "token": {signed["access_token"].(string)}, "require": {"yes"}}, ""); status != 200 || body["payload"].(map[string]any)["active"] != true {
				t.Fatal("an active token was refused", status, body)
			}
			// An unknown caller is refused.
			if status, body, _ := post(url.Values{"grant_type": {checkGrant}, "token": {signed["access_token"].(string)}, "caller": {"missing"}}, ""); status != 400 || body["error"] != "invalid_client" {
				t.Fatal("an unknown caller was accepted", status, body)
			}
		})
	}
}
