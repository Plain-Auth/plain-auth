package sqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// An extension authentication method: a client registered for it gets no
// secret, and authenticates at the token, introspection and revocation
// endpoints with a client assertion its strategy proves, before any store
// call and with each endpoint's URL as the audience. A refused assertion,
// a mismatched client_id and a mismatched registered method are refused, the
// last two with 400 invalid_client as for private_key_jwt,
// and discovery lists the method on all three endpoints.
func TestExtensionClientAuthentication(t *testing.T) {
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
			const assertionType = "urn:test:assertion"
			var mu sync.Mutex
			var audiences []string
			strategy := op.ClientAuthenticationStrategy{AssertionTypes: []string{assertionType}, Authenticate: func(ctx context.Context, in op.ClientAuthenticationInput) (op.ClientAuthenticationResult, error) {
				mu.Lock()
				audiences = append(audiences, in.ExpectedAudience)
				mu.Unlock()
				id, ok := strings.CutPrefix(in.Assertion, "assertion:")
				if !ok {
					return op.ClientAuthenticationResult{}, &auth.OAuthError{Status: 401, Code: "invalid_client", Description: "bad assertion"}
				}
				// The strategy may read the same store: it runs outside any transaction.
				if _, err := s.LookupOAuthClient(ctx, id); err != nil && err != op.ErrClientNotFound {
					return op.ClientAuthenticationResult{}, err
				}
				return op.ClientAuthenticationResult{ClientID: id}, nil
			}}
			opts := op.Options{Scopes: []string{"reports"}, Extensions: []op.Extension{{ClientAuthentication: map[string]op.ClientAuthenticationStrategy{"assertion": strategy}}},
				ClientPrivileges: func(context.Context, op.ClientAccess) (bool, error) { return true, nil }}
			p, err := op.New(opts)
			must(err)
			const origin = "https://assert.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("x", 40), Store: s, EmailAndPassword: true, PasswordHash: testPasswordHash, PasswordVerify: testPasswordVerify, Plugins: []auth.Plugin{p}, RateLimit: &off})
			must(err)
			owner, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
			must(err)
			_, err = owner.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@assert.test", Password: "local assertion password"})
			must(err)
			// A client registered for the method gets no secret.
			registered, err := owner.CreateOAuthClient(ctx, op.RegistrationMetadata{GrantTypes: []string{"client_credentials"}, TokenEndpointAuthMethod: "assertion"})
			must(err)
			if registered.ClientSecret != "" || registered.TokenEndpointAuthMethod != "assertion" {
				t.Fatal("a client registered for the extension method got a secret", registered)
			}
			id := registered.ClientID
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "oauthClient" SET "clientCredentialsScopes"=? WHERE "clientId"=?`), `["reports"]`, id)
			must(err)
			post := func(path string, form url.Values, header http.Header) (int, map[string]any, http.Header) {
				t.Helper()
				req := httptest.NewRequest("POST", origin+"/api/auth"+path, strings.NewReader(form.Encode()))
				req.Header = header.Clone()
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				var body map[string]any
				_ = json.Unmarshal(out.Body.Bytes(), &body)
				return out.Code, body, out.Header()
			}
			assertion := func(form url.Values, value string) url.Values {
				form.Set("client_assertion_type", assertionType)
				form.Set("client_assertion", value)
				return form
			}
			status, body, _ := post("/oauth2/token", assertion(url.Values{"grant_type": {"client_credentials"}}, "assertion:"+id), http.Header{})
			if status != 200 || body["scope"] != "reports" {
				t.Fatal("the extension assertion did not authenticate the client", status, body)
			}
			token := body["access_token"].(string)
			if status, body, _ := post("/oauth2/introspect", assertion(url.Values{"token": {token}}, "assertion:"+id), http.Header{}); status != 200 || body["active"] != true {
				t.Fatal("introspection refused the extension assertion", status, body)
			}
			if status, body, _ := post("/oauth2/revoke", assertion(url.Values{"token": {token}}, "assertion:"+id), http.Header{}); status != 200 {
				t.Fatal("revocation refused the extension assertion", status, body)
			}
			mu.Lock()
			seen := slices.Clone(audiences)
			mu.Unlock()
			if !slices.Equal(seen, []string{origin + "/api/auth/oauth2/token", origin + "/api/auth/oauth2/introspect", origin + "/api/auth/oauth2/revoke"}) {
				t.Fatal("the strategy did not see each endpoint as the audience", seen)
			}
			// Refusals.
			if status, body, header := post("/oauth2/token", assertion(url.Values{"grant_type": {"client_credentials"}}, "forged"), http.Header{}); status != 401 || body["error"] != "invalid_client" || header.Get("WWW-Authenticate") == "" {
				t.Fatal("a refused assertion was not 401 invalid_client", status, body)
			}
			if status, body, _ := post("/oauth2/token", assertion(url.Values{"grant_type": {"client_credentials"}, "client_id": {"other"}}, "assertion:"+id), http.Header{}); status != 400 || body["error"] != "invalid_client" {
				t.Fatal("a mismatched client_id was accepted", status, body)
			}
			// The pairing, repetition and one-method rules apply before the strategy runs.
			mu.Lock()
			calls := len(audiences)
			mu.Unlock()
			for description, form := range map[string]url.Values{
				"client_assertion and client_assertion_type must both be provided": {"grant_type": {"client_credentials"}, "client_assertion_type": {assertionType}},
				"client_assertion must not be repeated":                            {"grant_type": {"client_credentials"}, "client_assertion_type": {assertionType}, "client_assertion": {"assertion:" + id, "assertion:" + id}},
				"A request must use only one client authentication method":         assertion(url.Values{"grant_type": {"client_credentials"}, "client_secret": {"secret"}}, "assertion:"+id),
			} {
				if status, body, _ := post("/oauth2/token", form, http.Header{}); status == 200 || body["error_description"] != description {
					t.Fatal("a malformed extension assertion was not refused", description, status, body)
				}
			}
			if status, body, _ := post("/oauth2/token", assertion(url.Values{"grant_type": {"client_credentials"}}, "assertion:"+id), http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(id+":secret"))}}); status != 400 || body["error_description"] != "A request must use only one client authentication method" {
				t.Fatal("an extension assertion with Basic was accepted", status, body)
			}
			mu.Lock()
			strategyCalls := len(audiences)
			mu.Unlock()
			if strategyCalls != calls {
				t.Fatal("the strategy ran for a malformed request", strategyCalls, calls)
			}
			if status, body, _ := post("/oauth2/token", url.Values{"grant_type": {"client_credentials"}}, http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(id+":secret"))}}); status != 401 || !strings.Contains(body["error_description"].(string), "cannot use client_secret_basic") {
				t.Fatal("Basic was accepted for an extension client", status, body)
			}
			secretClient, err := owner.CreateOAuthClient(ctx, op.RegistrationMetadata{GrantTypes: []string{"client_credentials"}})
			must(err)
			if status, body, _ := post("/oauth2/token", assertion(url.Values{"grant_type": {"client_credentials"}}, "assertion:"+secretClient.ClientID), http.Header{}); status != 400 || !strings.Contains(body["error_description"].(string), "cannot use assertion") {
				t.Fatal("the extension assertion was accepted for a secret client", status, body)
			}
			// Discovery lists the method on every endpoint.
			doc, err := op.GetAuthorizationServerConfig(h)
			must(err)
			for name, list := range map[string][]string{"token": doc.TokenEndpointAuthMethods, "introspection": doc.IntrospectionEndpointAuthMethods, "revocation": doc.RevocationEndpointAuthMethods} {
				if !slices.Contains(list, "assertion") {
					t.Fatal("discovery did not list the extension method", name, list)
				}
			}
		})
	}
}

// A strategy that calls ConsumeClientAssertion binds the audience and
// bounds the lifetime before it spends each jti once: a second token
// request with it is refused with 400 invalid_client, another pool on the
// same database sees the spend, and the same jti for another client is
// accepted. The provider still refuses an unregistered client.
func TestExtensionAssertionReplay(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			other, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { other.Close() })
			const assertionType = "urn:test:assertion"
			// The strategy trusts the payload as if its signature were verified.
			strategy := op.ClientAuthenticationStrategy{AssertionTypes: []string{assertionType}, Authenticate: func(ctx context.Context, in op.ClientAuthenticationInput) (op.ClientAuthenticationResult, error) {
				var claims struct {
					Sub string `json:"sub"`
				}
				payload := []byte(in.Assertion)
				if err := json.Unmarshal(payload, &claims); err != nil {
					return op.ClientAuthenticationResult{}, &auth.OAuthError{Status: 401, Code: "invalid_client", Description: "bad assertion"}
				}
				if err := in.ConsumeClientAssertion(ctx, "urn:test:"+claims.Sub, payload); err != nil {
					return op.ClientAuthenticationResult{}, err
				}
				return op.ClientAuthenticationResult{ClientID: claims.Sub}, nil
			}}
			p, err := op.New(op.Options{Scopes: []string{"reports"}, Extensions: []op.Extension{{ClientAuthentication: map[string]op.ClientAuthenticationStrategy{"assertion": strategy}}}})
			must(err)
			const origin = "https://replay.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("y", 40), Store: s, Plugins: []auth.Plugin{p}, RateLimit: &off})
			must(err)
			for _, id := range []string{"one", "two"} {
				_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO "oauthClient" ("id","clientId","tokenEndpointAuthMethod","redirectUris","grantTypes","clientCredentialsScopes") VALUES (?,?,'assertion','[]',?,?)`),
					id, id, `["client_credentials"]`, `["reports"]`)
				must(err)
			}
			tokenURL := origin + "/api/auth/oauth2/token"
			exchangeWith := func(client, jti string, overrides map[string]any) (int, map[string]any) {
				t.Helper()
				payload := map[string]any{"sub": client, "aud": tokenURL, "exp": time.Now().Unix() + 60, "jti": jti}
				for k, v := range overrides {
					payload[k] = v
				}
				claims, _ := json.Marshal(payload)
				form := url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {assertionType}, "client_assertion": {string(claims)}}
				req := httptest.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				var body map[string]any
				_ = json.Unmarshal(out.Body.Bytes(), &body)
				return out.Code, body
			}
			exchange := func(client, jti string) (int, map[string]any) {
				t.Helper()
				return exchangeWith(client, jti, nil)
			}
			// The audience and lifetime are checked before the jti is spent.
			now := time.Now().Unix()
			for description, overrides := range map[string]map[string]any{
				"client assertion aud does not match the endpoint":         {"aud": origin + "/api/auth/oauth2/introspect"},
				"client assertion has expired":                             {"exp": now - 61},
				"client assertion exp is too far in the future (max 300s)": {"exp": now + 400},
				"client assertion iat is too far in the past (max 300s)":   {"iat": now - 400},
			} {
				if status, body := exchangeWith("one", "first", overrides); status != 400 || body["error"] != "invalid_client" || body["error_description"] != description {
					t.Fatal("a bad assertion was not refused", description, status, body)
				}
			}
			// The provider still refuses a client it will not authorize.
			if status, body := exchange("three", "unregistered"); status != 400 || body["error"] != "invalid_client" || body["error_description"] != "client not found" {
				t.Fatal("an unregistered client was authenticated", status, body)
			}
			if status, body := exchange("one", "first"); status != 200 {
				t.Fatal("the first assertion was refused", status, body)
			}
			if status, body := exchange("one", "first"); status != 400 || body["error"] != "invalid_client" || body["error_description"] != "client assertion jti has already been used" {
				t.Fatal("a replayed assertion was accepted", status, body)
			}
			if status, body := exchange("two", "first"); status != 200 {
				t.Fatal("the same jti for another client was refused", status, body)
			}
			// Another pool sees the spend, and its own spend is seen here.
			digest := func(namespace, jti string) string {
				sum := sha256.Sum256([]byte(namespace + ":" + jti))
				return base64.RawURLEncoding.EncodeToString(sum[:24])
			}
			expires := time.Now().Add(time.Minute)
			if err := other.ReserveOAuthClientAssertion(ctx, digest("urn:test:one", "first"), expires); err != op.ErrAssertionReplay {
				t.Fatal("another pool did not see the spend", err)
			}
			must(other.ReserveOAuthClientAssertion(ctx, digest("urn:test:one", "second"), expires))
			if status, body := exchange("one", "second"); status != 400 || body["error_description"] != "client assertion jti has already been used" {
				t.Fatal("a spend from another pool was not seen", status, body)
			}
		})
	}
}
