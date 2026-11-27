package sqlstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

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
