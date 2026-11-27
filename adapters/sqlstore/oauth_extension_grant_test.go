package sqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

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
