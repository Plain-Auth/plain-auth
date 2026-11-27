package sqlstore

import (
	"context"
	"database/sql"
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

// Server code creates clients with administrator settings: consent
// skipping, end session, PKCE, machine scopes and metadata are stored,
// assigning machine scopes and linking requested resources each need their
// own approval, and the response always names the machine scopes.
func TestAdminClientCreation(t *testing.T) {
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
			var denyScopes bool
			opts := op.Options{Scopes: []string{"openid", "reports"}, Registration: op.RegistrationOptions{DefaultResources: []string{"urn:reports"}},
				Resources: []op.ResourceDefinition{{Identifier: "urn:reports"}, {Identifier: "urn:billing"}},
				ClientPrivileges: func(_ context.Context, a op.ClientAccess) (bool, error) {
					return a.Action != "configure-client-credentials-scopes" || !denyScopes, nil
				}}
			p, err := op.New(opts)
			must(err)
			const origin = "https://admin.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("d", 40), Store: s, EmailAndPassword: true, PasswordHash: testPasswordHash, PasswordVerify: testPasswordVerify, Plugins: []auth.Plugin{p}, RateLimit: &off})
			must(err)
			owner, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
			must(err)
			signed, err := owner.SignUpEmail(ctx, client.SignUpRequest{Name: "Admin", Email: "admin@admin.test", Password: "local admin test password"})
			must(err)
			headers := http.Header{"Cookie": {h.SessionCookie(*signed.Token, true).String()}}
			manager, err := op.NewClientManager(h, s, opts)
			must(err)
			var denyLink bool
			resources, err := op.NewResourceManager(h, s, op.ResourceManagerOptions{Resources: opts.Resources,
				Privileges: func(_ context.Context, a op.ResourceAccess) (bool, error) {
					return a.Action != "link" || !denyLink, nil
				}})
			must(err)
			yes, no := true, false
			machine := op.ClientCreation{RegistrationMetadata: op.RegistrationMetadata{GrantTypes: []string{"client_credentials"}, TokenEndpointAuthMethod: "client_secret_post"},
				ClientCredentialsScopes: []string{" reports ", "reports"}, Metadata: map[string]json.RawMessage{"tier": json.RawMessage(`"gold"`), "clientSecret": json.RawMessage(`"x"`)}}
			// Machine scopes need the configure privilege.
			denyScopes = true
			if _, err := manager.CreateClient(ctx, headers, machine); err == nil || err.Error() != http.StatusText(401) {
				t.Fatal("machine scopes were assigned without approval", err)
			}
			denyScopes = false
			if _, err := manager.CreateClient(ctx, nil, machine); err == nil {
				t.Fatal("a client was created without a session")
			}
			created, err := manager.CreateClient(ctx, headers, machine)
			must(err)
			raw, err := json.Marshal(created)
			must(err)
			if !strings.Contains(string(raw), `"client_credentials_scopes":["reports"]`) || !strings.Contains(string(raw), `"tier":"gold"`) || strings.Contains(string(raw), `"clientSecret"`) || created.ClientSecret == "" {
				t.Fatal("the administrative response lost the machine scopes", string(raw))
			}
			var storedScopes, metadata sql.NullString
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "clientCredentialsScopes","metadata" FROM "oauthClient" WHERE "clientId"=?`), created.ClientID).Scan(&storedScopes, &metadata))
			if !sameJSON(storedScopes.String, `["reports"]`) || !sameJSON(metadata.String, `{"tier":"gold"}`) {
				t.Fatal("the machine scopes or metadata were not stored", storedScopes, metadata)
			}
			// The machine client gets a token for its scope.
			form := url.Values{"grant_type": {"client_credentials"}, "client_id": {created.ClientID}, "client_secret": {created.ClientSecret}}
			req := httptest.NewRequest("POST", origin+"/api/auth/oauth2/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			if out.Code != 200 || !strings.Contains(out.Body.String(), `"scope":"reports"`) {
				t.Fatal("the created machine client could not get a token", out.Code, out.Body.String())
			}
			for _, tc := range []struct {
				in   op.ClientCreation
				want string
			}{
				{op.ClientCreation{RegistrationMetadata: op.RegistrationMetadata{GrantTypes: []string{"client_credentials"}, TokenEndpointAuthMethod: "none"}, ClientCredentialsScopes: []string{"reports"}}, "public clients cannot be assigned client_credentials scopes"},
				{op.ClientCreation{RegistrationMetadata: op.RegistrationMetadata{RedirectURIs: []string{"https://app.example.test/cb"}}, ClientCredentialsScopes: []string{"reports"}}, "client_credentials_scopes requires the client_credentials grant"},
				{op.ClientCreation{RegistrationMetadata: op.RegistrationMetadata{GrantTypes: []string{"client_credentials"}}, ClientCredentialsScopes: []string{"openid"}}, "The following client_credentials scopes are invalid: openid"},
				{op.ClientCreation{RegistrationMetadata: op.RegistrationMetadata{GrantTypes: []string{"client_credentials"}}, ClientCredentialsScopes: []string{" "}}, "[body.client_credentials_scopes.0] Too small: expected string to have >=1 characters"},
			} {
				var oauth *auth.OAuthError
				var api *auth.APIError
				if _, err := manager.CreateClient(ctx, headers, tc.in); !(errors.As(err, &oauth) && oauth.Description == tc.want || errors.As(err, &api) && api.Message == tc.want) {
					t.Fatal("machine scopes were not checked", tc.want, err)
				}
			}
			// A browser client keeps its administrator settings, and its
			// default resources are linked.
			app, err := manager.CreateClient(ctx, headers, op.ClientCreation{RegistrationMetadata: op.RegistrationMetadata{RedirectURIs: []string{"https://app.example.test/cb"}},
				SkipConsent: &yes, EnableEndSession: &yes, RequirePKCE: &no})
			must(err)
			var skip, end, pkce sql.NullBool
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "skipConsent","enableEndSession","requirePKCE" FROM "oauthClient" WHERE "clientId"=?`), app.ClientID).Scan(&skip, &end, &pkce))
			if !skip.Bool || !end.Bool || !pkce.Valid || pkce.Bool || app.RequirePKCE == nil || *app.RequirePKCE {
				t.Fatal("the administrator settings were not stored", skip, end, pkce)
			}
			links := func(id string) int {
				var n int
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "oauthClientResource" WHERE "clientId"=?`), id).Scan(&n))
				return n
			}
			if links(app.ClientID) != 1 {
				t.Fatal("the default resource was not linked", links(app.ClientID))
			}
			// Requested resources need WithResources and its link privilege.
			linked := op.ClientCreation{RegistrationMetadata: op.RegistrationMetadata{RedirectURIs: []string{"https://app.example.test/cb"}, Resources: []string{"urn:billing"}}}
			if _, err := manager.CreateClient(ctx, headers, linked); err == nil || !strings.Contains(err.Error(), "requires ClientManager.WithResources") {
				t.Fatal("a resource was linked without the resource manager", err)
			}
			denyLink = true
			if _, err := manager.WithResources(resources).CreateClient(ctx, headers, linked); err == nil {
				t.Fatal("a resource was linked without the link privilege")
			}
			denyLink = false
			withLinks, err := manager.WithResources(resources).CreateClient(ctx, headers, linked)
			must(err)
			if links(withLinks.ClientID) != 2 {
				t.Fatal("the requested and default resources were not both linked", links(withLinks.ClientID))
			}
			// UpdateClient changes the administrator settings and metadata,
			// and a disabled client gets no tokens until it is enabled again.
			token := func() int {
				req := httptest.NewRequest("POST", origin+"/api/auth/oauth2/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				return out.Code
			}
			// The response names the stored machine scopes the update kept.
			if disabled, err := manager.UpdateClient(ctx, headers, created.ClientID, op.ClientAdminUpdate{Disabled: &yes}); err != nil || token() == 200 || !slices.Equal(disabled.ClientCredentialsScopes, []string{"reports"}) {
				t.Fatal("a disabled client still got a token or lost its machine scopes", err, disabled.ClientCredentialsScopes)
			}
			if _, err := manager.UpdateClient(ctx, headers, created.ClientID, op.ClientAdminUpdate{Disabled: &no}); err != nil || token() != 200 {
				t.Fatal("an enabled client got no token", err)
			}
			updated, err := manager.UpdateClient(ctx, headers, app.ClientID, op.ClientAdminUpdate{Fields: map[string]any{"client_name": "Admin named"},
				SkipConsent: &no, Metadata: map[string]json.RawMessage{"tier": json.RawMessage(`"silver"`), "userId": json.RawMessage(`"x"`)}})
			must(err)
			var name, meta sql.NullString
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "name","metadata","skipConsent" FROM "oauthClient" WHERE "clientId"=?`), app.ClientID).Scan(&name, &meta, &skip))
			if name.String != "Admin named" || !sameJSON(meta.String, `{"tier":"silver"}`) || skip.Bool || updated.SkipConsent == nil || *updated.SkipConsent {
				t.Fatal("the administrator update was not stored", name, meta, skip)
			}
			if raw, err := json.Marshal(updated); err != nil || !strings.Contains(string(raw), `"tier":"silver"`) {
				t.Fatal("the update response lost the metadata", string(raw), err)
			}
			// Machine scopes for a client left without the grant are refused.
			var problem *auth.OAuthError
			if _, err := manager.UpdateClient(ctx, headers, created.ClientID, op.ClientAdminUpdate{Fields: map[string]any{"grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://app.example.test/cb"}},
				ClientCredentialsScopes: []string{"reports"}}); !errors.As(err, &problem) || problem.Description != "client_credentials_scopes requires the client_credentials grant" {
				t.Fatal("machine scopes were accepted for a client without the grant", err)
			}
			// With DisableJWTPlugin, a created client's secret is stored
			// encrypted, so the token endpoint accepts it.
			hsOpts := op.Options{Scopes: []string{"openid", "reports"}, DisableJWTPlugin: true, ClientPrivileges: func(context.Context, op.ClientAccess) (bool, error) { return true, nil }}
			hsPlugin, err := op.New(hsOpts)
			must(err)
			hs, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("d", 40), Store: s, EmailAndPassword: true, PasswordHash: testPasswordHash, PasswordVerify: testPasswordVerify, Plugins: []auth.Plugin{hsPlugin}, RateLimit: &off})
			must(err)
			hsManager, err := op.NewClientManager(hs, s, hsOpts)
			must(err)
			hsClient, err := hsManager.CreateClient(ctx, headers, op.ClientCreation{RegistrationMetadata: op.RegistrationMetadata{GrantTypes: []string{"client_credentials"}, TokenEndpointAuthMethod: "client_secret_post"},
				ClientCredentialsScopes: []string{"reports"}})
			must(err)
			hsForm := url.Values{"grant_type": {"client_credentials"}, "client_id": {hsClient.ClientID}, "client_secret": {hsClient.ClientSecret}}
			hsReq := httptest.NewRequest("POST", origin+"/api/auth/oauth2/token", strings.NewReader(hsForm.Encode()))
			hsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			hsOut := httptest.NewRecorder()
			hs.ServeHTTP(hsOut, hsReq)
			var hsSecret string
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "clientSecret" FROM "oauthClient" WHERE "clientId"=?`), hsClient.ClientID).Scan(&hsSecret))
			if hsOut.Code != 200 || !strings.HasPrefix(hsSecret, "authn.v1.") {
				t.Fatal("a client created with DisableJWTPlugin could not authenticate or was not stored encrypted", hsOut.Code, hsOut.Body.String())
			}
			if _, err := op.NewClientManager(hs, s, op.Options{DisableJWTPlugin: true, Registration: op.RegistrationOptions{SecretStorage: "hashed"}}); err == nil {
				t.Fatal("a client manager accepted hashed secrets with DisableJWTPlugin")
			}
			// A scopes-only update goes through SetClientCredentialsScopes.
			if scoped, err := manager.UpdateClient(ctx, headers, created.ClientID, op.ClientAdminUpdate{ClientCredentialsScopes: []string{}}); err != nil || len(scoped.ClientCredentialsScopes) != 0 {
				t.Fatal("a scopes-only update did not clear the machine scopes", scoped.ClientCredentialsScopes, err)
			}
		})
	}
}
