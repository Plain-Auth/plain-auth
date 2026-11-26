package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

// A manager changes a provider's issuer, domain and OIDC configuration; an
// identity change is refused while accounts are linked, and only a new
// domain or identity resets the DNS proof.
func TestEnterpriseProviderUpdate(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"sso-domain-verification"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			idp := newSSOIssuer(t)
			dns := &dnsAnswers{records: map[string][]string{}}
			var mu sync.Mutex
			var reviewed []sso.ProviderMutation
			refuse := false
			guard := func(_ context.Context, m sso.ProviderMutation) error {
				mu.Lock()
				defer mu.Unlock()
				reviewed = append(reviewed, m)
				if refuse {
					return errors.New("change freeze")
				}
				return nil
			}
			h := newSSOHost(t, store, idp, sso.Options{DomainVerification: &sso.DomainVerificationOptions{Resolver: dns}, GuardProviderMutation: guard})
			owner := h.signUp("owner@service.test")
			w := h.register(owner, map[string]any{"providerId": "acme", "issuer": idp.URL, "domain": "acme.example", "oidcConfig": map[string]any{"clientId": "enterprise-client", "clientSecret": "first-secret", "skipDiscovery": true,
				"authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/keys"}})
			var registered struct{ DomainVerificationToken string }
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &registered) != nil || registered.DomainVerificationToken == "" {
				t.Fatal("registration failed", w.Code, w.Body.String())
			}
			dns.put("_plain-auth-token-acme.acme.example.", registered.DomainVerificationToken)
			if w := h.call("POST", "sso/verify-domain", owner, map[string]any{"providerId": "acme"}); w.Code >= 300 {
				t.Fatal("domain verification failed", w.Code, w.Body.String())
			}
			update := func(cookie string, body map[string]any) *httptest.ResponseRecorder {
				body["providerId"] = "acme"
				return h.call("POST", "sso/update-provider", cookie, body)
			}
			verified := func() bool {
				t.Helper()
				var p struct{ DomainVerified bool }
				w := h.call("GET", "sso/get-provider?providerId=acme", owner, nil)
				must(json.Unmarshal(w.Body.Bytes(), &p))
				return p.DomainVerified
			}
			stored := func() (issuer string, cfg sso.Config) {
				t.Helper()
				var raw string
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "issuer","oidcConfig" FROM "ssoProvider" WHERE "providerId"=?`), "acme").Scan(&issuer, &raw))
				must(json.Unmarshal([]byte(raw), &cfg))
				return issuer, cfg
			}
			code := func(w *httptest.ResponseRecorder) string {
				var e struct{ Code, Message string }
				json.Unmarshal(w.Body.Bytes(), &e)
				return e.Code + ":" + e.Message
			}
			if !verified() {
				t.Fatal("the registered domain was not verified")
			}

			if w := update(owner, map[string]any{"oidcConfig": map[string]any{"clientSecret": "second-secret"}}); w.Code != 200 {
				t.Fatal("the client secret was not rotated", w.Code, w.Body.String())
			}
			if _, cfg := stored(); cfg.ClientSecret != "second-secret" {
				t.Fatal("the client secret was not rotated", cfg.ClientSecret)
			}
			if !verified() {
				t.Fatal("a secret rotation reset the domain proof")
			}
			mu.Lock()
			last := reviewed[len(reviewed)-1]
			mu.Unlock()
			if last.Action != "update" || last.AuthenticationBoundaryChanged || last.LinkedAccounts != 0 || last.ProviderID != "acme" {
				t.Fatal("the guard did not review the secret rotation", last)
			}
			if w := update(owner, map[string]any{"oidcConfig": map[string]any{"scopes": []string{"openid", "email"}, "skipDiscovery": true}}); w.Code != 200 || !verified() {
				t.Fatal("a scope update reset the domain proof", w.Code, w.Body.String())
			}
			w = update(owner, map[string]any{"domain": "Acme.Example, sub.acme.example"})
			var changed struct{ Domain string }
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &changed) != nil || changed.Domain != "acme.example,sub.acme.example" {
				t.Fatal("the updated domain was not normalized", w.Code, w.Body.String())
			}
			if verified() {
				t.Fatal("a domain change kept the DNS proof")
			}

			var userID string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "id" FROM "user" WHERE "email"=?`), "owner@service.test").Scan(&userID))
			now := store.date(time.Now())
			_, err = store.db.ExecContext(ctx, store.bind(`INSERT INTO "account" ("id","providerId","accountId","userId","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), "linked", "acme", "subject", userID, now, now)
			must(err)
			if w := update(owner, map[string]any{"oidcConfig": map[string]any{"clientId": "other-client"}}); w.Code != 409 || code(w) != ":Cannot change SSO provider identity fields while linked accounts exist" {
				t.Fatal("an identity change was accepted while accounts are linked", w.Code, w.Body.String())
			}
			if _, cfg := stored(); cfg.ClientID != "enterprise-client" {
				t.Fatal("an identity change was accepted while accounts are linked", cfg.ClientID)
			}
			if w := update(owner, map[string]any{"issuer": "https://other-idp.example.test"}); w.Code != 409 {
				t.Fatal("an issuer change was accepted while accounts are linked", w.Code, w.Body.String())
			}
			if w := update(owner, map[string]any{"oidcConfig": map[string]any{"scopes": []string{"openid", "email"}, "mapping": map[string]any{"name": "display"}}}); w.Code != 200 {
				t.Fatal("a scope and mapping update was refused while accounts are linked", w.Code, w.Body.String())
			}
			if _, cfg := stored(); cfg.Mapping["name"] != "display" {
				t.Fatal("the supplied mapping was not stored", cfg.Mapping)
			}
			mu.Lock()
			refuse = true
			mu.Unlock()
			if w := update(owner, map[string]any{"oidcConfig": map[string]any{"pkce": false}}); w.Code != 409 || code(w) != "SSO_PROVIDER_MUTATION_REJECTED:SSO provider mutation is not allowed" {
				t.Fatal("a rejected update was stored", w.Code, w.Body.String())
			}
			if _, cfg := stored(); cfg.PKCE == nil || !*cfg.PKCE {
				t.Fatal("a rejected update was stored", cfg.PKCE)
			}
			mu.Lock()
			refuse = false
			mu.Unlock()

			for name, body := range map[string]map[string]any{
				"private token endpoint": {"oidcConfig": map[string]any{"tokenEndpoint": "https://127.0.0.1/token"}},
				"unknown OIDC field":     {"oidcConfig": map[string]any{"nickname": "x"}},
				"empty endpoint":         {"oidcConfig": map[string]any{"jwksEndpoint": ""}},
				"null scopes":            {"oidcConfig": map[string]any{"scopes": nil}},
				"unknown field":          {"name": "Acme"},
				"no change":              {},
				"invalid mapping":        {"oidcConfig": map[string]any{"mapping": map[string]any{"nickname": "x"}}},
			} {
				if w := update(owner, body); w.Code != 400 {
					t.Fatal("an invalid update was accepted", name, w.Code, w.Body.String())
				}
			}
			if w := update(owner, map[string]any{"oidcConfig": map[string]any{"tokenEndpoint": "https://127.0.0.1/token"}}); code(w) != "discovery_private_host:An internal identity provider endpoint needs an explicitly trusted origin" {
				t.Fatal("an update to a private token endpoint was accepted", w.Code, w.Body.String())
			}
			if w := update(h.signUp("other@service.test"), map[string]any{"oidcConfig": map[string]any{"clientSecret": "stolen"}}); w.Code != 403 {
				t.Fatal("another user updated the provider", w.Code, w.Body.String())
			}
			if issuer, cfg := stored(); issuer != idp.URL || cfg.ClientSecret != "second-secret" || cfg.Issuer != idp.URL {
				t.Fatal("a refused update changed the provider", issuer, cfg)
			}

			sdk, err := client.New("https://service.test/identity", &http.Client{Transport: guestTransport{h.a}})
			must(err)
			_, err = sdk.SignInEmail(ctx, client.SignInRequest{Email: "owner@service.test", Password: "correct-horse-staple"})
			must(err)
			if _, err := sdk.UpdateSSOProvider(ctx, client.UpdateSSOProviderRequest{ProviderID: "acme", OIDC: map[string]any{"clientSecret": "third-secret"}}); err != nil {
				t.Fatal("the native client could not rotate the client secret", err)
			}
			if _, cfg := stored(); cfg.ClientSecret != "third-secret" {
				t.Fatal("the native client could not rotate the client secret", cfg.ClientSecret)
			}

			// A SAML directory's domain changes through the same route; its
			// issuer and OIDC fields do not.
			_, _, idpPEM := samlTestCertificate(t)
			saml := newSSOHost(t, store, idp, sso.Options{SAML: &sso.SAMLOptions{}, DomainVerification: &sso.DomainVerificationOptions{Resolver: dns}})
			if w := saml.register(owner, map[string]any{"providerId": "directory", "issuer": "https://identity.example.test/metadata", "domain": "directory.example", "samlConfig": map[string]any{
				"entryPoint": "https://identity.example.test/sso", "cert": idpPEM, "idpMetadata": map[string]any{"entityID": "https://identity.example.test/metadata"}}}); w.Code != 200 {
				t.Fatal("SAML registration failed", w.Code, w.Body.String())
			}
			if w := saml.call("POST", "sso/update-provider", owner, map[string]any{"providerId": "directory", "domain": "Directory.Example,other.example"}); w.Code != 200 {
				t.Fatal("a SAML directory's domain was not updated", w.Code, w.Body.String())
			}
			var domain string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "domain" FROM "ssoProvider" WHERE "providerId"=?`), "directory").Scan(&domain))
			if domain != "directory.example,other.example" {
				t.Fatal("a SAML directory's domain was not updated", domain)
			}
			for _, body := range []map[string]any{{"providerId": "directory", "issuer": "https://other.example.test"}, {"providerId": "directory", "oidcConfig": map[string]any{"scopes": []string{"openid"}}}} {
				if w := saml.call("POST", "sso/update-provider", owner, body); w.Code != 400 {
					t.Fatal("a SAML directory accepted an issuer or OIDC update", w.Code, w.Body.String())
				}
			}
		})
	}
}
