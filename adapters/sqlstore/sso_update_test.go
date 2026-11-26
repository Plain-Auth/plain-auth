package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
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
				"authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/keys", "mapping": map[string]any{"email": "mail", "name": "n"}}})
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
			verifiedProvider := func(id string) bool {
				t.Helper()
				var p struct{ DomainVerified bool }
				w := h.call("GET", "sso/get-provider?providerId="+id, owner, nil)
				must(json.Unmarshal(w.Body.Bytes(), &p))
				return p.DomainVerified
			}
			verified := func() bool { t.Helper(); return verifiedProvider("acme") }
			lastReview := func() sso.ProviderMutation {
				mu.Lock()
				defer mu.Unlock()
				return reviewed[len(reviewed)-1]
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

			reference := func() string {
				t.Helper()
				p, err := store.FindBrowserProvider(ctx, sso.Selector{ProviderID: "acme"})
				if err != nil {
					t.Fatal(err)
				}
				return p.Reference
			}
			beforeSecret := reference()
			if w := update(owner, map[string]any{"oidcConfig": map[string]any{"clientSecret": "second-secret"}}); w.Code != 200 {
				t.Fatal("the client secret was not rotated", w.Code, w.Body.String())
			}
			// The reference leaves the client secret out, as another runtime's
			// fingerprint does, so a rotation keeps sign-ins in flight.
			if reference() != beforeSecret {
				t.Fatal("a client secret rotation changed the provider reference")
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
			beforeScopes := reference()
			if w := update(owner, map[string]any{"oidcConfig": map[string]any{"scopes": []string{"openid", "email"}, "skipDiscovery": true}}); w.Code != 200 || !verified() {
				t.Fatal("a scope update reset the domain proof", w.Code, w.Body.String())
			}
			if reference() == beforeScopes {
				t.Fatal("a scope update kept the provider reference")
			}
			w = update(owner, map[string]any{"domain": "Acme.Example, sub.acme.example"})
			var changed struct{ Domain string }
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &changed) != nil || changed.Domain != "acme.example,sub.acme.example" {
				t.Fatal("the updated domain was not normalized", w.Code, w.Body.String())
			}
			if verified() {
				t.Fatal("a domain change kept the DNS proof")
			}

			// On a second verified provider, a claim mapping change and an
			// identity change each need a fresh DNS proof.
			w = h.register(owner, map[string]any{"providerId": "beta", "issuer": idp.URL, "domain": "beta.example", "oidcConfig": map[string]any{"clientId": "enterprise-client", "clientSecret": "first-secret", "skipDiscovery": true,
				"authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/keys"}})
			var beta struct{ DomainVerificationToken string }
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &beta) != nil {
				t.Fatal("registration failed", w.Code, w.Body.String())
			}
			prove := func(token string) {
				t.Helper()
				dns.put("_plain-auth-token-beta.beta.example.", token)
				if w := h.call("POST", "sso/verify-domain", owner, map[string]any{"providerId": "beta"}); w.Code >= 300 || !verifiedProvider("beta") {
					t.Fatal("domain verification failed", w.Code, w.Body.String())
				}
			}
			challenge := func() string {
				t.Helper()
				var c struct{ DomainVerificationToken string }
				w := h.call("POST", "sso/request-domain-verification", owner, map[string]any{"providerId": "beta"})
				must(json.Unmarshal(w.Body.Bytes(), &c))
				return c.DomainVerificationToken
			}
			prove(beta.DomainVerificationToken)
			if w := h.call("POST", "sso/update-provider", owner, map[string]any{"providerId": "beta", "oidcConfig": map[string]any{"mapping": map[string]any{"email": "nickname"}}}); w.Code != 200 || verifiedProvider("beta") {
				t.Fatal("a claim mapping change kept the DNS proof", w.Code, w.Body.String())
			}
			prove(challenge())
			if w := h.call("POST", "sso/update-provider", owner, map[string]any{"providerId": "beta", "oidcConfig": map[string]any{"clientId": "other-client"}}); w.Code != 200 || verifiedProvider("beta") {
				t.Fatal("an identity change kept the DNS proof", w.Code, w.Body.String())
			}
			if m := lastReview(); !m.AuthenticationBoundaryChanged || m.LinkedAccounts != 0 {
				t.Fatal("the guard did not see the identity change", m)
			}
			prove(challenge())

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
			if m := lastReview(); m.Action != "update" || m.ProviderID != "acme" || m.ID == "" || m.Reference == "" || m.LinkedAccounts != 1 || !m.AuthenticationBoundaryChanged {
				t.Fatal("the guard did not see the linked accounts and the identity change", m)
			}
			if w := update(owner, map[string]any{"issuer": "https://other-idp.example.test"}); w.Code != 409 {
				t.Fatal("an issuer change was accepted while accounts are linked", w.Code, w.Body.String())
			}
			if w := update(owner, map[string]any{"oidcConfig": map[string]any{"scopes": []string{"openid", "email"}, "mapping": map[string]any{"name": "display"}}}); w.Code != 200 {
				t.Fatal("a scope and mapping update was refused while accounts are linked", w.Code, w.Body.String())
			}
			if _, cfg := stored(); !reflect.DeepEqual(cfg.Mapping, map[string]any{"name": "display"}) {
				t.Fatal("the supplied mapping did not replace the earlier one", cfg.Mapping)
			}
			if m := lastReview(); m.LinkedAccounts != 1 || m.AuthenticationBoundaryChanged {
				t.Fatal("the guard saw a scope and mapping update as an identity change", m)
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
			samlStored := func() sso.SAMLConfig {
				t.Helper()
				var issuer, raw string
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "issuer","samlConfig" FROM "ssoProvider" WHERE "providerId"=?`), "directory").Scan(&issuer, &raw))
				var cfg sso.SAMLConfig
				must(json.Unmarshal([]byte(raw), &cfg))
				if cfg.Issuer != issuer {
					t.Fatal("the stored SAML issuer left the provider's", issuer, cfg.Issuer)
				}
				return cfg
			}
			samlUpdate := func(patch map[string]any) *httptest.ResponseRecorder {
				return saml.call("POST", "sso/update-provider", owner, map[string]any{"providerId": "directory", "samlConfig": patch})
			}
			// An issuer change moves the default SP entity ID with it.
			if w := saml.call("POST", "sso/update-provider", owner, map[string]any{"providerId": "directory", "issuer": "https://other.example.test"}); w.Code != 200 || samlStored().Issuer != "https://other.example.test" {
				t.Fatal("an unlinked SAML directory's issuer did not change", w.Code, w.Body.String())
			}
			if w := saml.call("GET", "sso/saml2/sp/metadata?providerId=directory", "", nil); !strings.Contains(w.Body.String(), `entityID="https://other.example.test"`) {
				t.Fatal("the SP metadata did not follow the new issuer", w.Body.String())
			}
			// Each protocol's configuration applies only to its own providers.
			if w := saml.call("POST", "sso/update-provider", owner, map[string]any{"providerId": "directory", "oidcConfig": map[string]any{"scopes": []string{"openid"}}}); w.Code != 400 || !strings.Contains(w.Body.String(), "Cannot update OIDC config for a provider that doesn't have OIDC configured") {
				t.Fatal("a SAML directory accepted an OIDC update", w.Code, w.Body.String())
			}
			for _, patch := range []map[string]any{{"audience": "urn:example:audience"}, {"idpMetadata": map[string]any{"metadata": "<EntityDescriptor/>"}}} {
				if w := saml.call("POST", "sso/update-provider", owner, map[string]any{"providerId": "acme", "samlConfig": patch}); w.Code != 400 || !strings.Contains(w.Body.String(), "Cannot update SAML config for a provider that doesn't have SAML configured") {
					t.Fatal("an OIDC provider accepted a SAML update", patch, w.Code, w.Body.String())
				}
			}
			// samlConfig merges its fields under the registration checks.
			if w := samlUpdate(map[string]any{"audience": "urn:example:audience", "callbackUrl": "/landing", "mapping": map[string]any{"email": "mail"},
				"identifierFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "idpInitiatedCallbackUrl": "/portal"}); w.Code != 200 {
				t.Fatal("a SAML merge was refused", w.Code, w.Body.String())
			}
			if cfg := samlStored(); cfg.Audience != "urn:example:audience" || cfg.CallbackURL != "/landing" || cfg.Mapping.Email != "mail" || cfg.IdentifierFormat != "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" || cfg.IDPInitiatedCallbackURL != "/portal" || cfg.EntryPoint != "https://identity.example.test/sso" {
				t.Fatal("the SAML merge did not keep and change the right fields", cfg)
			}
			if w := samlUpdate(map[string]any{"idpInitiatedCallbackUrl": nil}); w.Code != 200 || samlStored().IDPInitiatedCallbackURL != "" {
				t.Fatal("a null idpInitiatedCallbackUrl did not clear it", w.Code, w.Body.String())
			}
			// With spMetadata.entityID set, an issuer change leaves the SP entity ID.
			if w := samlUpdate(map[string]any{"spMetadata": map[string]any{"entityID": "https://service.test/fixed-sp"}}); w.Code != 200 {
				t.Fatal("an SP entity ID merge was refused", w.Code, w.Body.String())
			}
			if w := saml.call("POST", "sso/update-provider", owner, map[string]any{"providerId": "directory", "issuer": "https://second.example.test"}); w.Code != 200 {
				t.Fatal("an issuer change beside a fixed SP entity ID was refused", w.Code, w.Body.String())
			}
			if w := saml.call("GET", "sso/saml2/sp/metadata?providerId=directory", "", nil); !strings.Contains(w.Body.String(), `entityID="https://service.test/fixed-sp"`) {
				t.Fatal("an issuer change moved a fixed SP entity ID", w.Body.String())
			}
			for _, c := range []struct {
				patch map[string]any
				text  string
			}{
				{map[string]any{"signatureAlgorithm": "rsa-sha1"}, "SAML_DEPRECATED_CONFIG_ALGORITHM"},
				{map[string]any{"spMetadata": map[string]any{"privateKey": "PEM"}}, "SAML private keys are not accepted"},
				{map[string]any{"unknown": true}, "Unsupported SAML update field"},
				{map[string]any{"entryPoint": nil}, "Invalid or unsupported SAML configuration"},
			} {
				if w := samlUpdate(c.patch); w.Code != 400 || !strings.Contains(w.Body.String(), c.text) {
					t.Fatal("an unusable SAML merge was not refused", c.patch, w.Code, w.Body.String())
				}
			}
			// Only the algorithms a patch names are checked against the policy.
			if w := samlUpdate(map[string]any{"digestAlgorithm": "sha384"}); w.Code != 200 {
				t.Fatal("a digest algorithm merge was refused", w.Code, w.Body.String())
			}
			narrowed := newSSOHost(t, store, idp, sso.Options{SAML: &sso.SAMLOptions{Algorithms: sso.SAMLAlgorithms{AllowedDigestAlgorithms: []sso.DigestAlgorithm{sso.DigestSHA256}}}, DomainVerification: &sso.DomainVerificationOptions{Resolver: dns}})
			if w := narrowed.call("POST", "sso/update-provider", owner, map[string]any{"providerId": "directory", "samlConfig": map[string]any{"signatureAlgorithm": "rsa-sha256"}}); w.Code != 200 {
				t.Fatal("an update naming one algorithm was refused for the stored other", w.Code, w.Body.String())
			}
			if w := narrowed.call("POST", "sso/update-provider", owner, map[string]any{"providerId": "directory", "samlConfig": map[string]any{"digestAlgorithm": "sha384"}}); w.Code != 400 || !strings.Contains(w.Body.String(), "SAML_ALGORITHM_NOT_ALLOWED") {
				t.Fatal("an update naming an algorithm outside the allow-list was accepted", w.Code, w.Body.String())
			}
			// With a linked account an identity change answers 409 and a
			// certificate rotation goes through.
			_, err = store.db.ExecContext(ctx, store.bind(`INSERT INTO "account" ("id","providerId","accountId","userId","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), "directory-linked", "directory", "employee", userID, now, now)
			must(err)
			before := samlStored()
			for _, patch := range []map[string]any{{"entryPoint": "https://identity.example.test/other"}, {"audience": "urn:other"}, {"identifierFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"},
				{"spMetadata": map[string]any{"entityID": "https://service.test/other-sp"}}, {"wantAssertionsSigned": false}} {
				if w := samlUpdate(patch); w.Code != 409 || !strings.Contains(w.Body.String(), "Cannot change SSO provider identity fields while linked accounts exist") || !reflect.DeepEqual(samlStored(), before) {
					t.Fatal("a SAML identity change was accepted while accounts are linked", patch, w.Code, w.Body.String())
				}
			}
			if w := saml.call("POST", "sso/update-provider", owner, map[string]any{"providerId": "directory", "issuer": "https://third.example.test"}); w.Code != 409 {
				t.Fatal("a SAML issuer change was accepted while accounts are linked", w.Code, w.Body.String())
			}
			_, _, rotated := samlTestCertificate(t)
			if w := samlUpdate(map[string]any{"cert": rotated}); w.Code != 200 || samlStored().Certificates[0] != rotated {
				t.Fatal("a certificate rotation was refused while accounts are linked", w.Code, w.Body.String())
			}
		})
	}
}
