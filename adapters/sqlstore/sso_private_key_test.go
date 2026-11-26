package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
	jose "github.com/go-jose/go-jose/v4"
)

// A private_key_jwt provider signs each code exchange with a key the host
// resolves, and its registration needs no client secret.
func TestEnterpriseOIDCPrivateKeyJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"organization", "sso"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			idp := newSSOIssuer(t)
			idp.mu.Lock()
			idp.assertionKey = &key.PublicKey
			idp.mu.Unlock()
			var mu sync.Mutex
			var requests []sso.PrivateKeyRequest
			empty := false
			jwk, err := jose.JSONWebKey{Key: key, KeyID: "jwk-key", Algorithm: "RS384"}.MarshalJSON()
			must(err)
			// Each provider ID can resolve its own key.
			keys := map[string]sso.PrivateKey{"jwk": {JWK: jwk}, "named": {PEM: keyPEM, KeyID: "resolved", Algorithm: "PS256"}, "weakresolved": {PEM: keyPEM, Algorithm: "HS256"}}
			withKey := newSSOHost(t, store, idp, sso.Options{ResolvePrivateKey: func(_ context.Context, r sso.PrivateKeyRequest) (sso.PrivateKey, error) {
				mu.Lock()
				defer mu.Unlock()
				requests = append(requests, r)
				if r.ProviderID == "failing" {
					return sso.PrivateKey{}, errors.New("vault unavailable")
				}
				if empty {
					return sso.PrivateKey{}, nil
				}
				if k, ok := keys[r.ProviderID]; ok {
					return k, nil
				}
				return sso.PrivateKey{PEM: keyPEM}, nil
			}})
			withoutKey := newSSOHost(t, store, idp, sso.Options{})
			owner := withKey.signUp("owner@service.test")
			provider := func(id string, edit func(map[string]any)) map[string]any {
				cfg := map[string]any{"clientId": "enterprise-client", "skipDiscovery": true, "authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/keys",
					"tokenEndpointAuthentication": "private_key_jwt", "privateKeyId": "tenant-key", "privateKeyAlgorithm": "RS256"}
				if edit != nil {
					edit(cfg)
				}
				return map[string]any{"providerId": id, "issuer": idp.URL, "domain": id + ".example", "oidcConfig": cfg}
			}
			stored := func(id string) (record, user string, cfg map[string]any) {
				t.Helper()
				var raw string
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "id","userId","oidcConfig" FROM "ssoProvider" WHERE "providerId"=?`), id).Scan(&record, &user, &raw))
				must(json.Unmarshal([]byte(raw), &cfg))
				return record, user, cfg
			}
			lastAssertion := func() string {
				idp.mu.Lock()
				defer idp.mu.Unlock()
				if len(idp.assertions) == 0 {
					return ""
				}
				return idp.assertions[len(idp.assertions)-1]
			}

			if w := withoutKey.register(owner, provider("acme", nil)); w.Code != 400 || !strings.Contains(w.Body.String(), "ResolvePrivateKey") {
				t.Fatal("private_key_jwt registered without a key resolver", w.Code, w.Body.String())
			}
			if w := withKey.register(owner, provider("acme", nil)); w.Code != 200 {
				t.Fatal("private_key_jwt registration without a client secret was refused", w.Code, w.Body.String())
			}
			record, user, cfg := stored("acme")
			if cfg["privateKeyId"] != "tenant-key" || cfg["privateKeyAlgorithm"] != "RS256" {
				t.Fatal("privateKeyId was not stored", cfg)
			}
			if w := withKey.signIn(map[string]any{"providerId": "acme"}, "ada@acme.example", "ada", "private_key_jwt", ""); w.Header().Get("Location") != "https://service.test/home" {
				t.Fatal("private_key_jwt sign-in did not complete", w.Code, w.Header().Get("Location"), w.Body.String())
			}
			mu.Lock()
			last := requests[len(requests)-1]
			mu.Unlock()
			if last != (sso.PrivateKeyRequest{RecordID: record, ProviderID: "acme", UserID: user, KeyID: "tenant-key", Issuer: idp.URL}) {
				t.Fatal("ResolvePrivateKey received the wrong request", last)
			}
			if got := lastAssertion(); got != "tenant-key RS256" {
				t.Fatal("the client assertion did not carry the configured key ID", got)
			}

			if w := withKey.register(owner, provider("pss", func(c map[string]any) { c["privateKeyAlgorithm"] = "PS256"; delete(c, "privateKeyId") })); w.Code != 200 {
				t.Fatal("a PS256 private key provider was refused", w.Code, w.Body.String())
			}
			if w := withKey.signIn(map[string]any{"providerId": "pss"}, "lin@pss.example", "lin", "private_key_jwt", ""); w.Header().Get("Location") != "https://service.test/home" || lastAssertion() != " PS256" {
				t.Fatal("the client assertion was not signed with the configured algorithm", w.Header().Get("Location"), lastAssertion())
			}

			mu.Lock()
			empty = true
			mu.Unlock()
			before := idp.tokens.Load()
			if w := withKey.signIn(map[string]any{"providerId": "acme"}, "grace@acme.example", "grace", "private_key_jwt", ""); w.Header().Get("Location") != "https://service.test/retry?error=invalid_provider&error_description=no_private_key_available" {
				t.Fatal("an empty resolved key did not fail the callback", w.Code, w.Header().Get("Location"))
			}
			if idp.tokens.Load() != before {
				t.Fatal("an empty resolved key reached the token endpoint")
			}
			mu.Lock()
			empty = false
			mu.Unlock()
			if w := withoutKey.call("POST", "sign-in/sso", "", map[string]any{"providerId": "acme", "callbackURL": "/home"}); w.Code != 400 {
				t.Fatal("a host without a resolver started a private_key_jwt sign-in", w.Code, w.Body.String())
			}

			if w := withKey.register(owner, provider("weak", func(c map[string]any) { c["privateKeyAlgorithm"] = "HS256" })); w.Code != 400 {
				t.Fatal("an unsupported private key algorithm was registered", w.Code, w.Body.String())
			}
			if w := withKey.register(owner, provider("secretless", func(c map[string]any) { c["tokenEndpointAuthentication"] = "client_secret_basic" })); w.Code != 400 {
				t.Fatal("client_secret_basic registered without a client secret", w.Code, w.Body.String())
			}
			idp.mu.Lock()
			idp.methods = []string{"private_key_jwt"}
			idp.mu.Unlock()
			discovered := map[string]any{"providerId": "discovered", "issuer": idp.URL, "domain": "discovered.example", "oidcConfig": map[string]any{"clientId": "enterprise-client"}}
			if w := withKey.register(owner, discovered); w.Code != 200 {
				t.Fatal("discovery did not select private_key_jwt", w.Code, w.Body.String())
			}
			if _, _, cfg := stored("discovered"); cfg["tokenEndpointAuthentication"] != "private_key_jwt" {
				t.Fatal("discovery did not select private_key_jwt", cfg)
			}
			idp.mu.Lock()
			idp.methods = nil
			idp.mu.Unlock()

			// Both secret methods require clientSecret.
			for _, method := range []string{"client_secret_basic", "client_secret_post"} {
				if w := withKey.register(owner, provider("secretless", func(c map[string]any) { c["tokenEndpointAuthentication"] = method })); w.Code != 400 {
					t.Fatal("a secret method without clientSecret was accepted", method, w.Code, w.Body.String())
				}
			}
			// A stored client secret is never sent with an assertion.
			if w := withKey.register(owner, provider("secretkept", func(c map[string]any) { c["clientSecret"] = "oidc-secret" })); w.Code != 200 {
				t.Fatal("a private_key_jwt provider with a stored secret was refused", w.Code, w.Body.String())
			}
			if w := withKey.signIn(map[string]any{"providerId": "secretkept"}, "kim@secretkept.example", "kim", "private_key_jwt", ""); w.Header().Get("Location") != "https://service.test/home" {
				t.Fatal("a private_key_jwt sign-in sent the stored client secret", w.Code, w.Header().Get("Location"))
			}
			// The key ID and algorithm fall back to the resolved key's, then RS256.
			bare := func(c map[string]any) { delete(c, "privateKeyId"); delete(c, "privateKeyAlgorithm") }
			for id, want := range map[string]string{"jwk": "jwk-key RS384", "named": "resolved PS256", "plain": " RS256"} {
				if w := withKey.register(owner, provider(id, bare)); w.Code != 200 {
					t.Fatal("registration failed", id, w.Code, w.Body.String())
				}
				if w := withKey.signIn(map[string]any{"providerId": id}, "ada@"+id+".example", "ada-"+id, "private_key_jwt", ""); w.Header().Get("Location") != "https://service.test/home" || lastAssertion() != want {
					t.Fatal("the assertion did not take the resolved key's ID and algorithm", id, w.Header().Get("Location"), lastAssertion())
				}
			}
			// A failing resolver, or a resolved algorithm outside the list,
			// fails the callback before any token request.
			for _, id := range []string{"failing", "weakresolved"} {
				if w := withKey.register(owner, provider(id, bare)); w.Code != 200 {
					t.Fatal("registration failed", id, w.Code, w.Body.String())
				}
				before := idp.tokens.Load()
				if w := withKey.signIn(map[string]any{"providerId": id}, "ada@"+id+".example", "ada-"+id, "private_key_jwt", ""); w.Header().Get("Location") != "https://service.test/retry?error=invalid_provider&error_description=no_private_key_available" || idp.tokens.Load() != before {
					t.Fatal("an unusable resolved key did not fail the callback", id, w.Header().Get("Location"))
				}
			}
			// The resolver sees the provider's organization.
			now := store.date(time.Now())
			_, err = store.db.ExecContext(ctx, store.bind(`INSERT INTO "organization" ("id","name","slug","createdAt") VALUES (?,?,?,?)`), "tenant", "Tenant", "tenant", now)
			must(err)
			_, err = store.db.ExecContext(ctx, store.bind(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,?,?,?,?)`), "owner-member", "tenant", user, "owner", now)
			must(err)
			org := provider("orgkey", nil)
			org["organizationId"] = "tenant"
			if w := withKey.register(owner, org); w.Code != 200 {
				t.Fatal("an organization's private_key_jwt provider was refused", w.Code, w.Body.String())
			}
			withKey.signIn(map[string]any{"providerId": "orgkey"}, "lin@orgkey.example", "lin-org", "private_key_jwt", "")
			mu.Lock()
			last = requests[len(requests)-1]
			mu.Unlock()
			if last.ProviderID != "orgkey" || last.OrganizationID != "tenant" {
				t.Fatal("ResolvePrivateKey did not receive the provider's organization", last)
			}
		})
	}
}
