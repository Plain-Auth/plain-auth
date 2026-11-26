package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"sync"
	"testing"

	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
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
			ddl, err := schema.Generate(dialect, []string{"sso"})
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
			withKey := newSSOHost(t, store, idp, sso.Options{ResolvePrivateKey: func(_ context.Context, r sso.PrivateKeyRequest) (sso.PrivateKey, error) {
				mu.Lock()
				defer mu.Unlock()
				requests = append(requests, r)
				if empty {
					return sso.PrivateKey{}, nil
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
		})
	}
}
