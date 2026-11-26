package sqlstore

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

// A skipDiscovery registration may leave endpoints out. Sign-in discovers
// them at the start and at the callback, and never stores them.
func TestEnterpriseOIDCRuntimeDiscovery(t *testing.T) {
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
			h := newSSOHost(t, store, idp, sso.Options{})
			owner := h.signUp("owner@service.test")
			lazy := func(id, method string) map[string]any {
				cfg := map[string]any{"clientId": "enterprise-client", "clientSecret": "oidc-secret", "skipDiscovery": true, "authorizationEndpoint": idp.URL + "/authorize", "jwksEndpoint": idp.URL + "/keys"}
				if method != "" {
					cfg["tokenEndpointAuthentication"] = method
				}
				return map[string]any{"providerId": id, "issuer": idp.URL, "domain": id + ".example", "oidcConfig": cfg}
			}
			if w := h.register(owner, lazy("lazy", "client_secret_post")); w.Code != 200 {
				t.Fatal("a skipDiscovery registration without a token endpoint was refused", w.Code, w.Body.String())
			}
			if idp.discoveries.Load() != 0 {
				t.Fatal("registration fetched discovery despite skipDiscovery")
			}
			if w := h.signIn(map[string]any{"providerId": "lazy"}, "ada@lazy.example", "ada", "client_secret_post", ""); w.Header().Get("Location") != "https://service.test/home" {
				t.Fatal("runtime discovery did not complete the sign-in", w.Code, w.Header().Get("Location"), w.Body.String())
			}
			if n := idp.discoveries.Load(); n != 2 {
				t.Fatal("sign-in did not discover the missing endpoint at start and callback", n)
			}
			var raw string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "oidcConfig" FROM "ssoProvider" WHERE "providerId"=?`), "lazy").Scan(&raw))
			var stored map[string]any
			must(json.Unmarshal([]byte(raw), &stored))
			if _, has := stored["tokenEndpoint"]; has {
				t.Fatal("runtime discovery stored the discovered endpoint", raw)
			}

			// A registration without a method keeps client_secret_basic,
			// though the issuer now advertises only client_secret_post.
			idp.mu.Lock()
			idp.methods = []string{"client_secret_post"}
			idp.mu.Unlock()
			if w := h.register(owner, lazy("lazy-basic", "")); w.Code != 200 {
				t.Fatal("a skipDiscovery registration without a method was refused", w.Code, w.Body.String())
			}
			if w := h.signIn(map[string]any{"providerId": "lazy-basic"}, "lin@lazy-basic.example", "lin", "client_secret_basic", ""); w.Header().Get("Location") != "https://service.test/home" {
				t.Fatal("runtime discovery replaced the stored token endpoint authentication", w.Code, w.Header().Get("Location"))
			}

			// Runtime discovery follows the registration rules.
			refusal := func(w *httptest.ResponseRecorder) string {
				var e struct{ Code string }
				json.Unmarshal(w.Body.Bytes(), &e)
				return e.Code
			}
			untrusted := lazy("untrusted", "client_secret_post")
			untrusted["oidcConfig"].(map[string]any)["discoveryEndpoint"] = "https://idp.example.org/.well-known/openid-configuration"
			tenant := lazy("tenant", "client_secret_post")
			tenant["issuer"] = idp.URL + "/tenant"
			tenant["oidcConfig"].(map[string]any)["discoveryEndpoint"] = idp.URL + "/.well-known/openid-configuration"
			for _, body := range []map[string]any{untrusted, tenant} {
				if w := h.register(owner, body); w.Code != 200 {
					t.Fatal("registration failed", body["providerId"], w.Code, w.Body.String())
				}
			}
			fetched := idp.discoveries.Load()
			if w := h.call("POST", "sign-in/sso", "", map[string]any{"providerId": "untrusted", "callbackURL": "/home"}); w.Code != 400 || refusal(w) != "discovery_untrusted_origin" || idp.discoveries.Load() != fetched {
				t.Fatal("runtime discovery contacted an untrusted discovery origin", w.Code, w.Body.String())
			}
			if w := h.call("POST", "sign-in/sso", "", map[string]any{"providerId": "tenant", "callbackURL": "/home"}); w.Code != 400 || refusal(w) != "issuer_mismatch" {
				t.Fatal("runtime discovery accepted another issuer's document", w.Code, w.Body.String())
			}
			pending, _ := h.start(map[string]any{"providerId": "lazy"}, "noor@lazy.example", "noor", "client_secret_post", "")
			idp.mu.Lock()
			idp.discovered = map[string]any{"token_endpoint": "https://elsewhere.example.test/token"}
			idp.mu.Unlock()
			tokens := idp.tokens.Load()
			location, err := url.Parse(h.finish(pending).Header().Get("Location"))
			must(err)
			if location.Query().Get("error") != "discovery_failed" || idp.tokens.Load() != tokens {
				t.Fatal("a callback used a discovered token endpoint outside the trusted origins", location)
			}
			idp.mu.Lock()
			idp.discovered = nil
			idp.mu.Unlock()

			pending, _ = h.start(map[string]any{"providerId": "lazy"}, "grace@lazy.example", "grace", "client_secret_post", "")
			if pending.path == "" {
				t.Fatal("a sign-in with discovery available did not start")
			}
			idp.discoveryDown.Store(true)
			location, err = url.Parse(h.finish(pending).Header().Get("Location"))
			must(err)
			if location.Path != "/retry" || location.Query().Get("error") != "discovery_failed" || location.Query().Get("error_description") == "" {
				t.Fatal("a failed callback discovery did not report discovery_failed", location)
			}
			if w := h.call("POST", "sign-in/sso", "", map[string]any{"providerId": "lazy", "callbackURL": "/home"}); w.Code != 400 || refusal(w) != "discovery_not_found" {
				t.Fatal("a failed runtime discovery started a sign-in", w.Code, w.Body.String())
			}
		})
	}
}
