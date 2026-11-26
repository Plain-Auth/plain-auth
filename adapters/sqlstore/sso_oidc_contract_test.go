package sqlstore

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
	"golang.org/x/oauth2"
)

// OIDC providers request their stored scopes or the default set, refuse an
// ID token for another client, refuse reserved authorization parameters and
// social provider IDs, require clientId and store overrideUserInfo updates,
// as another runtime does.
func TestEnterpriseOIDCContract(t *testing.T) {
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
			social := auth.OAuthProvider{Config: oauth2.Config{ClientID: "client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{AuthURL: "https://id.example.test/authorize", TokenURL: "https://id.example.test/token"}},
				Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) {
					return auth.OAuthProfile{}, nil
				}}
			h := newSSOHost(t, store, idp, sso.Options{SAML: &sso.SAMLOptions{}}, func(o *auth.Options) { o.SocialProviders = map[string]auth.OAuthProvider{"github": social} })
			owner := h.signUp("owner@service.test")
			oidc := func(extra map[string]any) map[string]any {
				cfg := map[string]any{"clientId": "enterprise-client", "clientSecret": "oidc-secret", "skipDiscovery": true, "authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/keys"}
				for k, v := range extra {
					cfg[k] = v
				}
				return cfg
			}
			register := func(id string, cfg map[string]any) int {
				t.Helper()
				return h.register(owner, map[string]any{"providerId": id, "issuer": idp.URL, "domain": id + ".example", "oidcConfig": cfg}).Code
			}
			if register("plain", oidc(nil)) != 200 || register("groups", oidc(map[string]any{"scopes": []string{"openid", "email", "groups"}})) != 200 {
				t.Fatal("an OIDC registration was refused")
			}
			// Without request scopes a sign-in asks for the stored ones or the default set.
			for id, want := range map[string]string{"plain": "openid email profile offline_access", "groups": "openid email groups"} {
				w := h.call("POST", "sign-in/sso", "", map[string]any{"providerId": id, "callbackURL": "/home"})
				var started struct{ URL string }
				must(json.Unmarshal(w.Body.Bytes(), &started))
				u, err := url.Parse(started.URL)
				must(err)
				if got := u.Query().Get("scope"); got != want {
					t.Fatal("a sign-in asked for the wrong scopes", id, got, want)
				}
			}
			// With PKCE off the authorization carries no challenge and the
			// exchange no verifier.
			if register("nopkce", oidc(map[string]any{"pkce": false})) != 200 {
				t.Fatal("a registration with PKCE off was refused")
			}
			w := h.call("POST", "sign-in/sso", "", map[string]any{"providerId": "nopkce", "callbackURL": "/home"})
			var started struct{ URL string }
			must(json.Unmarshal(w.Body.Bytes(), &started))
			if u, err := url.Parse(started.URL); err != nil || u.Query().Has("code_challenge") || u.Query().Has("code_challenge_method") {
				t.Fatal("a PKCE-off authorization carried a challenge", started.URL)
			}
			if done := h.signIn(map[string]any{"providerId": "nopkce"}, "kai@nopkce.example", "kai", "client_secret_basic", ""); done.Header().Get("Location") != "https://service.test/home" {
				t.Fatal("a PKCE-off sign-in failed or sent a verifier", done.Code, done.Header().Get("Location"))
			}
			// An ID token for another client is refused.
			idp.mu.Lock()
			idp.claims = map[string]map[string]any{"other-audience": {"aud": "other-client"}}
			idp.mu.Unlock()
			if location, _ := url.Parse(h.signIn(map[string]any{"providerId": "plain"}, "ada@plain.example", "ada", "client_secret_basic", "other-audience").Header().Get("Location")); location == nil || location.Path != "/retry" || location.Query().Get("error") != "invalid_provider" {
				t.Fatal("an ID token for another client was accepted", location)
			}
			var read map[string]any
			must(json.Unmarshal(h.call("GET", "sso/get-provider?providerId=plain", owner, nil).Body.Bytes(), &read))
			if cfg, _ := read["oidcConfig"].(map[string]any); cfg == nil || cfg["clientIdLastFour"] != "****ient" || cfg["clientId"] != nil {
				t.Fatal("the provider read did not mask the client ID to its last four characters", read)
			}
			// Reserved authorization parameters, and any on SAML, are refused.
			for _, params := range []map[string]any{{"client_id": "x"}, {"redirect_uri": "https://elsewhere.example/cb"}} {
				if w := h.call("POST", "sign-in/sso", "", map[string]any{"providerId": "plain", "callbackURL": "/home", "additionalParams": params}); w.Code != 400 {
					t.Fatal("a reserved authorization parameter was accepted", params, w.Code, w.Body.String())
				}
			}
			_, _, idpPEM := samlTestCertificate(t)
			if w := h.register(owner, map[string]any{"providerId": "directory", "issuer": "https://identity.example.test/metadata", "domain": "directory.example", "samlConfig": map[string]any{
				"entryPoint": "https://identity.example.test/sso", "cert": idpPEM, "idpMetadata": map[string]any{"entityID": "https://identity.example.test/metadata"}}}); w.Code != 200 {
				t.Fatal("a SAML registration was refused", w.Code, w.Body.String())
			}
			if w := h.call("POST", "sign-in/sso", "", map[string]any{"providerId": "directory", "providerType": "saml", "callbackURL": "/home", "additionalParams": map[string]any{"prompt": "login"}}); w.Code != 400 || !strings.Contains(w.Body.String(), "additionalParams is not supported for SAML providers") {
				t.Fatal("additionalParams was accepted for a SAML sign-in", w.Code, w.Body.String())
			}
			// A social provider's ID is reserved in any case, and clientId is required.
			if w := h.register(owner, map[string]any{"providerId": "GitHub", "issuer": idp.URL, "domain": "github.example", "oidcConfig": oidc(nil)}); w.Code != 422 {
				t.Fatal("a social provider's ID was registered in another case", w.Code, w.Body.String())
			}
			noClient := oidc(nil)
			delete(noClient, "clientId")
			if code := register("noclient", noClient); code != 400 {
				t.Fatal("a registration without clientId was accepted", code)
			}
			// update-provider stores overrideUserInfo.
			if w := h.call("POST", "sso/update-provider", owner, map[string]any{"providerId": "plain", "oidcConfig": map[string]any{"overrideUserInfo": true}}); w.Code != 200 {
				t.Fatal("an overrideUserInfo update was refused", w.Code, w.Body.String())
			}
			var raw string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "oidcConfig" FROM "ssoProvider" WHERE "providerId"=?`), "plain").Scan(&raw))
			var stored sso.Config
			must(json.Unmarshal([]byte(raw), &stored))
			if !stored.OverrideUserInfo {
				t.Fatal("update-provider did not store overrideUserInfo", raw)
			}
		})
	}
}

// With SharedCallback every OIDC provider returns to /sso/callback, the
// per-provider callback still answers a stateless return with a state error,
// and SAML directories keep their own ACS, as another runtime does with its
// shared redirectURI.
func TestEnterpriseOIDCSharedCallback(t *testing.T) {
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
			h := newSSOHost(t, store, idp, sso.Options{SharedCallback: true, SAML: &sso.SAMLOptions{}})
			owner := h.signUp("owner@service.test")
			w := h.register(owner, map[string]any{"providerId": "staff", "issuer": idp.URL, "domain": "staff.example", "oidcConfig": map[string]any{"clientId": "enterprise-client", "clientSecret": "oidc-secret", "skipDiscovery": true,
				"authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/keys"}})
			var registered struct{ RedirectURI string }
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &registered) != nil || registered.RedirectURI != "https://service.test/identity/sso/callback" {
				t.Fatal("a shared-callback registration did not return the shared redirect URI", w.Code, registered.RedirectURI)
			}
			if done := h.call("GET", "sso/callback/staff?code=stray", "", nil); done.Code != 302 || !strings.Contains(done.Header().Get("Location"), "error=state_not_found") {
				t.Fatal("a stateless per-provider return did not answer with a state error", done.Code, done.Header().Get("Location"))
			}
			_, _, idpPEM := samlTestCertificate(t)
			if w := h.register(owner, map[string]any{"providerId": "directory", "issuer": "https://identity.example.test/metadata", "domain": "directory.example", "samlConfig": map[string]any{
				"entryPoint": "https://identity.example.test/sso", "cert": idpPEM, "idpMetadata": map[string]any{"entityID": "https://identity.example.test/metadata"}}}); w.Code != 200 {
				t.Fatal("a SAML registration was refused", w.Code, w.Body.String())
			}
			if w := h.call("GET", "sso/saml2/sp/metadata?providerId=directory", "", nil); !strings.Contains(w.Body.String(), `Location="https://service.test/identity/sso/saml2/sp/acs/directory"`) {
				t.Fatal("SharedCallback changed a SAML directory's ACS", w.Body.String())
			}
		})
	}
}
