package sqlstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

// An enterprise OIDC return checks its stored callbacks with the callback
// request's own trusted origins. A callback that request no longer trusts
// sends the browser to BaseURL, or a failure to the error page, instead of
// failing after the sign-in.
func TestEnterpriseOIDCRequestOrigins(t *testing.T) {
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	ddl, err := schema.Generate("sqlite", []string{"organization", "sso"})
	must(err)
	store, err := OpenWithSchema(ctx, "sqlite", organizationTestDSN(t, "sqlite"), ddl)
	must(err)
	defer store.Close()
	idp := newSSOIssuer(t)
	refuse := false
	p, err := sso.New(sso.Options{})
	must(err)
	host, err := auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", RateLimit: new(bool), Store: store, Secret: strings.Repeat("k", 32),
		TrustedOrigins: []string{idp.URL, "myapp://"}, Plugins: []auth.Plugin{p},
		TrustedOriginsForRequest: func(r *http.Request) ([]string, error) {
			if r.Header.Get("X-Tenant") == "one" {
				return []string{"https://one.example"}, nil
			}
			return nil, nil
		},
		ValidateUserInfo: func(context.Context, auth.UserInfoValidation) error {
			if refuse {
				return &auth.APIError{Code: "sso_blocked", Message: "Not allowed"}
			}
			return nil
		}})
	must(err)
	now := time.Now().UTC()
	must(store.CreateUser(ctx, auth.User{ID: "owner", Name: "Owner", Email: "owner@example.test", CreatedAt: now, UpdatedAt: now}, "credential", nil))
	pkce := true
	cfg, _ := json.Marshal(sso.Config{Issuer: idp.URL, ClientID: "enterprise-client", ClientSecret: "oidc-secret", AuthorizationEndpoint: idp.URL + "/authorize",
		TokenEndpoint: idp.URL + "/token", JWKSEndpoint: idp.URL + "/keys", TokenEndpointAuthentication: "client_secret_basic", PKCE: &pkce})
	_, err = store.db.ExecContext(ctx, store.bind(`INSERT INTO "ssoProvider" ("id","providerId","issuer","oidcConfig","domain","userId") VALUES (?,?,?,?,?,?)`),
		"record-acme", "acme", idp.URL, string(cfg), "acme.example", "owner")
	must(err)
	call := func(method, path, tenant, cookie string, body any) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		if body != nil {
			json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, "https://service.test/identity/"+path, &buf)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://service.test")
		if tenant != "" {
			req.Header.Set("X-Tenant", tenant)
		}
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		w := httptest.NewRecorder()
		host.ServeHTTP(w, req)
		return w
	}
	// The sign-in starts on the tenant's request and returns on another.
	tenantCallbacks := map[string]any{"callbackURL": "https://one.example/home", "errorCallbackURL": "https://one.example/retry"}
	signInTo := func(callbacks map[string]any, returnTenant string) (string, bool) {
		t.Helper()
		body := map[string]any{"providerId": "acme"}
		maps.Copy(body, callbacks)
		w := call("POST", "sign-in/sso", "one", "", body)
		var started struct{ URL string }
		must(json.Unmarshal(w.Body.Bytes(), &started))
		u, err := url.Parse(started.URL)
		must(err)
		q := u.Query()
		code := rand.Text()
		idp.mu.Lock()
		idp.codes[code] = ssoCode{q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri"), "employee@acme.example", "employee", "client_secret_basic", ""}
		idp.mu.Unlock()
		cb, err := url.Parse(q.Get("redirect_uri"))
		must(err)
		c := w.Result().Cookies()[0]
		done := call("GET", strings.TrimPrefix(cb.Path, "/identity/")+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), returnTenant, c.Name+"="+c.Value, nil)
		if done.Code != http.StatusFound {
			t.Fatalf("the enterprise return answered %d: %s", done.Code, done.Body)
		}
		return done.Header().Get("Location"), strings.Contains(strings.Join(done.Header().Values("Set-Cookie"), "\n"), "session_token=")
	}
	signIn := func(returnTenant string) (string, bool) { return signInTo(tenantCallbacks, returnTenant) }
	if got, session := signIn("one"); got != "https://one.example/home" || !session {
		t.Fatal("a trusted enterprise return went to", got, session)
	}
	if got, session := signIn(""); got != "https://service.test" || !session {
		t.Fatal("an untrusted enterprise return went to", got, session)
	}
	refuse = true
	if got, _ := signIn("one"); got != "https://one.example/retry?error=sso_blocked&error_description=Not+allowed" {
		t.Fatal("a trusted enterprise failure went to", got)
	}
	if got, _ := signIn(""); got != "https://service.test/identity/error?error=sso_blocked&error_description=Not+allowed" {
		t.Fatal("an untrusted enterprise failure went to", got)
	}
	// A failure keeps the "//" of an app deep link.
	if got, _ := signInTo(map[string]any{"callbackURL": "myapp://"}, ""); got != "myapp://?error=sso_blocked&error_description=Not+allowed" {
		t.Fatal("an enterprise failure for a deep link went to", got)
	}
}

// An exact origin TrustedOriginsForRequest returns lets that request's OIDC
// discovery, endpoint checks and identity provider requests reach it, as
// another runtime's trusted origins function does. A wildcard pattern, an
// origin returned for another route and a SAML endpoint gain nothing.
func TestEnterpriseOIDCRequestTrustedEndpoints(t *testing.T) {
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
			// grant maps a route prefix to the origins returned for it.
			var grant map[string]string
			trust := func(o *auth.Options) {
				o.TrustedOrigins = nil
				o.TrustedOriginsForRequest = func(r *http.Request) ([]string, error) {
					path := strings.TrimPrefix(r.URL.Path, "/identity/")
					for prefix, origin := range grant {
						if strings.HasPrefix(path, prefix) {
							return []string{origin}, nil
						}
					}
					return nil, nil
				}
			}
			h := newSSOHost(t, store, idp, sso.Options{SAML: &sso.SAMLOptions{}}, trust)
			owner := h.signUp("owner@service.test")
			refusal := func(w *httptest.ResponseRecorder) string {
				var e struct{ Code string }
				json.Unmarshal(w.Body.Bytes(), &e)
				return e.Code
			}
			discovered := map[string]any{"providerId": "acme", "issuer": idp.URL, "domain": "acme.example", "oidcConfig": map[string]any{"clientId": "enterprise-client", "clientSecret": "oidc-secret"}}
			for _, g := range []map[string]string{nil, {"sso/register": "http://127.0.0.1:*"}, {"sign-in/sso": idp.URL}} {
				grant = g
				if w := h.register(owner, discovered); w.Code != 400 || refusal(w) != "discovery_untrusted_origin" || idp.discoveries.Load() != 0 {
					t.Fatal("registration discovery reached an issuer the request did not trust", g, w.Code, w.Body.String())
				}
			}
			// A supplied private endpoint is named before the discovery trust check.
			for field, value := range map[string]string{"discoveryEndpoint": idp.URL + "/.well-known/openid-configuration", "tokenEndpoint": "http://169.254.169.254/token"} {
				body := map[string]any{"providerId": "supplied", "issuer": "https://idp.example.org", "domain": "supplied.example", "oidcConfig": map[string]any{"clientId": "enterprise-client", "clientSecret": "oidc-secret", field: value}}
				if w := h.register(owner, body); w.Code != 400 || refusal(w) != "discovery_private_host" {
					t.Fatal("a supplied private endpoint was not refused as private", field, w.Code, w.Body.String())
				}
			}
			grant = map[string]string{"sso/register": idp.URL}
			if w := h.register(owner, discovered); w.Code != 200 {
				t.Fatal("registration discovery refused an origin the request trusted", w.Code, w.Body.String())
			}
			var raw string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "oidcConfig" FROM "ssoProvider" WHERE "providerId"=?`), "acme").Scan(&raw))
			var stored sso.Config
			must(json.Unmarshal([]byte(raw), &stored))
			if stored.TokenEndpoint != idp.URL+"/token" || stored.JWKSEndpoint != idp.URL+"/keys" {
				t.Fatal("registration did not store the discovered endpoints", raw)
			}

			// Sign-in checks the stored endpoints and discovers a missing one
			// with the sign-in request's origins.
			lazy := map[string]any{"providerId": "lazy", "issuer": idp.URL, "domain": "lazy.example", "oidcConfig": map[string]any{"clientId": "enterprise-client", "clientSecret": "oidc-secret", "skipDiscovery": true,
				"authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token"}}
			if w := h.register(owner, lazy); w.Code != 200 {
				t.Fatal("a skipDiscovery registration was refused", w.Code, w.Body.String())
			}
			grant = nil
			for id, code := range map[string]string{"acme": "discovery_private_host", "lazy": "discovery_untrusted_origin"} {
				if w := h.call("POST", "sign-in/sso", "", map[string]any{"providerId": id, "callbackURL": "/home"}); w.Code != 400 || refusal(w) != code {
					t.Fatal("a sign-in used endpoints the request did not trust", id, w.Code, w.Body.String())
				}
			}
			untrusted := `The main discovery endpoint \"` + idp.URL + `/.well-known/openid-configuration\" is not trusted by your trusted origins configuration.`
			if w := h.call("POST", "sign-in/sso", "", map[string]any{"providerId": "lazy", "callbackURL": "/home"}); !strings.Contains(w.Body.String(), untrusted) {
				t.Fatal("an untrusted discovery origin did not name it as another runtime does", w.Body.String())
			}
			// A discovery URL derived from the issuer is checked only when
			// it is fetched.
			public := map[string]any{"providerId": "public", "issuer": idp.URL, "domain": "public.example", "oidcConfig": map[string]any{"clientId": "enterprise-client", "clientSecret": "oidc-secret", "skipDiscovery": true,
				"authorizationEndpoint": "https://idp.example.org/authorize", "tokenEndpoint": "https://idp.example.org/token", "jwksEndpoint": "https://idp.example.org/keys"}}
			if w := h.register(owner, public); w.Code != 200 {
				t.Fatal("a skipDiscovery registration with public endpoints was refused for its issuer", w.Code, w.Body.String())
			}
			grant = map[string]string{"sign-in/sso": idp.URL}
			if w := h.call("POST", "sign-in/sso", "", map[string]any{"providerId": "lazy", "callbackURL": "/home"}); w.Code != 200 {
				t.Fatal("a sign-in refused endpoints the request trusted", w.Code, w.Body.String())
			}

			// The callback's token and key requests follow the callback
			// request's origins.
			pending, w := h.start(map[string]any{"providerId": "acme"}, "ada@acme.example", "ada", "client_secret_basic", "")
			if pending.path == "" {
				t.Fatal("a trusted sign-in did not start", w.Code, w.Body.String())
			}
			tokens := idp.tokens.Load()
			done := h.finish(pending)
			if location, _ := url.Parse(done.Header().Get("Location")); location == nil || location.Path != "/retry" || location.Query().Get("error") != "discovery_failed" || location.Query().Get("error_description") == "" ||
				idp.tokens.Load() != tokens || strings.Contains(strings.Join(done.Header().Values("Set-Cookie"), "\n"), "session_token=") {
				t.Fatal("a callback reached a token endpoint its request did not trust", done.Code, done.Header().Get("Location"))
			}
			grant = map[string]string{"sign-in/sso": idp.URL, "sso/callback": idp.URL}
			if done := h.signIn(map[string]any{"providerId": "acme"}, "ada@acme.example", "ada", "client_secret_basic", ""); done.Header().Get("Location") != "https://service.test/home" {
				t.Fatal("a callback refused a token endpoint its request trusted", done.Code, done.Header().Get("Location"))
			}

			// update-provider checks a new endpoint with its own origins.
			update := map[string]any{"providerId": "acme", "oidcConfig": map[string]any{"tokenEndpoint": idp.URL + "/token"}}
			grant = map[string]string{"sso/register": idp.URL}
			if w := h.call("POST", "sso/update-provider", owner, update); w.Code != 400 || refusal(w) != "discovery_private_host" {
				t.Fatal("update-provider stored an endpoint the request did not trust", w.Code, w.Body.String())
			}
			grant = map[string]string{"sso/update-provider": idp.URL}
			if w := h.call("POST", "sso/update-provider", owner, update); w.Code != 200 {
				t.Fatal("update-provider refused an endpoint the request trusted", w.Code, w.Body.String())
			}

			// SAML endpoints follow TrustedOrigins only.
			_, _, idpPEM := samlTestCertificate(t)
			grant = map[string]string{"sso/register": idp.URL}
			if w := h.register(owner, map[string]any{"providerId": "directory", "issuer": idp.URL + "/metadata", "domain": "directory.example", "samlConfig": map[string]any{
				"entryPoint": idp.URL + "/saml", "cert": idpPEM, "idpMetadata": map[string]any{"entityID": idp.URL + "/metadata"}}}); w.Code != 400 {
				t.Fatal("a SAML endpoint gained a per-request trusted origin", w.Code, w.Body.String())
			}
		})
	}
}
