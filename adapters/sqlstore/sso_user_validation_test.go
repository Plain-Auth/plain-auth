package sqlstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
	"github.com/crewjam/saml"
)

// Enterprise OIDC sign-ins run ValidateUserInfo with the SSO provider ID and
// the raw claims, check a returning user again, and return a refusal to the
// error callback with error and error_description.
func TestEnterpriseOIDCUserValidation(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, e := schema.Generate(dialect, []string{"organization", "sso"})
			must(e)
			store, e := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(e)
			defer store.Close()
			idp := newSSOIssuer(t)
			var checks []auth.UserInfoValidation
			refuse := false
			p, e := sso.New(sso.Options{})
			must(e)
			host, e := auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", RateLimit: new(bool), Store: store, Secret: strings.Repeat("k", 32),
				TrustedOrigins: []string{idp.URL}, Plugins: []auth.Plugin{p},
				ValidateUserInfo: func(_ context.Context, v auth.UserInfoValidation) error {
					checks = append(checks, v)
					if refuse {
						return &auth.APIError{Code: "sso_blocked", Message: "Not allowed"}
					}
					return nil
				}})
			must(e)
			now := time.Now().UTC()
			must(store.CreateUser(ctx, auth.User{ID: "owner", Name: "Owner", Email: "owner@example.test", CreatedAt: now, UpdatedAt: now}, "credential", nil))
			pkce := true
			cfg, _ := json.Marshal(sso.Config{Issuer: idp.URL, ClientID: "enterprise-client", ClientSecret: "oidc-secret", AuthorizationEndpoint: idp.URL + "/authorize",
				TokenEndpoint: idp.URL + "/token", JWKSEndpoint: idp.URL + "/keys", TokenEndpointAuthentication: "client_secret_basic", PKCE: &pkce})
			_, e = store.db.ExecContext(ctx, store.bind(`INSERT INTO "ssoProvider" ("id","providerId","issuer","oidcConfig","domain","userId") VALUES (?,?,?,?,?,?)`),
				"record-acme", "acme", idp.URL, string(cfg), "acme.example", "owner")
			must(e)
			call := func(method, path, cookie string, body any) *httptest.ResponseRecorder {
				var buf bytes.Buffer
				if body != nil {
					json.NewEncoder(&buf).Encode(body)
				}
				req := httptest.NewRequest(method, "https://service.test/identity/"+path, &buf)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", "https://service.test")
				if cookie != "" {
					req.Header.Set("Cookie", cookie)
				}
				w := httptest.NewRecorder()
				host.ServeHTTP(w, req)
				return w
			}
			signIn := func() string {
				t.Helper()
				w := call("POST", "sign-in/sso", "", map[string]any{"providerId": "acme", "callbackURL": "/home", "errorCallbackURL": "/retry"})
				var started struct{ URL string }
				must(json.Unmarshal(w.Body.Bytes(), &started))
				u, e := url.Parse(started.URL)
				must(e)
				q := u.Query()
				code := rand.Text()
				idp.mu.Lock()
				idp.codes[code] = ssoCode{q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri"), "employee@acme.example", "employee", "client_secret_basic", ""}
				idp.mu.Unlock()
				cb, e := url.Parse(q.Get("redirect_uri"))
				must(e)
				c := w.Result().Cookies()[0]
				done := call("GET", strings.TrimPrefix(cb.Path, "/identity/")+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), c.Name+"="+c.Value, nil)
				return done.Header().Get("Location")
			}
			refuse = true
			if got := signIn(); got != "https://service.test/retry?error=sso_blocked&error_description=Not+allowed" {
				t.Fatal("a refused enterprise sign-up signed in", got)
			}
			check := checks[len(checks)-1]
			if check.Action != auth.UserInfoCreateUser || check.Method != "sso-oidc" || check.Provider != "acme" || check.Profile["sub"] != "employee" || check.User.Email != "employee@acme.example" {
				t.Fatalf("the enterprise check was %+v", check)
			}
			if _, err := store.FindAccountUser(ctx, "employee@acme.example"); err == nil {
				t.Fatal("a refused enterprise sign-up stored a user")
			}
			refuse = false
			if got := signIn(); got != "https://service.test/home" {
				t.Fatal("an admitted enterprise sign-up failed", got)
			}
			refuse = true
			if got := signIn(); !strings.Contains(got, "error=sso_blocked") {
				t.Fatal("a refused returning enterprise sign-in signed in", got)
			}
			if check := checks[len(checks)-1]; check.Action != auth.UserInfoSignIn || check.User.ID == "" {
				t.Fatalf("the returning enterprise check was %+v", check)
			}
		})
	}
}

// Enterprise SAML sign-ins run ValidateUserInfo with method sso-saml, the
// SSO provider ID and the raw assertion attributes, check a returning user
// again, and send a refusal to the error callback with error and
// error_description, storing no user or session.
func TestEnterpriseSAMLUserValidation(t *testing.T) {
	idpKey, idpCert, idpPEM := samlTestCertificate(t)
	const idpBase = "https://identity.example.test"
	idpEntity, entry, spEntity := idpBase+"/metadata", idpBase+"/sso", "https://service.test/sp"
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, e := schema.Generate(dialect, []string{"organization", "sso"})
			must(e)
			store, e := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(e)
			defer store.Close()
			var checks []auth.UserInfoValidation
			refuse := false
			p, e := sso.New(sso.Options{SAML: &sso.SAMLOptions{}})
			must(e)
			host, e := auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", RateLimit: new(bool), Store: store, Secret: strings.Repeat("k", 32),
				Plugins: []auth.Plugin{p},
				ValidateUserInfo: func(_ context.Context, v auth.UserInfoValidation) error {
					checks = append(checks, v)
					if refuse {
						return &auth.APIError{Code: "sso_blocked", Message: "Not allowed"}
					}
					return nil
				}})
			must(e)
			now := time.Now().UTC()
			must(store.CreateUser(ctx, auth.User{ID: "owner", Name: "Owner", Email: "owner@example.test", CreatedAt: now, UpdatedAt: now}, "credential", nil))
			cfg, _ := json.Marshal(sso.SAMLConfig{Issuer: idpEntity, EntryPoint: entry, Certificates: sso.Certificates{idpPEM},
				IDPMetadata: sso.SAMLIDPMetadata{EntityID: idpEntity}, SPMetadata: &sso.SAMLSPMetadata{EntityID: spEntity}})
			_, e = store.db.ExecContext(ctx, store.bind(`INSERT INTO "ssoProvider" ("id","providerId","issuer","samlConfig","domain","userId") VALUES (?,?,?,?,?,?)`),
				"record-acme", "acme", idpEntity, string(cfg), "acme.example", "owner")
			must(e)
			call := func(method, path string, body any) *httptest.ResponseRecorder {
				var buf bytes.Buffer
				if body != nil {
					json.NewEncoder(&buf).Encode(body)
				}
				req := httptest.NewRequest(method, "https://service.test/identity/"+path, &buf)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", "https://service.test")
				w := httptest.NewRecorder()
				host.ServeHTTP(w, req)
				return w
			}
			w := call("GET", "sso/saml2/sp/metadata?providerId=acme", nil)
			if w.Code != 200 {
				t.Fatal("SP metadata", w.Code, w.Body.String())
			}
			var metadata saml.EntityDescriptor
			must(xml.Unmarshal(w.Body.Bytes(), &metadata))
			idp := &saml.IdentityProvider{Key: idpKey, Certificate: idpCert, MetadataURL: *mustTestURL(t, idpEntity), SSOURL: *mustTestURL(t, entry),
				ServiceProviderProvider: samlTestMetadata{spEntity: &metadata}, SignatureMethod: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"}
			// signIn starts a SAML sign-in, has the identity provider assert
			// the employee, and posts the response to the ACS.
			signIn := func() *httptest.ResponseRecorder {
				t.Helper()
				w := call("POST", "sign-in/sso", map[string]any{"providerId": "acme", "providerType": "saml", "callbackURL": "/home", "errorCallbackURL": "/retry"})
				var started struct{ URL string }
				must(json.Unmarshal(w.Body.Bytes(), &started))
				state := w.Result().Cookies()[0]
				r, e := http.NewRequest("GET", started.URL, nil)
				must(e)
				req, e := saml.NewIdpAuthnRequest(idp, r)
				must(e)
				must(req.Validate())
				sess := &saml.Session{ID: "idp-session", Index: "idp-index", CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour), NameID: "employee",
					CustomAttributes: []saml.Attribute{{Name: "email", Values: []saml.AttributeValue{{Value: "Employee@acme.example"}}}, {Name: "displayName", Values: []saml.AttributeValue{{Value: "Local Employee"}}},
						{Name: "groups", Values: []saml.AttributeValue{{Value: "staff"}, {Value: "admins"}}}}}
				must((saml.DefaultAssertionMaker{}).MakeAssertion(req, sess))
				req.Assertion.Subject.NameID.Value = "employee"
				must(req.MakeAssertionEl())
				post, e := req.PostBinding()
				must(e)
				body := url.Values{"RelayState": {post.RelayState}, "SAMLResponse": {post.SAMLResponse}}
				acs := httptest.NewRequest("POST", "https://service.test/identity/sso/saml2/sp/acs/acme", strings.NewReader(body.Encode()))
				acs.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				acs.Header.Set("Origin", idpBase)
				acs.Header.Set("Cookie", state.Name+"="+state.Value)
				done := httptest.NewRecorder()
				host.ServeHTTP(done, acs)
				return done
			}
			count := func(query string, args ...any) int {
				t.Helper()
				var n int
				must(store.db.QueryRowContext(ctx, store.bind(query), args...).Scan(&n))
				return n
			}
			sessionCookie := func(w *httptest.ResponseRecorder) bool {
				return strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), ";"), "session_token=")
			}
			refuse = true
			done := signIn()
			if got := done.Header().Get("Location"); done.Code != 302 || got != "https://service.test/retry?error=sso_blocked&error_description=Not+allowed" {
				t.Fatal("a refused SAML sign-up answered", done.Code, got, done.Body.String())
			}
			if len(checks) != 1 {
				t.Fatal("the gate ran", len(checks), "times")
			}
			check := checks[0]
			groups, _ := check.Profile["groups"].([]any)
			if check.Action != auth.UserInfoCreateUser || check.Method != "sso-saml" || check.Provider != "acme" || check.Profile["email"] != "Employee@acme.example" ||
				check.Profile["displayName"] != "Local Employee" || len(groups) != 2 || groups[0] != "staff" || groups[1] != "admins" || check.User.Email != "employee@acme.example" {
				t.Fatalf("the SAML check was %+v", check)
			}
			if _, err := store.FindAccountUser(ctx, "employee@acme.example"); err == nil || count(`SELECT COUNT(*) FROM "session"`) != 0 || count(`SELECT COUNT(*) FROM "account" WHERE "providerId"=?`, "acme") != 0 || sessionCookie(done) {
				t.Fatal("a refused SAML sign-up stored a user, account or session")
			}
			refuse = false
			done = signIn()
			if got := done.Header().Get("Location"); got != "https://service.test/home" || len(checks) != 2 || checks[1].Action != auth.UserInfoCreateUser || count(`SELECT COUNT(*) FROM "session"`) != 1 || !sessionCookie(done) {
				t.Fatal("an admitted SAML sign-up answered", got, len(checks))
			}
			u, err := store.FindAccountUser(ctx, "employee@acme.example")
			must(err)
			refuse = true
			done = signIn()
			if got := done.Header().Get("Location"); !strings.Contains(got, "error=sso_blocked") || !strings.Contains(got, "error_description=Not+allowed") {
				t.Fatal("a refused returning SAML sign-in answered", got)
			}
			if last := checks[len(checks)-1]; len(checks) != 3 || last.Action != auth.UserInfoSignIn || last.Method != "sso-saml" || last.User.ID != u.ID || last.Profile["email"] != "Employee@acme.example" {
				t.Fatalf("the returning SAML check was %+v", last)
			}
			if count(`SELECT COUNT(*) FROM "session"`) != 1 || sessionCookie(done) {
				t.Fatal("a refused returning SAML sign-in issued a session")
			}
		})
	}
}
