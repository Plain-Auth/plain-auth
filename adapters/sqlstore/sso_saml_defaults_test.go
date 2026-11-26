package sqlstore

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
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
	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// A SAML directory registered without spMetadata uses its issuer as the SP
// entity ID and expected audience, and a response the IdP signed over two
// assertions is refused with saml_multiple_assertions.
func TestEnterpriseSAMLDefaults(t *testing.T) {
	idpKey, idpCert, idpPEM := samlTestCertificate(t)
	const idpBase = "https://identity.example.test"
	const idpEntity, entry, spIssuer = idpBase + "/metadata", idpBase + "/sso", "https://service.test/saml-sp"
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
			p, err := sso.New(sso.Options{SAML: &sso.SAMLOptions{}})
			must(err)
			host, err := auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", RateLimit: new(bool), Store: store, Secret: strings.Repeat("k", 32), EmailAndPassword: true, Plugins: []auth.Plugin{p}})
			must(err)
			call := func(method, path, cookie string, body any) *httptest.ResponseRecorder {
				var buf bytes.Buffer
				if body != nil {
					must(json.NewEncoder(&buf).Encode(body))
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
			signup := call("POST", "sign-up/email", "", map[string]any{"name": "Owner", "email": "owner@example.test", "password": "correct-horse-staple"})
			var owner string
			for _, c := range signup.Result().Cookies() {
				if strings.Contains(c.Name, "session_token") {
					owner = c.Name + "=" + c.Value
				}
			}
			if w := call("POST", "sso/register", owner, map[string]any{"providerId": "acme", "issuer": spIssuer, "domain": "acme.example", "samlConfig": map[string]any{"entryPoint": entry, "cert": idpPEM, "idpMetadata": map[string]any{"entityID": idpEntity}}}); w.Code != 200 {
				t.Fatal("a SAML directory without spMetadata did not register", w.Code, w.Body.String())
			}
			// A registration without any signing certificate source names it.
			if w := call("POST", "sso/register", owner, map[string]any{"providerId": "uncertified", "issuer": spIssuer, "domain": "uncertified.example", "samlConfig": map[string]any{"entryPoint": entry, "idpMetadata": map[string]any{"entityID": idpEntity}}}); w.Code != 400 || !strings.Contains(w.Body.String(), `"code":"CERT_SOURCE_MISSING"`) {
				t.Fatal("a SAML registration without a certificate source did not answer CERT_SOURCE_MISSING", w.Code, w.Body.String())
			}
			// Private keys are refused in registrations and updates, and a
			// stored row carrying one is not served.
			keyed := func(id string, edit func(cfg map[string]any)) map[string]any {
				cfg := map[string]any{"entryPoint": entry, "cert": idpPEM, "idpMetadata": map[string]any{"entityID": idpEntity}, "spMetadata": map[string]any{}}
				edit(cfg)
				return map[string]any{"providerId": id, "issuer": spIssuer, "domain": id + ".example", "samlConfig": cfg}
			}
			rows := func(id string) int {
				var n int
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "ssoProvider" WHERE "providerId"=?`), id).Scan(&n))
				return n
			}
			const keyRefusal = "SAML private keys are not accepted in a provider registration; configure the request signing and decryption keys on the server"
			for _, edit := range []func(map[string]any){
				func(cfg map[string]any) { cfg["privateKey"] = "PEM" },
				func(cfg map[string]any) { cfg["spMetadata"].(map[string]any)["encPrivateKey"] = "PEM" },
				func(cfg map[string]any) { cfg["idpMetadata"].(map[string]any)["privateKeyPass"] = "secret" },
			} {
				if w := call("POST", "sso/register", owner, keyed("keyed", edit)); w.Code != 400 || !strings.Contains(w.Body.String(), keyRefusal) || rows("keyed") != 0 {
					t.Fatal("a SAML registration carrying a private key was not refused", w.Code, w.Body.String())
				}
			}
			if w := call("POST", "sso/update-provider", owner, map[string]any{"providerId": "acme", "samlConfig": map[string]any{"spMetadata": map[string]any{"privateKey": "PEM"}}}); w.Code != 400 || !strings.Contains(w.Body.String(), keyRefusal) {
				t.Fatal("a SAML update carrying a private key was not refused", w.Code, w.Body.String())
			}
			var ownerID string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "id" FROM "user" WHERE "email"=?`), "owner@example.test").Scan(&ownerID))
			storedKey, err := json.Marshal(keyed("stored-key", func(cfg map[string]any) { cfg["spMetadata"].(map[string]any)["privateKey"] = "PEM" })["samlConfig"])
			must(err)
			_, err = store.db.ExecContext(ctx, store.bind(`INSERT INTO "ssoProvider" ("id","providerId","issuer","samlConfig","domain","userId") VALUES (?,?,?,?,?,?)`), "record-stored-key", "stored-key", spIssuer, string(storedKey), "stored-key.example", ownerID)
			must(err)
			if w := call("GET", "sso/providers", owner, nil); w.Code != 200 || strings.Contains(w.Body.String(), "stored-key") {
				t.Fatal("a stored SAML row carrying a private key was listed", w.Code, w.Body.String())
			}
			if w := call("POST", "sign-in/sso", "", map[string]any{"providerId": "stored-key", "providerType": "saml", "callbackURL": "/home"}); w.Code != 404 {
				t.Fatal("a stored SAML row carrying a private key started a sign-in", w.Code, w.Body.String())
			}
			// Each provider holds one protocol, with SAML on or off, and a
			// stored row holding both is not served.
			oidcOnly, err := sso.New(sso.Options{})
			must(err)
			oidcHost, err := auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", RateLimit: new(bool), Store: store, Secret: strings.Repeat("k", 32), Plugins: []auth.Plugin{oidcOnly}})
			must(err)
			oidcBody := map[string]any{"clientId": "application", "clientSecret": "private", "skipDiscovery": true,
				"authorizationEndpoint": "https://idp.example.test/authorize", "tokenEndpoint": "https://idp.example.test/token", "jwksEndpoint": "https://idp.example.test/keys"}
			both := keyed("both", func(cfg map[string]any) {})
			both["oidcConfig"] = oidcBody
			for _, h := range []*auth.Auth{host, oidcHost} {
				var buf bytes.Buffer
				must(json.NewEncoder(&buf).Encode(both))
				req := httptest.NewRequest("POST", "https://service.test/identity/sso/register", &buf)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", "https://service.test")
				req.Header.Set("Cookie", owner)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, req)
				if w.Code != 400 || !strings.Contains(w.Body.String(), "Register OIDC and SAML as separate providers") || rows("both") != 0 {
					t.Fatal("a registration holding both protocols was not refused", w.Code, w.Body.String())
				}
			}
			oidcJSON, err := json.Marshal(oidcBody)
			must(err)
			samlJSON, err := json.Marshal(keyed("dual", func(cfg map[string]any) {})["samlConfig"])
			must(err)
			_, err = store.db.ExecContext(ctx, store.bind(`INSERT INTO "ssoProvider" ("id","providerId","issuer","oidcConfig","samlConfig","domain","userId") VALUES (?,?,?,?,?,?,?)`), "record-dual", "dual", spIssuer, string(oidcJSON), string(samlJSON), "dual.example", ownerID)
			must(err)
			if w := call("GET", "sso/providers", owner, nil); w.Code != 200 || strings.Contains(w.Body.String(), `"dual"`) {
				t.Fatal("a stored row holding both protocols was listed", w.Code, w.Body.String())
			}
			if w := call("GET", "sso/get-provider?providerId=dual", owner, nil); w.Code != 404 {
				t.Fatal("a stored row holding both protocols was returned", w.Code, w.Body.String())
			}
			for _, kind := range []string{"oidc", "saml"} {
				if w := call("POST", "sign-in/sso", "", map[string]any{"providerId": "dual", "providerType": kind, "callbackURL": "/home"}); w.Code != 404 {
					t.Fatal("a stored row holding both protocols started a sign-in", kind, w.Code, w.Body.String())
				}
			}
			// A providerType the provider lacks names the missing protocol.
			if w := call("POST", "sso/register", owner, map[string]any{"providerId": "oidc-one", "issuer": "https://idp.example.test", "domain": "oidc.example",
				"oidcConfig": map[string]any{"clientId": "application", "clientSecret": "private", "skipDiscovery": true,
					"authorizationEndpoint": "https://idp.example.test/authorize", "tokenEndpoint": "https://idp.example.test/token", "jwksEndpoint": "https://idp.example.test/keys"}}); w.Code != 200 {
				t.Fatal("an OIDC provider did not register", w.Code, w.Body.String())
			}
			for _, c := range []struct{ provider, kind, message string }{{"acme", "oidc", "OIDC provider is not configured"}, {"oidc-one", "saml", "SAML provider is not configured"}} {
				w := call("POST", "sign-in/sso", "", map[string]any{"providerId": c.provider, "providerType": c.kind, "callbackURL": "/home"})
				if w.Code != 400 || !strings.Contains(w.Body.String(), c.message) {
					t.Fatal("a providerType the provider lacks did not name the missing protocol", c.kind, w.Code, w.Body.String())
				}
			}
			// The logout routes answer SINGLE_LOGOUT_NOT_ENABLED while single
			// logout is off, after the session check.
			if w := call("POST", "sso/saml2/logout/acme", "", map[string]any{}); w.Code != 401 {
				t.Fatal("a logout without a session did not answer 401", w.Code, w.Body.String())
			}
			for _, w := range []*httptest.ResponseRecorder{call("POST", "sso/saml2/logout/acme", owner, map[string]any{}), call("GET", "sso/saml2/sp/slo/acme", "", nil)} {
				if w.Code != 400 || !strings.Contains(w.Body.String(), `"code":"SINGLE_LOGOUT_NOT_ENABLED"`) {
					t.Fatal("a logout route did not answer SINGLE_LOGOUT_NOT_ENABLED with single logout off", w.Code, w.Body.String())
				}
			}
			w := call("GET", "sso/saml2/sp/metadata?providerId=acme", "", nil)
			var metadata saml.EntityDescriptor
			if w.Code != 200 || xml.Unmarshal(w.Body.Bytes(), &metadata) != nil || metadata.EntityID != spIssuer {
				t.Fatal("the SP metadata did not default its entity ID to the registered issuer", w.Code, metadata.EntityID)
			}
			idp := &saml.IdentityProvider{Key: idpKey, Certificate: idpCert, MetadataURL: *mustTestURL(t, idpEntity), SSOURL: *mustTestURL(t, entry),
				ServiceProviderProvider: samlTestMetadata{spIssuer: &metadata}, SignatureMethod: dsig.RSASHA256SignatureMethod}
			signUp := false
			start := func() (*saml.IdpAuthnRequest, *http.Cookie) {
				t.Helper()
				w := call("POST", "sign-in/sso", "", map[string]any{"providerId": "acme", "providerType": "saml", "callbackURL": "/home", "errorCallbackURL": "/retry", "requestSignUp": signUp})
				var started struct{ URL string }
				must(json.Unmarshal(w.Body.Bytes(), &started))
				r, err := http.NewRequest("GET", started.URL, nil)
				must(err)
				req, err := saml.NewIdpAuthnRequest(idp, r)
				must(err)
				// Validate finds the SP by the request's issuer, so read it first.
				var authn saml.AuthnRequest
				if err := xml.Unmarshal(req.RequestBuffer, &authn); err != nil || authn.Issuer == nil || authn.Issuer.Value != spIssuer {
					t.Fatal("the AuthnRequest did not name the registered issuer as its SP entity ID", authn.Issuer, err)
				}
				must(req.Validate())
				return req, w.Result().Cookies()[0]
			}
			attr := func(name, value string) saml.Attribute {
				return saml.Attribute{Name: name, Values: []saml.AttributeValue{{Value: value}}}
			}
			assertion := func(req *saml.IdpAuthnRequest, nameID string, adjust func(*saml.Assertion), attrs ...saml.Attribute) *etree.Element {
				t.Helper()
				sess := &saml.Session{ID: "idp-" + nameID, Index: "index-" + nameID, CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour), NameID: nameID, CustomAttributes: attrs}
				must((saml.DefaultAssertionMaker{}).MakeAssertion(req, sess))
				req.Assertion.Subject.NameID.Value = nameID
				if adjust != nil {
					adjust(req.Assertion)
				}
				must(req.MakeAssertionEl())
				return req.AssertionEl
			}
			asJSON := false
			// post signs a response over every assertion, as the IdP signs one
			// over a single assertion, and posts it to the ACS.
			post := func(req *saml.IdpAuthnRequest, state *http.Cookie, assertions ...*etree.Element) *httptest.ResponseRecorder {
				t.Helper()
				response := &saml.Response{Destination: req.ACSEndpoint.Location, ID: "id-" + rand.Text(), InResponseTo: req.Request.ID, IssueInstant: req.Now, Version: "2.0",
					Issuer: &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: idp.MetadataURL.String()}, Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}}}
				el := response.Element()
				for _, a := range assertions {
					el.AddChild(a)
				}
				signer := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{Certificate: [][]byte{idpCert.Raw}, PrivateKey: idpKey, Leaf: idpCert}))
				signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
				must(signer.SetSignatureMethod(dsig.RSASHA256SignatureMethod))
				signed, err := signer.SignEnveloped(el)
				must(err)
				response.Signature = signed.ChildElements()[len(signed.ChildElements())-1]
				el = response.Element()
				for _, a := range assertions {
					el.AddChild(a)
				}
				req.ResponseEl = el
				form, err := req.PostBinding()
				must(err)
				body := url.Values{"RelayState": {form.RelayState}, "SAMLResponse": {form.SAMLResponse}}
				acs := httptest.NewRequest("POST", "https://service.test/identity/sso/saml2/sp/acs/acme", strings.NewReader(body.Encode()))
				acs.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if asJSON {
					encoded, _ := json.Marshal(map[string]string{"RelayState": form.RelayState, "SAMLResponse": form.SAMLResponse})
					acs = httptest.NewRequest("POST", "https://service.test/identity/sso/saml2/sp/acs/acme", bytes.NewReader(encoded))
					acs.Header.Set("Content-Type", "application/json")
				}
				acs.Header.Set("Origin", idpBase)
				acs.Header.Set("Cookie", state.Name+"="+state.Value)
				done := httptest.NewRecorder()
				host.ServeHTTP(done, acs)
				return done
			}
			sessionCookie := func(w *httptest.ResponseRecorder) bool {
				return strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), ";"), "session_token=")
			}
			stored := func(email string) bool {
				var name string
				return store.db.QueryRowContext(ctx, store.bind(`SELECT "name" FROM "user" WHERE "email"=?`), email).Scan(&name) == nil
			}

			req, state := start()
			done := post(req, state, assertion(req, "ada", nil, attr("email", "ada@acme.example"), attr("givenName", "Ada"), attr("surname", "Lovelace"), attr("displayName", "Countess of Lovelace")))
			if done.Code != 302 || done.Header().Get("Location") != "https://service.test/home" || !sessionCookie(done) {
				t.Fatal("an assertion addressed to the default SP entity ID did not sign in", done.Code, done.Header().Get("Location"))
			}
			var name string
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "name" FROM "user" WHERE "email"=?`), "ada@acme.example").Scan(&name); err != nil || name != "Ada Lovelace" {
				t.Fatal("the new user's name did not join the first and last names", name, err)
			}

			// The SAML state lasts the five-minute request lifetime, and a
			// response after it answers 400 without a session.
			req, state = start()
			var expires time.Time
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "expiresAt" FROM "verification" WHERE "identifier" LIKE 'oauth-state:%' ORDER BY "expiresAt" DESC LIMIT 1`)).Scan(&expires))
			if left := time.Until(expires); !strings.HasSuffix(state.Name, "saml_state") || state.MaxAge != 300 || left < 4*time.Minute || left > 5*time.Minute+5*time.Second {
				t.Fatal("the SAML state did not last five minutes", state.Name, state.MaxAge, left)
			}
			_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier" LIKE 'oauth-state:%'`), store.date(time.Now().Add(-time.Minute)))
			must(err)
			if done := post(req, state, assertion(req, "late", nil, attr("email", "late@acme.example"))); done.Code != 400 || sessionCookie(done) || stored("late@acme.example") {
				t.Fatal("a SAML response after the request lifetime signed in", done.Code, done.Header().Get("Location"))
			}
			// RequestTTL sets the SAML lifetime; an OIDC attempt keeps ten minutes.
			short, err := sso.New(sso.Options{SAML: &sso.SAMLOptions{RequestTTL: 2 * time.Minute}})
			must(err)
			shortHost, err := auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", RateLimit: new(bool), Store: store, Secret: strings.Repeat("k", 32), Plugins: []auth.Plugin{short}})
			must(err)
			for _, c := range []struct {
				h        *auth.Auth
				provider string
				age      int
			}{{shortHost, "acme", 120}, {host, "oidc-one", 600}} {
				req := httptest.NewRequest("POST", "https://service.test/identity/sign-in/sso", strings.NewReader(`{"providerId":"`+c.provider+`","callbackURL":"/home"}`))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", "https://service.test")
				w := httptest.NewRecorder()
				c.h.ServeHTTP(w, req)
				cookies := w.Result().Cookies()
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "expiresAt" FROM "verification" WHERE "identifier" LIKE 'oauth-state:%' ORDER BY "expiresAt" DESC LIMIT 1`)).Scan(&expires))
				if left := time.Until(expires); w.Code != 200 || len(cookies) == 0 || cookies[0].MaxAge != c.age || left < time.Duration(c.age-60)*time.Second || left > time.Duration(c.age+5)*time.Second {
					t.Fatal("a sign-in state did not last its lifetime", c.provider, w.Code, cookies, left)
				}
			}

			req, state = start()
			done = post(req, state, assertion(req, "grace", func(a *saml.Assertion) { a.Conditions.AudienceRestrictions[0].Audience.Value = idpEntity }, attr("email", "grace@acme.example")))
			if !strings.Contains(done.Header().Get("Location"), "error=invalid_saml_response") || sessionCookie(done) || stored("grace@acme.example") {
				t.Fatal("an assertion for another audience signed in under the default SP entity ID", done.Code, done.Header().Get("Location"))
			}

			req, state = start()
			first := assertion(req, "first", nil, attr("email", "first@acme.example"))
			second := assertion(req, "intruder", nil, attr("email", "intruder@acme.example"))
			done = post(req, state, first, second)
			if location := done.Header().Get("Location"); done.Code != 302 || !strings.Contains(location, "error=saml_multiple_assertions") || sessionCookie(done) {
				t.Fatal("a response signed over two assertions signed in", done.Code, location)
			}
			if stored("first@acme.example") || stored("intruder@acme.example") {
				t.Fatal("a refused two-assertion response stored a user")
			}

			// The ACS also takes the response as JSON.
			asJSON = true
			req, state = start()
			done = post(req, state, assertion(req, "json", nil, attr("email", "json@acme.example")))
			if done.Code != 302 || done.Header().Get("Location") != "https://service.test/home" || !sessionCookie(done) {
				t.Fatal("a JSON SAML response did not sign in", done.Code, done.Header().Get("Location"))
			}
			asJSON = false
			// A GET to the ACS returns a signed-in browser to a trusted
			// RelayState, the application origin otherwise, and anyone else to
			// the error page.
			for _, c := range []struct{ cookie, relay, want string }{
				{owner, "/dashboard", "https://service.test/dashboard"},
				{owner, "https://evil.example/steal", "https://service.test/"},
				{"", "/dashboard", "https://service.test/identity/error?error=invalid_request"},
			} {
				w := call("GET", "sso/saml2/sp/acs/acme?RelayState="+url.QueryEscape(c.relay), c.cookie, nil)
				if w.Code != 302 || w.Header().Get("Location") != c.want {
					t.Fatal("a GET to the ACS did not return the browser as another runtime does", c.relay, w.Code, w.Header().Get("Location"))
				}
			}
			// requestSignUp applies to OIDC only, so DisableImplicitSignUp
			// refuses a SAML sign-up that asks for one.
			strict, err := sso.New(sso.Options{SAML: &sso.SAMLOptions{}, DisableImplicitSignUp: true})
			must(err)
			host, err = auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", RateLimit: new(bool), Store: store, Secret: strings.Repeat("k", 32), EmailAndPassword: true, Plugins: []auth.Plugin{strict}})
			must(err)
			signUp = true
			req, state = start()
			done = post(req, state, assertion(req, "newcomer", nil, attr("email", "newcomer@acme.example")))
			if location := done.Header().Get("Location"); !strings.Contains(location, "error=signup_disabled") || stored("newcomer@acme.example") {
				t.Fatal("requestSignUp let a SAML sign-up past DisableImplicitSignUp", location)
			}
			// A refused sign-in result lands on the success callback, as
			// another runtime sends it.
			if location := done.Header().Get("Location"); location != "https://service.test/home?error=signup_disabled" {
				t.Fatal("a refused SAML sign-up did not land on the success callback", location)
			}
			// JSON keys are exact, so lowercased names carry no response.
			// A case-insensitive reader would take this as an unsolicited
			// response and redirect; an exact one finds no response.
			if w := call("POST", "sso/saml2/sp/acs/acme", "", map[string]any{"samlresponse": "x"}); w.Code != 400 {
				t.Fatal("a JSON SAML response with lowercased keys was read", w.Code, w.Body.String())
			}
		})
	}
}
