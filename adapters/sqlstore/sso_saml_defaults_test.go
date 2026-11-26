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
			w := call("GET", "sso/saml2/sp/metadata?providerId=acme", "", nil)
			var metadata saml.EntityDescriptor
			if w.Code != 200 || xml.Unmarshal(w.Body.Bytes(), &metadata) != nil || metadata.EntityID != spIssuer {
				t.Fatal("the SP metadata did not default its entity ID to the registered issuer", w.Code, metadata.EntityID)
			}
			idp := &saml.IdentityProvider{Key: idpKey, Certificate: idpCert, MetadataURL: *mustTestURL(t, idpEntity), SSOURL: *mustTestURL(t, entry),
				ServiceProviderProvider: samlTestMetadata{spIssuer: &metadata}, SignatureMethod: dsig.RSASHA256SignatureMethod}
			start := func() (*saml.IdpAuthnRequest, *http.Cookie) {
				t.Helper()
				w := call("POST", "sign-in/sso", "", map[string]any{"providerId": "acme", "providerType": "saml", "callbackURL": "/home", "errorCallbackURL": "/retry"})
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
		})
	}
}
