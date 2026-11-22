package sqlstore

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/client"
	"github.com/Stonewrit/stonewrit-auth/plugins/sso"
	"github.com/Stonewrit/stonewrit-auth/schema"
	"github.com/crewjam/saml"
)

type samlTestMetadata map[string]*saml.EntityDescriptor

func (m samlTestMetadata) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	p := m[id]
	if p == nil {
		return nil, os.ErrNotExist
	}
	return p, nil
}
func samlTestCertificate(t *testing.T) (*rsa.PrivateKey, *x509.Certificate, string) {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local SAML signing fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return key, cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
func TestEnterpriseSAMLBrowser(t *testing.T) {
	idpKey, idpCert, idpPEM := samlTestCertificate(t)
	spKey, spCert, _ := samlTestCertificate(t)
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			ddl, e := schema.Generate(dialect, []string{"sso-domain-verification", "organization"})
			must(e)
			first, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			t.Cleanup(func() { first.Close() })
			second, e := Open(ctx, dialect, dsn)
			must(e)
			t.Cleanup(func() { second.Close() })
			var node, peer http.Handler
			app := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/sp/acs/") {
					peer.ServeHTTP(w, r)
				} else {
					node.ServeHTTP(w, r)
				}
			}))
			t.Cleanup(app.Close)
			const idpBase = "https://identity.example.test"
			idpEntity := idpBase + "/metadata"
			entry := "https://IDENTITY.example.test:443/sso"
			dns := &dnsAnswers{records: map[string][]string{}}
			host := func(s *Store) *auth.Auth {
				plug, e := sso.New(sso.Options{SAML: &sso.SAMLOptions{RequestSigner: spKey, RequestCertificate: spCert, TrustEmailVerified: true}, DomainVerification: &sso.DomainVerificationOptions{Resolver: dns}})
				must(e)
				a, e := auth.New(auth.Options{BaseURL: app.URL, BasePath: "/identity", Secret: strings.Repeat("s", 40), Store: s, RateLimit: new(bool), EmailAndPassword: true, Plugins: []auth.Plugin{plug}})
				must(e)
				return a
			}
			node, peer = host(first), host(second)
			newBrowser := func() *http.Client {
				jar, e := cookiejar.New(nil)
				must(e)
				return &http.Client{Jar: jar, Transport: app.Client().Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			}
			api := app.URL + "/identity"
			sdk := func(h *http.Client) *client.Client { c, e := client.New(api, h); must(e); return c }
			send := func(h *http.Client, method, path, kind, body, origin string) (int, http.Header, []byte) {
				t.Helper()
				r, e := http.NewRequestWithContext(ctx, method, api+path, strings.NewReader(body))
				must(e)
				if kind != "" {
					r.Header.Set("Content-Type", kind)
				}
				if origin != "" {
					r.Header.Set("Origin", origin)
				}
				res, e := h.Do(r)
				must(e)
				defer res.Body.Close()
				raw, e := io.ReadAll(res.Body)
				must(e)
				return res.StatusCode, res.Header, raw
			}
			ownerBrowser := newBrowser()
			owner := sdk(ownerBrowser)
			status, _, data := send(ownerBrowser, "POST", "/sign-up/email", "application/json", `{"name":"Owner","email":"admin@staff.example","password":"aLongLocalPassword123"}`, app.URL)
			if status != 200 {
				t.Fatal(status, string(data))
			}
			cfg := sso.SAMLConfig{SPMetadata: &sso.SAMLSPMetadata{EntityID: app.URL + "/sp"}, EntryPoint: entry, IDPMetadata: sso.SAMLIDPMetadata{EntityID: idpEntity}, Certificates: sso.Certificates{idpPEM}, AuthnRequestsSigned: true, Mapping: sso.SAMLMapping{EmailVerified: "verified"}}
			reg, e := owner.RegisterSAMLProvider(ctx, client.RegisterSAMLProviderRequest{ProviderID: "work", Domain: "staff.example", Issuer: idpEntity, SAML: cfg})
			must(e)
			if reg.RedirectURI != api+"/sso/callback/work" || reg.DomainVerificationToken == "" {
				t.Fatal("registration or challenge missing")
			}
			status, headers, data := send(newBrowser(), "GET", "/sso/saml2/sp/metadata?providerId=work", "", "", "")
			if status != 200 || headers.Get("Content-Type") != "application/xml" {
				t.Fatal(status, string(data))
			}
			var metadata saml.EntityDescriptor
			must(xml.Unmarshal(data, &metadata))
			if metadata.EntityID != cfg.SPMetadata.EntityID || len(metadata.SPSSODescriptors) != 1 || metadata.SPSSODescriptors[0].AssertionConsumerServices[0].Location != api+"/sso/saml2/sp/acs/work" || len(metadata.SPSSODescriptors[0].SingleLogoutServices) != 0 {
				t.Fatal("wrong SP metadata", string(data))
			}
			for _, k := range metadata.SPSSODescriptors[0].KeyDescriptors {
				if k.Use != "signing" {
					t.Fatal("unexpected metadata encryption key")
				}
			}
			// The remote IdP parses and validates the real Redirect signature against
			// the public SP metadata before it constructs any test assertion.
			idpURL, _ := url.Parse(idpEntity)
			ssoURL, _ := url.Parse(entry)
			idp := &saml.IdentityProvider{Key: idpKey, Certificate: idpCert, MetadataURL: *idpURL, SSOURL: *ssoURL, ServiceProviderProvider: samlTestMetadata{cfg.SPMetadata.EntityID: &metadata}, SignatureMethod: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"}
			start := func(h *http.Client) (*saml.IdpAuthnRequest, error) {
				out, e := sdk(h).SignInSSO(ctx, client.SSOSignInRequest{ProviderID: "work", ProviderType: "saml", CallbackURL: "/home", NewUserCallbackURL: "/welcome", ErrorCallbackURL: "/failed"})
				if e != nil {
					return nil, e
				}
				r, e := http.NewRequest("GET", out.URL, nil)
				if e != nil {
					return nil, e
				}
				if !out.Redirect || r.URL.Query().Get("Signature") == "" {
					return nil, errors.New("missing signed Redirect binding")
				}
				req, e := saml.NewIdpAuthnRequest(idp, r)
				if e == nil {
					e = req.Validate()
				}
				return req, e
			}
			if _, e = start(newBrowser()); e == nil {
				t.Fatal("unverified directory accepted")
			}
			token, e := owner.RequestSSODomainVerification(ctx, "work")
			must(e)
			dns.put("_stonewrit-auth-token-work.staff.example.", token)
			must(owner.VerifySSODomain(ctx, "work"))
			form := func(req *saml.IdpAuthnRequest, identity, email string, adjust func(*saml.Assertion)) url.Values {
				t.Helper()
				sess := &saml.Session{ID: "idp-session", Index: "idp-index", CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour), NameID: identity, CustomAttributes: []saml.Attribute{{Name: "email", Values: []saml.AttributeValue{{Value: email}}}, {Name: "verified", Values: []saml.AttributeValue{{Value: "true"}}}, {Name: "displayName", Values: []saml.AttributeValue{{Value: "Local Employee"}}}}}
				must((saml.DefaultAssertionMaker{}).MakeAssertion(req, sess))
				req.Assertion.Subject.NameID.Value = identity
				if adjust != nil {
					adjust(req.Assertion)
				}
				must(req.MakeAssertionEl())
				post, e := req.PostBinding()
				must(e)
				return url.Values{"RelayState": {post.RelayState}, "SAMLResponse": {post.SAMLResponse}}
			}
			post := func(h *http.Client, body url.Values, path string) (int, http.Header, []byte) {
				return send(h, "POST", path, "application/x-www-form-urlencoded", body.Encode(), idpBase)
			}
			const acs = "/sso/saml2/sp/acs/work"
			status, _, _ = send(newBrowser(), "GET", acs, "", "", "")
			if status != 404 && status != 405 {
				t.Fatal("unexpected GET assertion consumer", status)
			}
			status, _, _ = send(newBrowser(), "POST", acs, "application/json", "{}", idpBase)
			if status != 415 {
				t.Fatal("unexpected JSON assertion consumer", status)
			}
			browser := newBrowser()
			req, e := start(browser)
			must(e)
			proof := form(req, "staff-opaque-01", "worker@staff.example", nil)
			status, _, _ = post(browser, proof, "/sso/saml2/sp/acs/another-tenant")
			if status != 400 {
				t.Fatal("wrong tenant callback", status)
			}
			status, _, _ = post(newBrowser(), proof, acs)
			if status != 400 {
				t.Fatalf("foreign browser got %d", status)
			}
			status, headers, data = post(browser, proof, acs)
			if status != 302 || headers.Get("Location") != app.URL+"/home" {
				t.Fatalf("first login %d %v %s", status, headers, string(data))
			}
			status, _, data = send(browser, "GET", "/get-session", "", "", "")
			if status != 200 || !bytes.Contains(data, []byte("worker@staff.example")) || !bytes.Contains(data, []byte("Local Employee")) {
				t.Fatal(status, string(data))
			}
			status, _, _ = post(browser, proof, acs)
			if status != 400 {
				t.Fatal("reused state", status)
			}
			repeat, e := start(browser)
			must(e)
			status, headers, _ = post(browser, form(repeat, "staff-opaque-01", "worker@staff.example", nil), acs)
			if status != 302 || headers.Get("Location") != app.URL+"/home" {
				t.Fatal("repeat login", status, headers)
			}
			// Independent signed fixtures exercise the ordinary validation contracts.
			for name, adjust := range map[string]func(*saml.Assertion){
				"issuer": func(a *saml.Assertion) { a.Issuer.Value = "https://another.example.test/idp" },
				"audience": func(a *saml.Assertion) {
					a.Conditions.AudienceRestrictions[0].Audience.Value = "https://other.example.test/sp"
				},
				"recipient": func(a *saml.Assertion) {
					a.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient = api + "/elsewhere"
				},
				"request": func(a *saml.Assertion) {
					a.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = "_otherRequest"
				},
				"expiry":     func(a *saml.Assertion) { a.Conditions.NotOnOrAfter = time.Now().Add(-time.Hour) },
				"not-before": func(a *saml.Assertion) { a.Conditions.NotBefore = time.Now().Add(time.Hour) },
			} {
				t.Run(name, func(t *testing.T) {
					h := newBrowser()
					r, e := start(h)
					must(e)
					status, hd, _ := post(h, form(r, "unavailable-"+name, "invalid-"+name+"@staff.example", adjust), acs)
					if status != 302 || !strings.Contains(hd.Get("Location"), "error=invalid_saml_response") || strings.Contains(strings.Join(hd.Values("Set-Cookie"), ";"), "session_token=") {
						t.Fatal(status, hd)
					}
				})
			}
			// Existing accounts link only when both the provider's DNS proof and the
			// locally verified mailbox agree, even when the IdP attests its email.
			for _, email := range []string{"prior@staff.example", "prior@third.example"} {
				h := newBrowser()
				existing, e := sdk(h).SignUpEmail(ctx, client.SignUpRequest{Name: "Existing", Email: email, Password: "local-secret-account-123"})
				must(e)
				_, e = first.db.ExecContext(ctx, first.bind(`UPDATE "user" SET "emailVerified"=? WHERE "id"=?`), true, existing.User.ID)
				must(e)
				fresh := newBrowser()
				r, e := start(fresh)
				must(e)
				st, hd, _ := post(fresh, form(r, "existing-"+email, email, nil), acs)
				if st != 302 {
					t.Fatal(st)
				}
				if email == "prior@staff.example" {
					if hd.Get("Location") != app.URL+"/home" {
						t.Fatal("verified domain link", hd)
					}
					_, _, body := send(fresh, "GET", "/get-session", "", "", "")
					if !bytes.Contains(body, []byte(existing.User.ID)) {
						t.Fatal("identity was not linked to original account")
					}
				} else if !strings.Contains(hd.Get("Location"), "account_not_linked") {
					t.Fatal("outside tenant link", hd)
				}
			}
			h := newBrowser()
			r, e := start(h)
			must(e)
			foreignKey, foreignCert, _ := samlTestCertificate(t)
			unrelated := *idp
			unrelated.Key = foreignKey
			unrelated.Certificate = foreignCert
			r.IDP = &unrelated
			st, head, _ := post(h, form(r, "other-signer", "other@staff.example", nil), acs)
			if st != 302 || !strings.Contains(head.Get("Location"), "invalid_saml_response") {
				t.Fatal("unknown signing authority", head)
			}
			h = newBrowser()
			r, e = start(h)
			must(e)
			otherACS := *r.ACSEndpoint
			otherACS.Location = api + "/sso/saml2/sp/acs/other"
			r.ACSEndpoint = &otherACS
			st, head, _ = post(h, form(r, "other-destination", "dest@staff.example", nil), acs)
			if st != 302 || !strings.Contains(head.Get("Location"), "invalid_saml_response") {
				t.Fatal("other ACS destination", head)
			}
			// Two legitimate requests with distinct request IDs receive the same assertion
			// identifier. Exactly one login may claim the issuer's receipt.
			bs := []*http.Client{newBrowser(), newBrowser()}
			forms := make([]url.Values, 2)
			for i, b := range bs {
				r, e := start(b)
				must(e)
				forms[i] = form(r, "same-employee", "shared@staff.example", func(a *saml.Assertion) { a.ID = "_oneAssertionAcrossRequests" })
			}
			gate := make(chan struct{})
			paths := make(chan string, 2)
			for i, b := range bs {
				go func() { <-gate; _, head, _ := post(b, forms[i], acs); paths <- head.Get("Location") }()
			}
			close(gate)
			pathsOut := []string{<-paths, <-paths}
			pass, denied := 0, 0
			for _, path := range pathsOut {
				if path == app.URL+"/home" {
					pass++
				}
				if strings.Contains(path, "error=invalid_saml_response") {
					denied++
				}
			}
			if pass != 1 || denied != 1 {
				t.Fatal("assertion replay results", pathsOut)
			}
			h = newBrowser()
			r, e = start(h)
			must(e)
			staleForm := form(r, "stale-config", "outdated@staff.example", nil)
			updated := cfg
			updated.Issuer = idpEntity
			updated.Audience = app.URL + "/new-audience"
			raw, e := json.Marshal(updated)
			must(e)
			_, e = second.db.ExecContext(ctx, second.bind(`UPDATE "ssoProvider" SET "samlConfig"=? WHERE "providerId"=?`), string(raw), "work")
			must(e)
			st, head, _ = post(h, staleForm, acs)
			if st != 302 || !strings.Contains(head.Get("Location"), "error=invalid_state") {
				t.Fatal("changed provider accepted response", head)
			}
			must(owner.DeleteSSOProvider(ctx, "work"))
			var links int
			must(first.db.QueryRowContext(ctx, first.bind(`SELECT COUNT(*) FROM "account" WHERE "providerId"=?`), "work").Scan(&links))
			if links != 0 {
				t.Fatal("deleted SAML directory retained attributed account links")
			}
			_, e = first.FindAccountUser(ctx, "worker@staff.example")
			must(e)
		})
	}
}
