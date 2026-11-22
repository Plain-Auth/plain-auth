package sqlstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/client"
	"github.com/Stonewrit/stonewrit-auth/plugins/sso"
	"github.com/Stonewrit/stonewrit-auth/schema"
	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/xmlenc"
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
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local SAML signing fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
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
func TestEnterpriseSAMLBrowser(t *testing.T)          { runEnterpriseSAMLBrowser(t, false, false) }
func TestEnterpriseSAMLEncryptedBrowser(t *testing.T) { runEnterpriseSAMLBrowser(t, true, false) }
func TestEnterpriseSAMLSingleLogout(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "signed"
		if encrypted {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) { runEnterpriseSAMLBrowser(t, encrypted, true) })
	}
}
func runEnterpriseSAMLBrowser(t *testing.T, encrypted, logout bool) {
	idpKey, idpCert, idpPEM := samlTestCertificate(t)
	spKey, spCert, _ := samlTestCertificate(t)
	encKey, encCert, _ := samlTestCertificate(t)
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
				if strings.Contains(r.URL.Path, "/sp/acs/") || strings.Contains(r.URL.Path, "/sp/slo/") {
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
			var reviewed atomic.Pointer[sso.SAMLDirectory]
			portalPolicy := func(_ context.Context, d sso.SAMLDirectory) (bool, error) {
				expected := reviewed.Load()
				return expected != nil && *expected == d, nil
			}
			host := func(s *Store, encryption *sso.SAMLEncryption, policy sso.SAMLDirectoryPolicy, disableSignup bool) *auth.Auth {
				plug, e := sso.New(sso.Options{DisableImplicitSignUp: disableSignup, SAML: &sso.SAMLOptions{EnableSingleLogout: logout, EnableIDPInitiatedLogout: logout, AllowIDPInitiated: policy, IDPInitiatedCallbackURL: "/global-portal", Encryption: encryption, RequestSigner: spKey, RequestCertificate: spCert, TrustEmailVerified: true}, DomainVerification: &sso.DomainVerificationOptions{Resolver: dns}})
				must(e)
				a, e := auth.New(auth.Options{BaseURL: app.URL, BasePath: "/identity", Secret: strings.Repeat("s", 40), Store: s, RateLimit: new(bool), EmailAndPassword: true, Plugins: []auth.Plugin{plug}})
				must(e)
				return a
			}
			keys := &sso.SAMLEncryption{PrivateKey: encKey, Certificate: encCert}
			node, peer = host(first, keys, portalPolicy, false), host(second, keys, portalPolicy, false)
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
			cfg := sso.SAMLConfig{IDPInitiatedCallbackURL: "/company-portal", CallbackURL: "/fallback-portal", SPMetadata: &sso.SAMLSPMetadata{EntityID: app.URL + "/sp"}, EntryPoint: entry, IDPMetadata: sso.SAMLIDPMetadata{EntityID: idpEntity, IsAssertionEncrypted: encrypted}, Certificates: sso.Certificates{idpPEM}, AuthnRequestsSigned: true, Mapping: sso.SAMLMapping{EmailVerified: "verified"}}
			if logout {
				cfg.IDPMetadata.SingleLogoutService = []sso.SAMLService{{Binding: saml.HTTPRedirectBinding, Location: idpBase + "/logout"}}
			}
			if encrypted {
				withoutKey := host(first, nil, portalPolicy, false)
				requestBody, e := json.Marshal(client.RegisterSAMLProviderRequest{ProviderID: "missing-key", Domain: "staff.example", Issuer: idpEntity, SAML: cfg})
				must(e)
				r := httptest.NewRequest(http.MethodPost, api+"/sso/register", bytes.NewReader(requestBody))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", app.URL)
				for _, cookie := range ownerBrowser.Jar.Cookies(r.URL) {
					r.AddCookie(cookie)
				}
				result := httptest.NewRecorder()
				withoutKey.ServeHTTP(result, r)
				if result.Code != 400 || !strings.Contains(result.Body.String(), "decryption is not configured") {
					t.Fatal("encrypted registration on a keyless host", result.Code, result.Body.String())
				}
			}
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
			if metadata.EntityID != cfg.SPMetadata.EntityID || len(metadata.SPSSODescriptors) != 1 || metadata.SPSSODescriptors[0].AssertionConsumerServices[0].Location != api+"/sso/saml2/sp/acs/work" {
				t.Fatal("wrong SP metadata", string(data))
			}
			endpoints := metadata.SPSSODescriptors[0].SingleLogoutServices
			if logout {
				if len(endpoints) != 1 || endpoints[0].Binding != saml.HTTPRedirectBinding || endpoints[0].Location != api+"/sso/saml2/sp/slo/work" {
					t.Fatal("wrong SP logout service", endpoints)
				}
			} else if len(endpoints) != 0 {
				t.Fatal("unexpected SP logout service")
			}

			var advertised bool
			for _, k := range metadata.SPSSODescriptors[0].KeyDescriptors {
				switch k.Use {
				case "signing":
					if len(k.KeyInfo.X509Data.X509Certificates) != 1 || k.KeyInfo.X509Data.X509Certificates[0].Data != base64.StdEncoding.EncodeToString(spCert.Raw) {
						t.Fatal("wrong request-signing certificate")
					}
				case "encryption":
					if advertised || len(k.KeyInfo.X509Data.X509Certificates) != 1 || k.KeyInfo.X509Data.X509Certificates[0].Data != base64.StdEncoding.EncodeToString(encCert.Raw) {
						t.Fatal("incorrect assertion encryption certificate")
					}
					if len(k.EncryptionMethods) != 2 || k.EncryptionMethods[0].Algorithm != xmlenc.AES256GCM.Algorithm() || k.EncryptionMethods[1].Algorithm != "http://www.w3.org/2009/xmlenc11#rsa-oaep" {
						t.Fatal("incorrect encryption profiles", k.EncryptionMethods)
					}
					if !bytes.Contains(data, []byte("http://www.w3.org/2009/xmlenc11#mgf1sha256")) || !bytes.Contains(data, []byte("http://www.w3.org/2001/04/xmlenc#sha256")) {
						t.Fatal("key transport parameters missing from SP metadata")
					}
					advertised = true
				default:
					t.Fatal("unrecognized metadata key usage")
				}
			}
			if advertised != encrypted {
				t.Fatal("encryption-key visibility does not match provider policy")
			}
			// The remote IdP parses and validates the real Redirect signature against
			// the public SP metadata before it constructs any test assertion.
			idpURL, _ := url.Parse(idpEntity)
			ssoURL, _ := url.Parse(entry)
			idp := &saml.IdentityProvider{Key: idpKey, Certificate: idpCert, MetadataURL: *idpURL, SSOURL: *ssoURL, ServiceProviderProvider: samlTestMetadata{cfg.SPMetadata.EntityID: &metadata}, SignatureMethod: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"}
			if logout {
				idp.LogoutURL = *mustTestURL(t, idpBase+"/logout")
			}
			if encrypted {
				protection := xmlenc.OAEP_SHA256()
				protection.BlockCipher = xmlenc.AES256GCM
				idp.AssertionEncrypter = protection
			}
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
			catalog, e := first.FindBrowserProvider(ctx, sso.Selector{ProviderID: "work", Protocol: "saml"})
			must(e)
			t.Run("portal requires current DNS proof", func(t *testing.T) {
				expected := sso.SAMLDirectory{RecordID: reg.ID, Reference: catalog.Reference, ProviderID: "work", Issuer: idpEntity, EntryPoint: entry}
				reviewed.Store(&expected)
				defer reviewed.Store(nil)
				req, e := idp.NewIdpInitiatedRequest(httptest.NewRequest("GET", entry, nil), cfg.SPMetadata.EntityID, "")
				must(e)
				fields := form(req, "unproven", "unproven@staff.example", nil)
				fields.Del("RelayState")
				status, head, _ := post(newBrowser(), fields, acs)
				if status != http.StatusUnauthorized || strings.Contains(strings.Join(head.Values("Set-Cookie"), ";"), "session_token=") {
					t.Fatal("unexpected portal response for an unverified directory", status)
				}
			})
			token, e := owner.RequestSSODomainVerification(ctx, "work")
			must(e)
			dns.put("_stonewrit-auth-token-work.staff.example.", token)
			must(owner.VerifySSODomain(ctx, "work"))

			if logout {
				login := func(t *testing.T, h *http.Client, subject string, adjust func(*saml.Assertion)) {
					request, e := start(h)
					if e != nil {
						t.Fatal(e)
					}
					status, head, _ := post(h, form(request, subject, subject+"@staff.example", adjust), acs)
					if status != 302 || head.Get("Location") != app.URL+"/home" {
						t.Fatal("SAML login failed", status, head.Get("Location"))
					}
				}
				t.Run("IdP session logout", func(t *testing.T) {
					testSAMLIDPLogout(t, first, second, idp, api, newBrowser, sdk, login, owner, node, peer, dns)
				})
				testSAMLLogout(t, first, second, idp, api, idpBase, newBrowser, sdk, login, owner, node, peer)
				return
			}

			t.Run("reviewed identity provider portal", func(t *testing.T) {
				directory := sso.SAMLDirectory{RecordID: reg.ID, Reference: catalog.Reference, ProviderID: "work", Issuer: idpEntity, EntryPoint: entry}
				checkSAMLPortal(t, idp, cfg.SPMetadata.EntityID, api+acs, idpBase, form, &reviewed, directory, node, peer, host(second, keys, nil, false), host(second, keys, portalPolicy, true))
			})

			t.Run("live directory checks during portal login", func(t *testing.T) {
				var original string
				must(first.db.QueryRowContext(ctx, first.bind(`SELECT "samlConfig" FROM "ssoProvider" WHERE "id"=?`), reg.ID).Scan(&original))
				var changed sso.SAMLConfig
				must(json.Unmarshal([]byte(original), &changed))
				changed.Audience = "urn:changed:audience"
				changedRaw, e := json.Marshal(changed)
				must(e)
				set := func(s string) error {
					_, err := first.db.ExecContext(ctx, first.bind(`UPDATE "ssoProvider" SET "samlConfig"=? WHERE "id"=?`), s, reg.ID)
					return err
				}
				entered, resume := make(chan struct{}), make(chan struct{})
				policy := func(ctx context.Context, d sso.SAMLDirectory) (bool, error) {
					close(entered)
					select {
					case <-resume:
						return d.RecordID == reg.ID, nil
					case <-ctx.Done():
						return false, ctx.Err()
					}
				}
				handler := host(second, keys, policy, false)
				req, e := idp.NewIdpInitiatedRequest(httptest.NewRequest("GET", entry, nil), cfg.SPMetadata.EntityID, "")
				must(e)
				fields := form(req, "portal-changing", "portal-changing@staff.example", nil)
				fields.Del("RelayState")
				incoming := httptest.NewRequest("POST", api+acs, strings.NewReader(fields.Encode()))
				incoming.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				incoming.Header.Set("Origin", idpBase)
				w := httptest.NewRecorder()
				done := make(chan struct{})
				go func() { handler.ServeHTTP(w, incoming); close(done) }()
				select {
				case <-entered:
				case <-done:
					t.Fatalf("policy was never reached: %d", w.Code)
				case <-time.After(10 * time.Second):
					t.Fatal("policy wait timed out")
				}
				updateErr := set(string(changedRaw))
				close(resume)
				<-done
				must(updateErr)
				must(set(original))
				if w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "error=SSO_PROVIDER_CHANGED") || strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), ";"), "session_token=") {
					t.Fatal("stale reviewed directory created a portal session", w.Code)
				}
			})

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
			status, headers, _ = post(newBrowser(), url.Values{"SAMLResponse": {proof.Get("SAMLResponse")}}, acs)
			if status != 302 || !strings.Contains(headers.Get("Location"), "error=invalid_saml_response") {
				t.Fatal("a correlated reply was accepted without its state", status)
			}

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
			if encrypted {
				for _, mode := range []string{"plaintext", "AES-128-GCM", "AES-256-CBC", "legacy RSA-OAEP", "RSA-OAEP SHA-384", "different recipient certificate", "only the response is signed"} {
					t.Run(mode, func(t *testing.T) {
						h := newBrowser()
						request, e := start(h)
						must(e)
						// Prepare a fresh, correctly signed assertion, then configure the test
						// IdP's protection mode independently of the directory's requirements.
						descriptor := *request.SPSSODescriptor
						descriptor.KeyDescriptors = nil
						request.SPSSODescriptor = &descriptor
						fields := form(request, "alternate-mode", "alternate@staff.example", nil)
						if mode != "plaintext" {
							cert := encCert
							protection := xmlenc.OAEP_SHA256()
							protection.BlockCipher = xmlenc.AES256GCM
							switch mode {
							case "AES-128-GCM":
								protection.BlockCipher = xmlenc.AES128GCM
							case "AES-256-CBC":
								protection.BlockCipher = xmlenc.AES256CBC
							case "RSA-OAEP SHA-384":
								protection = xmlenc.OAEP_SHA384()
								protection.BlockCipher = xmlenc.AES256GCM
							case "legacy RSA-OAEP":
								protection = xmlenc.OAEP()
								protection.BlockCipher = xmlenc.AES256GCM
							case "different recipient certificate":
								cert = spCert
							case "only the response is signed":
								request.Assertion.Signature = nil
							}
							doc := etree.NewDocument()
							doc.SetRoot(request.Assertion.Element())
							raw, e := doc.WriteToBytes()
							must(e)
							ciphertext, e := protection.Encrypt(cert, raw, nil)
							must(e)
							wrapper := etree.NewElement("saml:EncryptedAssertion")
							wrapper.AddChild(ciphertext)
							request.AssertionEl = wrapper
							request.ResponseEl = nil
							signed, e := request.PostBinding()
							must(e)
							fields.Set("SAMLResponse", signed.SAMLResponse)
						}
						status, hd, _ := post(h, fields, acs)
						if status != 302 || !strings.Contains(hd.Get("Location"), "error=invalid_saml_response") || strings.Contains(strings.Join(hd.Values("Set-Cookie"), ";"), "session_token=") {
							t.Fatal("unexpected session or redirect for", mode, status)
						}
						_, _, body := send(h, "GET", "/get-session", "", "", "")
						if string(bytes.TrimSpace(body)) != "null" {
							t.Fatalf("unexpected active session for %s", mode)
						}
					})
				}
			}
			if !encrypted {
				t.Run("recipient key requires directory opt-in", func(t *testing.T) {
					h := newBrowser()
					request, e := start(h)
					must(e)
					// Some IdPs reuse the SP request-signing certificate for encryption.
					// The ordinary signed-assertion directory requires explicit opt-in.
					descriptor := *request.SPSSODescriptor
					descriptor.KeyDescriptors = []saml.KeyDescriptor{{Use: "encryption", KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(spCert.Raw)}}}}}}
					request.SPSSODescriptor = &descriptor
					remote := *idp
					cipher := xmlenc.OAEP_SHA256()
					cipher.BlockCipher = xmlenc.AES256GCM
					remote.AssertionEncrypter = cipher
					request.IDP = &remote
					status, hd, _ := post(h, form(request, "other-format", "other-format@staff.example", nil), acs)
					if status != 302 || !strings.Contains(hd.Get("Location"), "error=invalid_saml_response") || strings.Contains(strings.Join(hd.Values("Set-Cookie"), ";"), "session_token=") {
						t.Fatal("directory accepted ciphertext without opt-in", status)
					}
				})
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
			t.Run("inline metadata registration and signing key rotation", func(t *testing.T) {
				outsider := sdk(newBrowser())
				_, e := outsider.SignUpEmail(ctx, client.SignUpRequest{Name: "Other", Email: "other-admin@outside.example", Password: "local-test-secret-1234"})
				must(e)
				pending := func(key *rsa.PrivateKey, cert *x509.Certificate) func() string {
					b := newBrowser()
					req, e := start(b)
					must(e)
					previousKey, previousCert := idp.Key, idp.Certificate
					idp.Key, idp.Certificate = key, cert
					body := form(req, "metadata-user", "rotation@staff.example", nil)
					idp.Key, idp.Certificate = previousKey, previousCert
					return func() string {
						code, headers, _ := post(b, body, acs)
						if code != 302 {
							t.Fatalf("ACS %d", code)
						}
						return headers.Get("Location")
					}
				}
				testSAMLMetadataRotation(t, first, second, owner, outsider, cfg, idpKey, idpCert, pending)
			})
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
			// Registration names may be reused. Approval for the removed immutable row
			// must not follow a new record with the same name, issuer and signing key.
			replacement, e := owner.RegisterSAMLProvider(ctx, client.RegisterSAMLProviderRequest{ProviderID: "work", Domain: "staff.example", Issuer: idpEntity, SAML: cfg})
			must(e)
			if replacement.ID == reg.ID {
				t.Fatal("provider identity reused")
			}
			newProof, e := owner.RequestSSODomainVerification(ctx, "work")
			must(e)
			dns.put("_stonewrit-auth-token-work.staff.example.", newProof)
			must(owner.VerifySSODomain(ctx, "work"))
			portal, e := idp.NewIdpInitiatedRequest(httptest.NewRequest("GET", entry, nil), cfg.SPMetadata.EntityID, "")
			must(e)
			fields := form(portal, "new-directory", "new-directory@staff.example", nil)
			fields.Del("RelayState")
			st, head, _ = post(newBrowser(), fields, acs)
			if st != 302 || !strings.Contains(head.Get("Location"), "error=unsolicited_response") {
				t.Fatal("portal approval adopted a replacement registration", st)
			}

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
