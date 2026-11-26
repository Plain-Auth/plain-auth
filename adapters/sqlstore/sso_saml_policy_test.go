package sqlstore

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/xmlenc"
	dsig "github.com/russellhaering/goxmldsig"
)

// samlPolicy is a store, an owner and an identity provider shared by the
// SAML response policy tests. Directories are inserted per test.
type samlPolicy struct {
	t       *testing.T
	store   *Store
	idpKey  *rsa.PrivateKey
	idpCert *x509.Certificate
	idpPEM  string
	// recipient decrypts assertions for encrypted directories.
	recipient *sso.SAMLEncryption
	// respond, when set, runs after the assertion is signed and before the
	// response is, so a test can sign them differently.
	respond func(*saml.IdpAuthnRequest)
	// nameIDFormat is the NameID format the IdP session declares.
	nameIDFormat string
}

const samlPolicyIdP = "https://identity.example.test"

func newSAMLPolicy(t *testing.T, dialect string) *samlPolicy {
	t.Helper()
	ctx := t.Context()
	ddl, err := schema.Generate(dialect, []string{"organization", "sso"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	now := time.Now().UTC()
	if err := store.CreateUser(ctx, auth.User{ID: "owner", Name: "Owner", Email: "owner@example.test", CreatedAt: now, UpdatedAt: now}, "credential", nil); err != nil {
		t.Fatal(err)
	}
	key, cert, pem := samlTestCertificate(t)
	encKey, encCert, _ := samlTestCertificate(t)
	return &samlPolicy{t: t, store: store, idpKey: key, idpCert: cert, idpPEM: pem, recipient: &sso.SAMLEncryption{PrivateKey: encKey, Certificate: encCert}}
}

// directory inserts a SAML directory id for the shared IdP, after edit.
func (p *samlPolicy) directory(id string, edit func(*sso.SAMLConfig)) {
	p.t.Helper()
	cfg := sso.SAMLConfig{Issuer: samlPolicyIdP + "/metadata", EntryPoint: samlPolicyIdP + "/sso", Certificates: sso.Certificates{p.idpPEM},
		IDPMetadata: sso.SAMLIDPMetadata{EntityID: samlPolicyIdP + "/metadata"}, SPMetadata: &sso.SAMLSPMetadata{EntityID: "https://service.test/sp/" + id}}
	if edit != nil {
		edit(&cfg)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		p.t.Fatal(err)
	}
	if _, err := p.store.db.ExecContext(p.t.Context(), p.store.bind(`INSERT INTO "ssoProvider" ("id","providerId","issuer","samlConfig","domain","userId") VALUES (?,?,?,?,?,?)`),
		"record-"+id, id, cfg.Issuer, string(raw), id+".example", "owner"); err != nil {
		p.t.Fatal(err)
	}
}

func (p *samlPolicy) host(opts sso.SAMLOptions, logger *slog.Logger) *auth.Auth {
	p.t.Helper()
	return p.pluginHost(sso.Options{SAML: &opts}, logger)
}

// pluginHost builds a host with the full plugin options.
func (p *samlPolicy) pluginHost(o sso.Options, logger *slog.Logger) *auth.Auth {
	p.t.Helper()
	plugin, err := sso.New(o)
	if err != nil {
		p.t.Fatal(err)
	}
	h, err := auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", RateLimit: new(bool), Store: p.store, Secret: strings.Repeat("k", 32), EmailAndPassword: true, Logger: logger, Plugins: []auth.Plugin{plugin}})
	if err != nil {
		p.t.Fatal(err)
	}
	return h
}

func (p *samlPolicy) call(h *auth.Auth, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			p.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, "https://service.test/identity/"+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://service.test")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// start begins a sign-in through directory id and returns the IdP's view of
// the AuthnRequest and the state cookie.
func (p *samlPolicy) start(h *auth.Auth, id string) (*saml.IdpAuthnRequest, *http.Cookie) {
	p.t.Helper()
	w := p.call(h, "GET", "sso/saml2/sp/metadata?providerId="+id, nil)
	var md saml.EntityDescriptor
	if w.Code != 200 || xml.Unmarshal(w.Body.Bytes(), &md) != nil {
		p.t.Fatal("SP metadata", w.Code, w.Body.String())
	}
	idp := &saml.IdentityProvider{Key: p.idpKey, Certificate: p.idpCert, MetadataURL: *mustTestURL(p.t, samlPolicyIdP+"/metadata"), SSOURL: *mustTestURL(p.t, samlPolicyIdP+"/sso"),
		ServiceProviderProvider: samlTestMetadata{md.EntityID: &md}, SignatureMethod: dsig.RSASHA256SignatureMethod}
	w = p.call(h, "POST", "sign-in/sso", map[string]any{"providerId": id, "providerType": "saml", "callbackURL": "/home", "errorCallbackURL": "/retry"})
	var started struct{ URL string }
	if err := json.Unmarshal(w.Body.Bytes(), &started); err != nil {
		p.t.Fatal(err, w.Body.String())
	}
	r, err := http.NewRequest("GET", started.URL, nil)
	if err != nil {
		p.t.Fatal(err)
	}
	req, err := saml.NewIdpAuthnRequest(idp, r)
	if err != nil {
		p.t.Fatal(err)
	}
	if err := req.Validate(); err != nil {
		p.t.Fatal(err)
	}
	return req, w.Result().Cookies()[0]
}

// finish has the IdP assert employee-<id> with an email in the directory's
// domain, after the optional edits, and posts the response to the ACS.
func (p *samlPolicy) finish(h *auth.Auth, id string, req *saml.IdpAuthnRequest, state *http.Cookie, idpEdit func(*saml.IdentityProvider), adjust func(*saml.Assertion), formEdit func(url.Values)) *httptest.ResponseRecorder {
	p.t.Helper()
	if idpEdit != nil {
		idpEdit(req.IDP)
	}
	sess := &saml.Session{ID: "idp-" + id, Index: "index-" + id, CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour), NameID: "employee-" + id, NameIDFormat: p.nameIDFormat,
		CustomAttributes: []saml.Attribute{{Name: "email", Values: []saml.AttributeValue{{Value: "employee-" + id + "@" + id + ".example"}}}}}
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, sess); err != nil {
		p.t.Fatal(err)
	}
	req.Assertion.Subject.NameID.Value = "employee-" + id
	if adjust != nil {
		adjust(req.Assertion)
	}
	if err := req.MakeAssertionEl(); err != nil {
		p.t.Fatal(err)
	}
	if p.respond != nil {
		p.respond(req)
	}
	form, err := req.PostBinding()
	if err != nil {
		p.t.Fatal(err)
	}
	body := url.Values{"RelayState": {form.RelayState}, "SAMLResponse": {form.SAMLResponse}}
	if formEdit != nil {
		formEdit(body)
	}
	acs := httptest.NewRequest("POST", "https://service.test/identity/sso/saml2/sp/acs/"+id, strings.NewReader(body.Encode()))
	acs.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	acs.Header.Set("Origin", samlPolicyIdP)
	acs.Header.Set("Cookie", state.Name+"="+state.Value)
	done := httptest.NewRecorder()
	h.ServeHTTP(done, acs)
	return done
}

// samlOutcome parses the ACS redirect and reports whether it set a session.
func samlOutcome(t *testing.T, w *httptest.ResponseRecorder) (*url.URL, bool) {
	t.Helper()
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return location, strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), ";"), "session_token=")
}

func TestEnterpriseSAMLResponsePolicy(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			t.Run("response size", func(t *testing.T) {
				p := newSAMLPolicy(t, dialect)
				p.directory("size", nil)
				plain, small := p.host(sso.SAMLOptions{}, nil), p.host(sso.SAMLOptions{MaxResponseSize: 1024}, nil)
				req, state := p.start(plain, "size")
				w := p.finish(plain, "size", req, state, nil, nil, func(v url.Values) { v.Set("SAMLResponse", strings.Repeat("A", 256*1024+1)) })
				location, session := samlOutcome(t, w)
				if w.Code != 302 || location.Path != "/retry" || location.Query().Get("error") != "saml_error" || location.Query().Get("error_description") != "SAML response exceeds maximum allowed size (262144 bytes)" || session {
					t.Fatal("an oversized SAMLResponse did not redirect with saml_error", w.Code, location)
				}
				req, state = p.start(small, "size")
				w = p.finish(small, "size", req, state, nil, nil, nil)
				location, session = samlOutcome(t, w)
				if location.Query().Get("error_description") != "SAML response exceeds maximum allowed size (1024 bytes)" || session {
					t.Fatal("MaxResponseSize did not bound a signed response", w.Code, location)
				}
				req, state = p.start(plain, "size")
				w = p.finish(plain, "size", req, state, nil, nil, nil)
				if location, session = samlOutcome(t, w); location.String() != "https://service.test/home" || !session {
					t.Fatal("a SAMLResponse under the default limit was refused", w.Code, location)
				}
			})
			t.Run("signature algorithms", func(t *testing.T) {
				p := newSAMLPolicy(t, dialect)
				p.directory("algorithms", nil)
				def := p.host(sso.SAMLOptions{}, nil)
				sigOnly := p.host(sso.SAMLOptions{Algorithms: sso.SAMLAlgorithms{AllowedSignatureAlgorithms: []sso.SignatureAlgorithm{sso.SignatureRSASHA256}}}, nil)
				digestOnly := p.host(sso.SAMLOptions{Algorithms: sso.SAMLAlgorithms{AllowedDigestAlgorithms: []sso.DigestAlgorithm{sso.DigestSHA256}}}, nil)
				signedWith := func(h *auth.Auth, method sso.SignatureAlgorithm) (*url.URL, bool) {
					t.Helper()
					req, state := p.start(h, "algorithms")
					return samlOutcome(t, p.finish(h, "algorithms", req, state, func(idp *saml.IdentityProvider) { idp.SignatureMethod = string(method) }, nil, nil))
				}
				refused := func(location *url.URL, session bool, code, description string) bool {
					return location.Path == "/retry" && location.Query().Get("error") == code && location.Query().Get("error_description") == description && !session
				}
				home := func(location *url.URL, session bool) bool {
					return location.String() == "https://service.test/home" && session
				}
				if location, session := signedWith(def, sso.SignatureRSASHA1); !refused(location, session, "saml_deprecated_algorithm", "SAML response uses deprecated signature algorithm: http://www.w3.org/2000/09/xmldsig#rsa-sha1. Please configure your IdP to use SHA-256 or stronger.") {
					t.Fatal("an RSA-SHA1 response did not fail with saml_deprecated_algorithm", location)
				}
				if location, session := signedWith(def, sso.SignatureRSASHA384); !home(location, session) {
					t.Fatal("an RSA-SHA384 response was refused", location)
				}
				if location, session := signedWith(def, sso.SignatureRSASHA512); !home(location, session) {
					t.Fatal("an RSA-SHA512 response was refused", location)
				}
				if location, session := signedWith(sigOnly, sso.SignatureRSASHA512); !refused(location, session, "saml_algorithm_not_allowed", "SAML signature algorithm not in allow-list: http://www.w3.org/2001/04/xmldsig-more#rsa-sha512") {
					t.Fatal("the signature allow-list accepted an RSA-SHA512 response", location)
				}
				if location, session := signedWith(sigOnly, sso.SignatureRSASHA256); !home(location, session) {
					t.Fatal("the signature allow-list refused an RSA-SHA256 response", location)
				}
				if location, session := signedWith(digestOnly, sso.SignatureRSASHA384); !refused(location, session, "saml_algorithm_not_allowed", "SAML digest algorithm not in allow-list: http://www.w3.org/2001/04/xmldsig-more#sha384") {
					t.Fatal("the digest allow-list accepted a SHA-384 digest", location)
				}
				p.respond = func(req *saml.IdpAuthnRequest) { req.IDP.SignatureMethod = string(sso.SignatureRSASHA256) }
				location, session := signedWith(sigOnly, sso.SignatureRSASHA512)
				p.respond = nil
				if !refused(location, session, "saml_algorithm_not_allowed", "SAML signature algorithm not in allow-list: http://www.w3.org/2001/04/xmldsig-more#rsa-sha512") {
					t.Fatal("an RSA-SHA512 assertion inside an RSA-SHA256 response escaped the allow-list", location)
				}
				p.respond = func(req *saml.IdpAuthnRequest) { req.IDP.SignatureMethod = string(sso.SignatureRSASHA512) }
				location, session = signedWith(sigOnly, sso.SignatureRSASHA256)
				p.respond = nil
				if !refused(location, session, "saml_algorithm_not_allowed", "SAML signature algorithm not in allow-list: http://www.w3.org/2001/04/xmldsig-more#rsa-sha512") {
					t.Fatal("an RSA-SHA512 response around an RSA-SHA256 assertion escaped the allow-list", location)
				}
			})
			t.Run("deprecated encryption", func(t *testing.T) {
				p := newSAMLPolicy(t, dialect)
				p.directory("sealed", func(cfg *sso.SAMLConfig) { cfg.IDPMetadata.IsAssertionEncrypted = true })
				def := p.host(sso.SAMLOptions{Encryption: p.recipient}, nil)
				sigOnly := p.host(sso.SAMLOptions{Encryption: p.recipient, Algorithms: sso.SAMLAlgorithms{AllowedSignatureAlgorithms: []sso.SignatureAlgorithm{sso.SignatureRSASHA256}}}, nil)
				sealed := func(h *auth.Auth, encrypter xmlenc.Encrypter, method sso.SignatureAlgorithm) (*url.URL, bool) {
					t.Helper()
					req, state := p.start(h, "sealed")
					return samlOutcome(t, p.finish(h, "sealed", req, state, func(idp *saml.IdentityProvider) {
						idp.AssertionEncrypter = encrypter
						idp.SignatureMethod = string(method)
					}, nil, nil))
				}
				cipher := func(key xmlenc.RSA, block xmlenc.BlockCipher) xmlenc.Encrypter {
					key.BlockCipher = block
					return key
				}
				refused := func(location *url.URL, session bool, code, description string) bool {
					return location.Path == "/retry" && location.Query().Get("error") == code && location.Query().Get("error_description") == description && !session
				}
				if location, session := sealed(def, cipher(xmlenc.OAEP_SHA256(), xmlenc.TripleDES), sso.SignatureRSASHA256); !refused(location, session, "saml_deprecated_algorithm", "SAML response uses deprecated data encryption algorithm: http://www.w3.org/2001/04/xmlenc#tripledes-cbc. Please configure your IdP to use AES-GCM.") {
					t.Fatal("a 3DES assertion did not fail with saml_deprecated_algorithm", location)
				}
				// The key transport is named first, whatever the content cipher.
				for _, block := range []xmlenc.BlockCipher{xmlenc.AES256GCM, xmlenc.AES256CBC, xmlenc.TripleDES} {
					if location, session := sealed(def, cipher(xmlenc.PKCS1v15(), block), sso.SignatureRSASHA256); !refused(location, session, "saml_deprecated_algorithm", "SAML response uses deprecated key encryption algorithm: http://www.w3.org/2001/04/xmlenc#rsa-1_5. Please configure your IdP to use RSA-OAEP.") {
						t.Fatal("an RSA 1.5 key transport did not fail with saml_deprecated_algorithm", block.Algorithm(), location)
					}
				}
				// sealedWith edits the posted Response XML before the ACS reads it.
				sealedWith := func(h *auth.Auth, encrypter xmlenc.Encrypter, edits ...func(*etree.Element)) (*url.URL, bool) {
					t.Helper()
					req, state := p.start(h, "sealed")
					return samlOutcome(t, p.finish(h, "sealed", req, state, func(idp *saml.IdentityProvider) {
						idp.AssertionEncrypter = encrypter
						idp.SignatureMethod = string(sso.SignatureRSASHA256)
					}, nil, func(form url.Values) {
						raw, err := base64.StdEncoding.DecodeString(form.Get("SAMLResponse"))
						doc := etree.NewDocument()
						if err != nil || doc.ReadFromBytes(raw) != nil {
							t.Fatal("unreadable SAML response", err)
						}
						for _, edit := range edits {
							edit(doc.Root())
						}
						out, err := doc.WriteToBytes()
						if err != nil {
							t.Fatal(err)
						}
						form.Set("SAMLResponse", base64.StdEncoding.EncodeToString(out))
					}))
				}
				unsigned := func(r *etree.Element) {
					for _, c := range r.ChildElements() {
						if c.Tag == "Signature" {
							r.RemoveChild(c)
						}
					}
				}
				keyMethod := func(r *etree.Element) *etree.Element {
					return r.FindElement("./EncryptedAssertion/EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod")
				}
				signedIn := func(location *url.URL, session bool) bool {
					return location.String() == "https://service.test/home" && session
				}
				for _, tc := range []struct {
					key   xmlenc.RSA
					block xmlenc.BlockCipher
				}{{xmlenc.OAEP_SHA256(), xmlenc.AES128GCM}, {xmlenc.OAEP_SHA256(), xmlenc.AES192GCM}, {xmlenc.OAEP(), xmlenc.AES256GCM},
					{xmlenc.OAEP_SHA512(), xmlenc.AES256GCM}, {xmlenc.OAEP_SHA256(), xmlenc.AES128CBC}, {xmlenc.OAEP(), xmlenc.AES256CBC}} {
					if location, session := sealedWith(def, cipher(tc.key, tc.block)); !signedIn(location, session) {
						t.Fatal("a supported encryption profile was refused", tc.key.Algorithm(), tc.block.Algorithm(), location)
					}
				}
				if location, session := sealedWith(def, cipher(xmlenc.OAEP_SHA256(), xmlenc.AES256GCM), unsigned); !signedIn(location, session) {
					t.Fatal("an AES-GCM assertion inside an unsigned Response was refused", location)
				}
				// AES-CBC needs a Response signature over its ciphertext.
				cbc := cipher(xmlenc.OAEP_SHA256(), xmlenc.AES256CBC)
				flip := func(r *etree.Element) {
					v := r.FindElement("./EncryptedAssertion/EncryptedData/CipherData/CipherValue")
					b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v.Text()))
					if err != nil {
						t.Fatal(err)
					}
					b[len(b)-1] ^= 1
					v.SetText(base64.StdEncoding.EncodeToString(b))
				}
				// A comment inside the signed CipherValue, which
				// canonicalization drops, leaves the ciphertext intact.
				split := func(r *etree.Element) {
					v := r.FindElement("./EncryptedAssertion/EncryptedData/CipherData/CipherValue")
					text := strings.TrimSpace(v.Text())
					v.SetText(text[:len(text)/2])
					v.CreateComment("split")
					v.CreateText(text[len(text)/2:])
				}
				if location, session := sealedWith(def, cbc, split); !signedIn(location, session) {
					t.Fatal("a comment inside a signed AES-CBC ciphertext changed it", location)
				}
				for _, edit := range []func(*etree.Element){unsigned, flip} {
					if location, session := sealedWith(def, cbc, edit); !refused(location, session, "invalid_saml_response", "SAML response must be signed when the assertion is encrypted with AES-CBC") {
						t.Fatal("an AES-CBC assertion was decrypted without a Response signature over it", location)
					}
				}
				// Key transport parameters outside the profile are refused,
				// including an rsa-oaep-mgf1p digest the library would accept.
				sha512MGF1P := xmlenc.OAEP()
				sha512MGF1P.DigestMethod = xmlenc.SHA512
				mgf := func(r *etree.Element) {
					e := keyMethod(r).CreateElement("xenc11:MGF")
					e.CreateAttr("xmlns:xenc11", "http://www.w3.org/2009/xmlenc11#")
					e.CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#mgf1sha1")
				}
				label := func(r *etree.Element) {
					e := keyMethod(r).CreateElement("xenc:OAEPparams")
					e.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
					e.SetText("bGFiZWw=")
				}
				for _, tc := range []struct {
					enc  xmlenc.Encrypter
					edit func(*etree.Element)
				}{{cipher(xmlenc.OAEP(), xmlenc.AES256GCM), mgf}, {cipher(xmlenc.OAEP_SHA256(), xmlenc.AES256GCM), label}, {cipher(sha512MGF1P, xmlenc.AES256GCM), nil}} {
					edits := []func(*etree.Element){unsigned}
					if tc.edit != nil {
						edits = append(edits, tc.edit)
					}
					if location, session := sealedWith(def, tc.enc, edits...); location.Query().Get("error") != "invalid_saml_response" || session {
						t.Fatal("a key transport with unsupported parameters was accepted", location)
					}
				}
				// Allow-lists name the key transport before the content cipher.
				dataList := p.host(sso.SAMLOptions{Encryption: p.recipient, Algorithms: sso.SAMLAlgorithms{AllowedDataEncryptionAlgorithms: []sso.DataEncryptionAlgorithm{sso.DataEncryptionAES256GCM}}}, nil)
				bothLists := p.host(sso.SAMLOptions{Encryption: p.recipient, Algorithms: sso.SAMLAlgorithms{AllowedKeyEncryptionAlgorithms: []sso.KeyEncryptionAlgorithm{sso.KeyEncryptionRSAOAEPSHA256},
					AllowedDataEncryptionAlgorithms: []sso.DataEncryptionAlgorithm{sso.DataEncryptionAES256GCM}}}, nil)
				if location, session := sealedWith(dataList, cipher(xmlenc.OAEP_SHA256(), xmlenc.AES128GCM)); !refused(location, session, "saml_algorithm_not_allowed", "SAML data encryption algorithm not in allow-list: http://www.w3.org/2009/xmlenc11#aes128-gcm") {
					t.Fatal("an AES-128-GCM assertion escaped the data encryption allow-list", location)
				}
				if location, session := sealedWith(bothLists, cipher(xmlenc.OAEP(), xmlenc.AES128GCM)); !refused(location, session, "saml_algorithm_not_allowed", "SAML key encryption algorithm not in allow-list: http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p") {
					t.Fatal("the key transport allow-list was not checked first", location)
				}
				if location, session := sealedWith(bothLists, cipher(xmlenc.PKCS1v15(), xmlenc.AES256GCM)); !refused(location, session, "saml_algorithm_not_allowed", "SAML key encryption algorithm not in allow-list: http://www.w3.org/2001/04/xmlenc#rsa-1_5") {
					t.Fatal("an RSA 1.5 key transport escaped the key encryption allow-list", location)
				}
				if location, session := sealedWith(bothLists, cipher(xmlenc.OAEP_SHA256(), xmlenc.AES256GCM)); !signedIn(location, session) {
					t.Fatal("an allowed encryption profile was refused", location)
				}
				// The SP metadata advertises the allow-lists in order, with
				// OAEP parameters only on XML Encryption 1.1 rsa-oaep.
				listed := p.host(sso.SAMLOptions{Encryption: p.recipient, Algorithms: sso.SAMLAlgorithms{AllowedKeyEncryptionAlgorithms: []sso.KeyEncryptionAlgorithm{sso.KeyEncryptionRSAOAEP, sso.KeyEncryptionRSAOAEPSHA256},
					AllowedDataEncryptionAlgorithms: []sso.DataEncryptionAlgorithm{sso.DataEncryptionAES128GCM, sso.DataEncryptionAES256CBC}}}, nil)
				w := p.call(listed, "GET", "sso/saml2/sp/metadata?providerId=sealed", nil)
				md := etree.NewDocument()
				if w.Code != 200 || md.ReadFromBytes(w.Body.Bytes()) != nil {
					t.Fatal("SP metadata", w.Code, w.Body.String())
				}
				var methods []string
				for _, m := range md.FindElements("//KeyDescriptor[@use='encryption']/EncryptionMethod") {
					entry := m.SelectAttrValue("Algorithm", "")
					for _, param := range m.ChildElements() {
						entry += " " + param.Tag + "=" + param.SelectAttrValue("Algorithm", "")
					}
					methods = append(methods, entry)
				}
				if want := []string{"http://www.w3.org/2009/xmlenc11#aes128-gcm", "http://www.w3.org/2001/04/xmlenc#aes256-cbc", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
					"http://www.w3.org/2009/xmlenc11#rsa-oaep DigestMethod=http://www.w3.org/2001/04/xmlenc#sha256 MGF=http://www.w3.org/2009/xmlenc11#mgf1sha256"}; !slices.Equal(methods, want) {
					t.Fatal("the SP metadata did not advertise the allow-lists in order", methods)
				}
				if location, session := sealed(def, cipher(xmlenc.OAEP_SHA256(), xmlenc.AES256GCM), sso.SignatureRSASHA256); location.String() != "https://service.test/home" || !session {
					t.Fatal("the supported encryption profile was refused", location)
				}
				p.respond = func(req *saml.IdpAuthnRequest) { req.IDP.SignatureMethod = string(sso.SignatureRSASHA256) }
				location, session := sealed(sigOnly, cipher(xmlenc.OAEP_SHA256(), xmlenc.AES256GCM), sso.SignatureRSASHA512)
				p.respond = nil
				if !refused(location, session, "saml_algorithm_not_allowed", "SAML signature algorithm not in allow-list: http://www.w3.org/2001/04/xmldsig-more#rsa-sha512") {
					t.Fatal("a decrypted RSA-SHA512 assertion escaped the allow-list", location)
				}
				p.respond = func(req *saml.IdpAuthnRequest) { req.IDP.SignatureMethod = string(sso.SignatureRSASHA512) }
				location, session = sealed(sigOnly, cipher(xmlenc.OAEP_SHA256(), xmlenc.AES256GCM), sso.SignatureRSASHA256)
				p.respond = nil
				if !refused(location, session, "saml_algorithm_not_allowed", "SAML signature algorithm not in allow-list: http://www.w3.org/2001/04/xmldsig-more#rsa-sha512") {
					t.Fatal("an RSA-SHA512 response around an encrypted assertion escaped the allow-list", location)
				}
			})
			t.Run("assertion signatures", func(t *testing.T) {
				p := newSAMLPolicy(t, dialect)
				optional := func(c *sso.SAMLConfig) { c.WantAssertionsSigned = new(bool) }
				p.directory("strict", nil)
				p.directory("optional", optional)
				p.directory("sealed-strict", func(c *sso.SAMLConfig) { c.IDPMetadata.IsAssertionEncrypted = true })
				p.directory("sealed-optional", func(c *sso.SAMLConfig) { optional(c); c.IDPMetadata.IsAssertionEncrypted = true })
				h := p.host(sso.SAMLOptions{Encryption: p.recipient}, nil)
				// The IdP signs only the Response: the assertion loses its
				// signature, and is encrypted again for sealed directories.
				p.respond = func(req *saml.IdpAuthnRequest) {
					req.Assertion.Signature = nil
					el := req.Assertion.Element()
					if req.AssertionEl.Tag == "EncryptedAssertion" {
						doc := etree.NewDocument()
						doc.SetRoot(el)
						raw, err := doc.WriteToBytes()
						if err != nil {
							t.Fatal(err)
						}
						cipher := xmlenc.OAEP_SHA256()
						cipher.BlockCipher = xmlenc.AES256GCM
						data, err := cipher.Encrypt(p.recipient.Certificate, raw, nil)
						if err != nil {
							t.Fatal(err)
						}
						el = etree.NewElement("saml:EncryptedAssertion")
						el.AddChild(data)
					}
					req.AssertionEl = el
				}
				defer func() { p.respond = nil }()
				run := func(id string, form func(url.Values)) (*url.URL, bool) {
					t.Helper()
					req, state := p.start(h, id)
					return samlOutcome(t, p.finish(h, id, req, state, nil, nil, form))
				}
				unsignedResponse := func(form url.Values) {
					raw, err := base64.StdEncoding.DecodeString(form.Get("SAMLResponse"))
					doc := etree.NewDocument()
					if err != nil || doc.ReadFromBytes(raw) != nil {
						t.Fatal("unreadable SAML response", err)
					}
					for _, c := range doc.Root().ChildElements() {
						if c.Tag == "Signature" {
							doc.Root().RemoveChild(c)
						}
					}
					out, err := doc.WriteToBytes()
					if err != nil {
						t.Fatal(err)
					}
					form.Set("SAMLResponse", base64.StdEncoding.EncodeToString(out))
				}
				signedIn := func(location *url.URL, session bool) bool {
					return location.String() == "https://service.test/home" && session
				}
				required := func(location *url.URL, session bool) bool {
					return location.Path == "/retry" && location.Query().Get("error") == "invalid_saml_response" && location.Query().Get("error_description") == "SAML assertion signature is required" && !session
				}
				for _, id := range []string{"strict", "sealed-strict"} {
					if location, session := run(id, nil); !required(location, session) {
						t.Fatal("a response-only signature passed for a directory requiring the assertion's own", id, location)
					}
				}
				for _, id := range []string{"optional", "sealed-optional"} {
					if location, session := run(id, nil); !signedIn(location, session) {
						t.Fatal("a response-only signature was refused with wantAssertionsSigned false", id, location)
					}
				}
				if location, session := run("optional", unsignedResponse); location.Query().Get("error") != "invalid_saml_response" || session {
					t.Fatal("a response signed nowhere was accepted", location)
				}
				for id, want := range map[string]string{"strict": `WantAssertionsSigned="true"`, "optional": `WantAssertionsSigned="false"`} {
					if w := p.call(h, "GET", "sso/saml2/sp/metadata?providerId="+id, nil); w.Code != 200 || !strings.Contains(w.Body.String(), want) {
						t.Fatal("the SP metadata did not advertise the assertion signature policy", id, w.Body.String())
					}
				}
			})
			t.Run("manual sign-in service", func(t *testing.T) {
				p := newSAMLPolicy(t, dialect)
				const legacy = "https://legacy.example.test/sso"
				p.directory("manual", func(c *sso.SAMLConfig) {
					c.EntryPoint = legacy
					c.IDPMetadata.SingleSignOnService = []sso.SAMLService{{Binding: saml.HTTPPostBinding, Location: samlPolicyIdP + "/post"}, {Binding: saml.HTTPRedirectBinding, Location: samlPolicyIdP + "/sso"}}
				})
				h := p.host(sso.SAMLOptions{}, nil)
				// The listed Redirect service replaces entryPoint as the
				// AuthnRequest destination and the expected IdP origin.
				w := p.call(h, "POST", "sign-in/sso", map[string]any{"providerId": "manual", "providerType": "saml", "callbackURL": "/home"})
				var started struct{ URL string }
				if err := json.Unmarshal(w.Body.Bytes(), &started); err != nil || !strings.HasPrefix(started.URL, samlPolicyIdP+"/sso?") {
					t.Fatal("the AuthnRequest did not go to the listed sign-in service", w.Code, started.URL)
				}
				req, state := p.start(h, "manual")
				if location, session := samlOutcome(t, p.finish(h, "manual", req, state, nil, nil, nil)); location.String() != "https://service.test/home" || !session {
					t.Fatal("a response from the listed sign-in service's origin was refused", location)
				}
				signup := p.call(h, "POST", "sign-up/email", map[string]any{"name": "Admin", "email": "admin@service.test", "password": "correct-horse-staple"})
				var admin string
				for _, c := range signup.Result().Cookies() {
					if strings.Contains(c.Name, "session_token") {
						admin = c.Name + "=" + c.Value
					}
				}
				register := func(id string, services []map[string]any) int {
					t.Helper()
					cfg := map[string]any{"entryPoint": legacy, "idpMetadata": map[string]any{"entityID": samlPolicyIdP + "/metadata", "singleSignOnService": services}, "cert": p.idpPEM, "spMetadata": map[string]any{"entityID": "https://service.test/sp/" + id}}
					var buf bytes.Buffer
					if err := json.NewEncoder(&buf).Encode(map[string]any{"providerId": id, "issuer": "https://service.test/sp/" + id, "domain": id + ".example", "samlConfig": cfg}); err != nil {
						t.Fatal(err)
					}
					req := httptest.NewRequest("POST", "https://service.test/identity/sso/register", &buf)
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Origin", "https://service.test")
					req.Header.Set("Cookie", admin)
					w := httptest.NewRecorder()
					h.ServeHTTP(w, req)
					return w.Code
				}
				service := func(binding, location string) map[string]any {
					return map[string]any{"Binding": binding, "Location": location}
				}
				if code := register("listed", []map[string]any{service(saml.HTTPRedirectBinding, samlPolicyIdP+"/sso")}); code != 200 {
					t.Fatal("a manual sign-in service was refused", code)
				}
				for name, services := range map[string][]map[string]any{
					"post only":     {service(saml.HTTPPostBinding, samlPolicyIdP+"/post")},
					"plain HTTP":    {service(saml.HTTPRedirectBinding, "http://identity.example.test/sso")},
					"query":         {service(saml.HTTPRedirectBinding, samlPolicyIdP+"/sso?tenant=one")},
					"two redirects": {service(saml.HTTPRedirectBinding, samlPolicyIdP+"/sso"), service(saml.HTTPRedirectBinding, samlPolicyIdP+"/other")},
					"empty":         {},
				} {
					if code := register("refused", services); code != 400 {
						t.Fatal("an unusable manual sign-in service was accepted", name, code)
					}
				}
			})
			t.Run("registration algorithms", func(t *testing.T) {
				p := newSAMLPolicy(t, dialect)
				def := p.host(sso.SAMLOptions{}, nil)
				allowList := p.host(sso.SAMLOptions{Algorithms: sso.SAMLAlgorithms{AllowedSignatureAlgorithms: []sso.SignatureAlgorithm{sso.SignatureRSASHA256}}}, nil)
				signup := p.call(def, "POST", "sign-up/email", map[string]any{"name": "Admin", "email": "admin@service.test", "password": "correct-horse-staple"})
				var admin string
				for _, c := range signup.Result().Cookies() {
					if strings.Contains(c.Name, "session_token") {
						admin = c.Name + "=" + c.Value
					}
				}
				register := func(h *auth.Auth, id string, algorithms map[string]any) (int, string, string) {
					t.Helper()
					cfg := map[string]any{"entryPoint": samlPolicyIdP + "/sso", "idpMetadata": map[string]any{"entityID": samlPolicyIdP + "/metadata"}, "cert": p.idpPEM, "spMetadata": map[string]any{"entityID": "https://service.test/sp/" + id}}
					for k, v := range algorithms {
						cfg[k] = v
					}
					var buf bytes.Buffer
					if err := json.NewEncoder(&buf).Encode(map[string]any{"providerId": id, "issuer": "https://service.test/sp/" + id, "domain": id + ".example", "samlConfig": cfg}); err != nil {
						t.Fatal(err)
					}
					req := httptest.NewRequest("POST", "https://service.test/identity/sso/register", &buf)
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Origin", "https://service.test")
					req.Header.Set("Cookie", admin)
					w := httptest.NewRecorder()
					h.ServeHTTP(w, req)
					var body struct{ Code, Message string }
					_ = json.Unmarshal(w.Body.Bytes(), &body)
					return w.Code, body.Code, body.Message
				}
				if status, code, message := register(def, "bad-sig", map[string]any{"signatureAlgorithm": "rsa-sha1"}); status != 400 || code != "SAML_DEPRECATED_CONFIG_ALGORITHM" || message != "SAML config uses deprecated signature algorithm: rsa-sha1. Consider using SHA-256 or stronger." {
					t.Fatal("registration accepted a deprecated signatureAlgorithm", status, code, message)
				}
				if status, code, _ := register(def, "bad-digest", map[string]any{"digestAlgorithm": "sha1"}); status != 400 || code != "SAML_DEPRECATED_CONFIG_ALGORITHM" {
					t.Fatal("registration accepted a deprecated digestAlgorithm", status, code)
				}
				if status, code, _ := register(def, "bad-unknown", map[string]any{"signatureAlgorithm": "md5"}); status != 400 || code != "SAML_UNKNOWN_ALGORITHM" {
					t.Fatal("registration accepted an unknown signatureAlgorithm", status, code)
				}
				if status, code, _ := register(allowList, "bad-listed", map[string]any{"signatureAlgorithm": "rsa-sha512"}); status != 400 || code != "SAML_ALGORITHM_NOT_ALLOWED" {
					t.Fatal("registration accepted a signatureAlgorithm outside the allow-list", status, code)
				}
				var stored int
				if err := p.store.db.QueryRowContext(t.Context(), p.store.bind(`SELECT COUNT(*) FROM "ssoProvider" WHERE "providerId" LIKE 'bad-%'`)).Scan(&stored); err != nil || stored != 0 {
					t.Fatal("a refused algorithm registration stored a provider", stored, err)
				}
				if status, code, message := register(def, "good-alg", map[string]any{"signatureAlgorithm": "rsa-sha256", "digestAlgorithm": "sha256"}); status != 200 {
					t.Fatal("registration refused supported algorithms", status, code, message)
				}
				read := httptest.NewRequest("GET", "https://service.test/identity/sso/get-provider?providerId=good-alg", nil)
				read.Header.Set("Cookie", admin)
				w := httptest.NewRecorder()
				def.ServeHTTP(w, read)
				var got struct {
					SAMLConfig struct{ SignatureAlgorithm, DigestAlgorithm string } `json:"samlConfig"`
				}
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.SAMLConfig.SignatureAlgorithm != "rsa-sha256" || got.SAMLConfig.DigestAlgorithm != "sha256" {
					t.Fatal("get-provider did not return the registered algorithms", w.Code, w.Body.String())
				}
			})
			t.Run("identifier format", func(t *testing.T) {
				const persistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
				p := newSAMLPolicy(t, dialect)
				p.directory("persistent", func(cfg *sso.SAMLConfig) { cfg.IdentifierFormat = persistent })
				p.nameIDFormat = persistent
				def := p.host(sso.SAMLOptions{}, nil)
				w := p.call(def, "GET", "sso/saml2/sp/metadata?providerId=persistent", nil)
				var md saml.EntityDescriptor
				if xml.Unmarshal(w.Body.Bytes(), &md) != nil || len(md.SPSSODescriptors) != 1 || len(md.SPSSODescriptors[0].NameIDFormats) != 1 || string(md.SPSSODescriptors[0].NameIDFormats[0]) != persistent {
					t.Fatal("SP metadata did not advertise the directory's identifierFormat", w.Body.String())
				}
				req, state := p.start(def, "persistent")
				if req.Request.NameIDPolicy == nil || req.Request.NameIDPolicy.Format == nil || *req.Request.NameIDPolicy.Format != persistent {
					t.Fatal("the AuthnRequest did not ask for the directory's identifierFormat", req.Request.NameIDPolicy)
				}
				done := p.finish(def, "persistent", req, state, func(idp *saml.IdentityProvider) { idp.EnforceNameIDPolicy = true }, nil, nil)
				if location, session := samlOutcome(t, done); location.String() != "https://service.test/home" || !session {
					t.Fatal("a sign-in requesting a persistent NameID failed", location)
				}
			})
			t.Run("audience", func(t *testing.T) {
				p := newSAMLPolicy(t, dialect)
				const audience = "urn:example:audience"
				p.directory("aud", func(c *sso.SAMLConfig) { c.Audience = audience })
				p.directory("plain", nil)
				h := p.host(sso.SAMLOptions{}, nil)
				restrict := func(groups ...[]string) func(*saml.Assertion) {
					return func(a *saml.Assertion) {
						a.Conditions.AudienceRestrictions = nil
						for _, g := range groups {
							r := saml.AudienceRestriction{Audience: saml.Audience{Value: g[0]}}
							for _, more := range g[1:] {
								r.AdditionalAudiences = append(r.AdditionalAudiences, saml.Audience{Value: more})
							}
							a.Conditions.AudienceRestrictions = append(a.Conditions.AudienceRestrictions, r)
						}
					}
				}
				run := func(id string, adjust func(*saml.Assertion)) (*url.URL, bool) {
					t.Helper()
					req, state := p.start(h, id)
					return samlOutcome(t, p.finish(h, id, req, state, nil, adjust, nil))
				}
				signedIn := func(location *url.URL, session bool) bool {
					return location.String() == "https://service.test/home" && session
				}
				refused := func(location *url.URL, session bool, description string) bool {
					return location.Path == "/retry" && location.Query().Get("error") == "invalid_saml_response" && location.Query().Get("error_description") == description && !session
				}
				sp := func(id string) string { return "https://service.test/sp/" + id }
				for _, groups := range [][][]string{{{audience}}, {{sp("aud"), audience}}, {{audience}, {sp("aud")}}} {
					if location, session := run("aud", restrict(groups...)); !signedIn(location, session) {
						t.Fatal("an assertion naming the configured audience was refused", groups, location)
					}
				}
				if location, session := run("aud", restrict([]string{sp("aud")})); !refused(location, session, "Audience mismatch") {
					t.Fatal("an assertion naming only the SP was accepted under a configured audience", location)
				}
				for _, groups := range [][][]string{{{"urn:other"}}, {{audience}, {"urn:other"}}} {
					if location, session := run("aud", restrict(groups...)); !refused(location, session, "SAML assertion audience does not match this Service Provider") {
						t.Fatal("a restriction naming neither the SP nor the audience was accepted", groups, location)
					}
				}
				if location, session := run("plain", restrict([]string{sp("plain")})); !signedIn(location, session) {
					t.Fatal("an assertion naming the SP was refused without a configured audience", location)
				}
				if location, session := run("plain", restrict([]string{sp("plain")}, []string{"urn:other"})); !refused(location, session, "SAML assertion audience does not match this Service Provider") {
					t.Fatal("a second restriction naming another audience was accepted", location)
				}
				if location, session := run("plain", restrict()); !refused(location, session, "SAML assertion is missing an AudienceRestriction") {
					t.Fatal("an assertion without an AudienceRestriction was not reported as missing one", location)
				}
				// Audiences are trimmed, and a restriction holding only empty
				// ones counts as missing.
				for _, empty := range []string{"", "   "} {
					if location, session := run("plain", restrict([]string{empty})); !refused(location, session, "SAML assertion is missing an AudienceRestriction") {
						t.Fatal("an AudienceRestriction without values was not reported as missing", location)
					}
				}
				if location, session := run("plain", restrict([]string{sp("plain")}, []string{""})); !refused(location, session, "SAML assertion audience does not match this Service Provider") {
					t.Fatal("an empty restriction beside a matching one was accepted", location)
				}
				if location, session := run("plain", restrict([]string{" " + sp("plain") + " "})); !signedIn(location, session) {
					t.Fatal("a padded SP audience was refused", location)
				}
			})
			t.Run("timestamps", func(t *testing.T) {
				p := newSAMLPolicy(t, dialect)
				p.directory("clock", nil)
				var buf lockedLog
				def, strict, required := p.host(sso.SAMLOptions{}, nil), p.host(sso.SAMLOptions{ClockSkew: time.Minute}, nil), p.host(sso.SAMLOptions{RequireTimestamps: true}, nil)
				logged := p.host(sso.SAMLOptions{}, slog.New(slog.NewTextHandler(&buf, nil)))
				run := func(h *auth.Auth, adjust func(*saml.Assertion)) (*url.URL, bool) {
					t.Helper()
					req, state := p.start(h, "clock")
					return samlOutcome(t, p.finish(h, "clock", req, state, nil, adjust, nil))
				}
				refused := func(location *url.URL, session bool, description string) bool {
					return location.Path == "/retry" && location.Query().Get("error") == "saml_error" && location.Query().Get("error_description") == description && !session
				}
				expired := func(ago time.Duration) func(*saml.Assertion) {
					return func(a *saml.Assertion) { a.Conditions.NotOnOrAfter = time.Now().Add(-ago) }
				}
				future := func(ahead time.Duration) func(*saml.Assertion) {
					return func(a *saml.Assertion) { a.Conditions.NotBefore = time.Now().Add(ahead) }
				}
				if location, session := run(def, expired(2*time.Minute)); location.String() != "https://service.test/home" || !session {
					t.Fatal("an assertion expired within the default clock skew was refused", location)
				}
				if location, session := run(strict, expired(2*time.Minute)); !refused(location, session, "SAML assertion has expired") {
					t.Fatal("a one-minute clock skew accepted an assertion expired two minutes ago", location)
				}
				if location, session := run(def, expired(time.Hour)); !refused(location, session, "SAML assertion has expired") {
					t.Fatal("an hour-old assertion did not fail with saml_error", location)
				}
				if location, session := run(strict, future(2*time.Minute)); !refused(location, session, "SAML assertion is not yet valid") {
					t.Fatal("a one-minute clock skew accepted an assertion valid only in two minutes", location)
				}
				if location, session := run(def, future(time.Hour)); !refused(location, session, "SAML assertion is not yet valid") {
					t.Fatal("a future assertion did not fail with saml_error", location)
				}
				// The bearer confirmation's deadline is narrowed before the
				// user is provisioned, even when Conditions are valid. A fresh
				// directory shows that no user is stored.
				p.directory("bearer", nil)
				bearer := func(a *saml.Assertion) {
					a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = time.Now().Add(-2 * time.Minute)
				}
				req, state := p.start(strict, "bearer")
				location, session := samlOutcome(t, p.finish(strict, "bearer", req, state, nil, bearer, nil))
				var users int
				if err := p.store.db.QueryRowContext(t.Context(), p.store.bind(`SELECT COUNT(*) FROM "user" WHERE "email"=?`), "employee-bearer@bearer.example").Scan(&users); err != nil || !refused(location, session, "SAML assertion has expired") || users != 0 {
					t.Fatal("a one-minute clock skew accepted a bearer confirmation expired two minutes ago", location, users, err)
				}
				if location, session := run(def, bearer); location.String() != "https://service.test/home" || !session {
					t.Fatal("a bearer confirmation expired within the default clock skew was refused", location)
				}
				untimed := func(a *saml.Assertion) { a.Conditions.NotBefore, a.Conditions.NotOnOrAfter = time.Time{}, time.Time{} }
				if location, session := run(logged, untimed); location.String() != "https://service.test/home" || !session || buf.count("SAML assertion accepted without timestamp conditions") != 1 || buf.count("providerId=clock") != 1 {
					t.Fatal("an assertion without timestamps was refused or not logged", location)
				}
				if location, session := run(required, untimed); !refused(location, session, "SAML assertion missing required timestamp conditions") {
					t.Fatal("RequireTimestamps accepted an assertion without timestamp conditions", location)
				}
				if location, session := run(required, func(a *saml.Assertion) { a.Conditions.NotOnOrAfter = time.Time{} }); location.String() != "https://service.test/home" || !session {
					t.Fatal("RequireTimestamps refused an assertion that has NotBefore", location)
				}
			})
		})
	}
}
