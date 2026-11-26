package sqlstore

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"log/slog"
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
	return &samlPolicy{t: t, store: store, idpKey: key, idpCert: cert, idpPEM: pem}
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
	plugin, err := sso.New(sso.Options{SAML: &opts})
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
	sess := &saml.Session{ID: "idp-" + id, Index: "index-" + id, CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour), NameID: "employee-" + id,
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
