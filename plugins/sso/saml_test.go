package sso

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	auth "github.com/Plain-Org/plain-auth"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/xmlenc"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestSAMLConfigurationModes(t *testing.T) {
	const supported = `{"entryPoint":"https://idp.example/sso","idpMetadata":{"entityID":"urn:example:idp"}`
	for _, suffix := range []string{`,"wantAssertionsSigned":false}`, `,"spMetadata":{"metadata":"<xml/>"}}`, `,"privateKey":"unused"}`, `,"spMetadata":{"encPrivateKey":"unused"}}`, `,"spMetadata":{"encPrivateKeyPass":"unused"}}`, `,"idpInitiatedCallbackUrl":"not a landing URL"}`, `}{ }`} {
		if _, err := DecodeSAMLConfig([]byte(supported + suffix)); err == nil {
			t.Errorf("unexpected supported mode %s", suffix)
		}
	}
	for _, cert := range []string{`"first"`, `["first","second"]`} {
		v, err := DecodeSAMLConfig([]byte(supported + `,"cert":` + cert + `,"spMetadata":{"entityID":"urn:example:sp"}}`))
		if err != nil || v.Certificates[0] != "first" {
			t.Fatal(err)
		}
	}
}

func TestSAMLBrowserOrigin(t *testing.T) {
	const entry = "https://IDENTITY.example.test:443/sso"
	for _, origin := range []string{"https://identity.example.test", "https://identity.example.test:443"} {
		if !sameSAMLOrigin(origin, entry) {
			t.Errorf("browser origin %q must match", origin)
		}
	}
	for _, origin := range []string{"", "null", "http://identity.example.test", "https://identity.example.test:444", "https://other.example.test", "https://identity.example.test/path", "https://identity.example.test?", "https://identity.example.test#", "https://admin@identity.example.test"} {
		if sameSAMLOrigin(origin, entry) {
			t.Errorf("unexpected match for %q", origin)
		}
	}
}

func TestInlineSAMLMetadataSizeOption(t *testing.T) {
	for _, size := range []int{-1, (1 << 20) + 1} {
		if _, err := New(Options{SAML: &SAMLOptions{MaxMetadataSize: size}}); err == nil {
			t.Fatalf("accepted size %d", size)
		}
	}
	for _, size := range []int{0, 4096, 1 << 20} {
		option := SAMLOptions{MaxMetadataSize: size}
		if _, err := New(Options{SAML: &option}); err != nil {
			t.Fatal(err)
		}
		want := size
		if want == 0 {
			want = 100 * 1024
		}
		if option.metadataLimit() != want {
			t.Fatal("metadata size default")
		}
	}
}

func TestSAMLEncryptionHostKeys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), KeyUsage: x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	for _, keys := range []SAMLEncryption{{}, {PrivateKey: key}, {Certificate: cert}, {PrivateKey: other, Certificate: cert}, {PrivateKey: key, Certificate: &x509.Certificate{PublicKey: &key.PublicKey}}} {
		if _, err := New(Options{SAML: &SAMLOptions{Encryption: &keys}}); err == nil {
			t.Fatal("accepted an incomplete or inconsistent recipient identity")
		}
	}
	if _, err := New(Options{SAML: &SAMLOptions{Encryption: &SAMLEncryption{PrivateKey: key, Certificate: cert}}}); err != nil {
		t.Fatal(err)
	}
}

func TestSAMLLogoutConfiguration(t *testing.T) {
	if _, e := New(Options{SAML: &SAMLOptions{EnableIDPInitiatedLogout: true}}); e == nil {
		t.Fatal("IdP logout enabled without single logout")
	}
	if _, e := New(Options{SAML: &SAMLOptions{EnableSingleLogout: true}}); e == nil {
		t.Fatal("missing SP signing credentials accepted")
	}
	for _, ttl := range []time.Duration{-time.Second, time.Millisecond, 1500 * time.Millisecond} {
		if _, e := New(Options{SAML: &SAMLOptions{LogoutRequestTTL: ttl}}); e == nil {
			t.Fatal("invalid logout request lifetime", ttl)
		}
	}
	for _, list := range [][]SAMLService{
		{{Binding: saml.HTTPRedirectBinding, Location: "http://idp.example/logout"}},
		{{Binding: saml.HTTPRedirectBinding, Location: "https://idp.example/logout?binding=x"}},
		{{Binding: saml.HTTPRedirectBinding, Location: "https://idp.example/logout"}, {Binding: saml.HTTPRedirectBinding, Location: "https://idp.example/alternate"}},
	} {
		if _, e := logoutLocation(list); e == nil {
			t.Fatal("unusable logout service accepted")
		}
	}
}

func TestSAMLProvisioningDeadline(t *testing.T) {
	now := time.Now().UTC()
	const acs = "https://app.example/acs"
	confirmation := func(recipient, requestID string, expires time.Time) saml.SubjectConfirmation {
		return saml.SubjectConfirmation{
			Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
			SubjectConfirmationData: &saml.SubjectConfirmationData{
				Recipient: recipient, InResponseTo: requestID, NotOnOrAfter: expires.Add(-saml.MaxClockSkew),
			},
		}
	}
	early, late := now.Add(time.Second), now.Add(2*time.Second)
	a := &saml.Assertion{
		IssueInstant: now, Conditions: &saml.Conditions{NotOnOrAfter: now.Add(time.Hour)},
		Subject: &saml.Subject{SubjectConfirmations: []saml.SubjectConfirmation{
			confirmation(acs, "_id", early), confirmation(acs, "_id", late),
			confirmation(acs, "_other", now.Add(time.Hour)), confirmation("elsewhere", "_id", now.Add(time.Hour)),
		}},
	}
	if got := samlProvisioningDeadline(a, acs, "_id", now, saml.MaxClockSkew); !got.Equal(late) {
		t.Fatal("did not use the last matching confirmation", got)
	}
	untimed := *a
	untimed.Conditions = &saml.Conditions{}
	if got := samlProvisioningDeadline(&untimed, acs, "_id", now, saml.MaxClockSkew); !got.Equal(late) {
		t.Fatal("an assertion without NotOnOrAfter lost its provisioning deadline", got)
	}
	a.Conditions.NotOnOrAfter = early.Add(-saml.MaxClockSkew)
	if got := samlProvisioningDeadline(a, acs, "_id", now, saml.MaxClockSkew); !got.Equal(early) {
		t.Fatal("provisioning exceeded assertion conditions", got)
	}
	a.IssueInstant = now.Add(-saml.MaxIssueDelay)
	if got := samlProvisioningDeadline(a, acs, "_id", now, saml.MaxClockSkew); !got.Equal(now) {
		t.Fatal("provisioning exceeded assertion age", got)
	}
}

// A SAML profile carries the raw attributes for ValidateUserInfo: one value
// as a string and several as a list.
func TestSAMLProfileRawAttributes(t *testing.T) {
	assertion := &saml.Assertion{
		Subject: &saml.Subject{NameID: &saml.NameID{Value: "employee"}},
		AttributeStatements: []saml.AttributeStatement{{Attributes: []saml.Attribute{
			{Name: "email", Values: []saml.AttributeValue{{Value: "Employee@Example.test"}}},
			{Name: "groups", Values: []saml.AttributeValue{{Value: "staff"}, {Value: "admins"}}},
		}}},
	}
	profile, err := samlProfile(assertion, SAMLMapping{}, false)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := profile.Data.(map[string]any)
	if !ok || raw["email"] != "Employee@Example.test" || len(raw["groups"].([]string)) != 2 || profile.Email != "employee@example.test" {
		t.Fatalf("the profile data was %#v", profile.Data)
	}
}

// The SAML name joins givenName and surname (or the mapped names), falls back
// to displayName and then the NameID, and several values for one name
// attribute refuse the response.
func TestSAMLProfileNameParts(t *testing.T) {
	profile := func(m SAMLMapping, attrs ...saml.Attribute) (auth.OAuthProfile, error) {
		return samlProfile(&saml.Assertion{Subject: &saml.Subject{NameID: &saml.NameID{Value: "employee@acme.example"}}, AttributeStatements: []saml.AttributeStatement{{Attributes: attrs}}}, m, false)
	}
	attr := func(name string, values ...string) saml.Attribute {
		a := saml.Attribute{Name: name}
		for _, v := range values {
			a.Values = append(a.Values, saml.AttributeValue{Value: v})
		}
		return a
	}
	name := func(m SAMLMapping, attrs ...saml.Attribute) string {
		t.Helper()
		p, err := profile(m, attrs...)
		if err != nil {
			t.Fatal(err)
		}
		return p.Name
	}
	if got := name(SAMLMapping{}, attr("givenName", "Ada"), attr("surname", "Lovelace")); got != "Ada Lovelace" {
		t.Fatal("givenName and surname were not joined into the name", got)
	}
	if got := name(SAMLMapping{}, attr("givenName", "Ada")); got != "Ada" {
		t.Fatal("a first name alone did not become the name", got)
	}
	if got := name(SAMLMapping{}, attr("surname", "Lovelace")); got != "Lovelace" {
		t.Fatal("a last name alone did not become the name", got)
	}
	if got := name(SAMLMapping{FirstName: "first", LastName: "last"}, attr("first", "Grace"), attr("last", "Hopper"), attr("givenName", "Ada")); got != "Grace Hopper" {
		t.Fatal("mapped firstName and lastName attributes were not used", got)
	}
	if got := name(SAMLMapping{}, attr("displayName", "Countess")); got != "Countess" {
		t.Fatal("displayName was not used without name parts", got)
	}
	if got := name(SAMLMapping{}); got != "employee@acme.example" {
		t.Fatal("the NameID was not used without any name attribute", got)
	}
	if _, err := profile(SAMLMapping{}, attr("givenName", "Ada", "Augusta")); err == nil {
		t.Fatal("several values for a name attribute were accepted")
	}
}

// A response passes only with exactly one top-level signed assertion; the
// assertion count names a missing or second assertion, plain or encrypted.
func TestSAMLAssertionEnvelopeCount(t *testing.T) {
	const acs, request = "https://service.test/identity/sso/saml2/sp/acs/acme", "_request"
	assertion := func(id, inner string) string {
		return `<saml:Assertion ID="` + id + `"><ds:Signature/>` + inner + `</saml:Assertion>`
	}
	enc := `<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedAssertion>`
	response := func(children ...string) []byte {
		return []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Destination="` + acs + `" InResponseTo="` + request + `">` + strings.Join(children, "") + `</samlp:Response>`)
	}
	if id, err := assertionEnvelope(response(assertion("_one", "")), acs, request); err != nil || id != "_one" {
		t.Fatal("a response with one signed assertion failed the envelope check", id, err)
	}
	if _, err := assertionEnvelope(response(assertion("_first", ""), assertion("_second", "")), acs, request); err == nil {
		t.Fatal("a response with two assertions passed the envelope check")
	}
	if _, err := assertionEnvelope(response(assertion("_outer", `<saml:Advice>`+assertion("_inner", "")+`</saml:Advice>`)), acs, request); err == nil {
		t.Fatal("an assertion nested in another assertion passed the envelope check")
	}
	if _, err := assertionEnvelope(response(), acs, request); err == nil {
		t.Fatal("a response without an assertion passed the envelope check")
	}
	for raw, want := range map[string]int{
		string(response()): 0, string(response(assertion("_one", ""))): 1, string(response(enc)): 1,
		string(response(assertion("_a", ""), assertion("_b", ""))): 2, string(response(enc, enc)): 2,
		string(response(assertion("_plain", ""), enc)): 2, string(response(assertion("_outer", `<saml:Advice>`+assertion("_inner", "")+`</saml:Advice>`))): 2,
		"<broken": -1,
	} {
		if got := samlAssertionCount([]byte(raw)); got != want {
			t.Fatal("the assertion count did not name a missing or second assertion", want, got, raw)
		}
	}
}

// MaxResponseSize defaults to 256 KiB, keeps a configured value and refuses
// a negative size or one above the 1 MiB form cap.
func TestSAMLResponseSizeOption(t *testing.T) {
	if _, err := New(Options{SAML: &SAMLOptions{MaxResponseSize: -1}}); err == nil {
		t.Fatal("accepted a negative SAML response size")
	}
	if _, err := New(Options{SAML: &SAMLOptions{MaxResponseSize: (1 << 20) + 1}}); err == nil {
		t.Fatal("accepted a SAML response size above the 1 MiB form cap")
	}
	if limit := (SAMLOptions{}).responseLimit(); limit != 256*1024 {
		t.Fatal("unset SAML response size is not 256 KiB", limit)
	}
	if limit := (SAMLOptions{MaxResponseSize: 4096}).responseLimit(); limit != 4096 {
		t.Fatal("configured SAML response size was not kept", limit)
	}
}

// ClockSkew defaults to three minutes, keeps a narrower value and refuses a
// negative one or one above three minutes.
func TestSAMLClockSkewOption(t *testing.T) {
	if skew := (SAMLOptions{}).clockSkew(); skew != 3*time.Minute {
		t.Fatal("unset SAML clock skew is not three minutes", skew)
	}
	if _, err := New(Options{SAML: &SAMLOptions{ClockSkew: -time.Second}}); err == nil {
		t.Fatal("accepted a negative SAML clock skew")
	}
	if _, err := New(Options{SAML: &SAMLOptions{ClockSkew: 3*time.Minute + time.Second}}); err == nil {
		t.Fatal("accepted a SAML clock skew above three minutes")
	}
	if skew := (SAMLOptions{ClockSkew: time.Minute}).clockSkew(); skew != time.Minute {
		t.Fatal("configured SAML clock skew was not kept", skew)
	}
	now := time.Now()
	stale := &saml.Assertion{IssueInstant: now, Conditions: &saml.Conditions{NotOnOrAfter: now.Add(-90 * time.Second)}}
	if message, _ := (SAMLOptions{ClockSkew: time.Minute}).checkTimestamps(stale, now); message != "SAML assertion has expired" {
		t.Fatal("checkTimestamps ignored a narrowed clock skew", message)
	}
}

// The exported algorithm constants are the XML Signature and XML Encryption
// URIs, the same values the decrypter uses.
func TestSAMLAlgorithmURIs(t *testing.T) {
	for got, want := range map[SignatureAlgorithm]string{
		SignatureRSASHA1: "http://www.w3.org/2000/09/xmldsig#rsa-sha1", SignatureRSASHA256: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		SignatureRSASHA384: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", SignatureRSASHA512: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
		SignatureECDSASHA256: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", SignatureECDSASHA384: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
		SignatureECDSASHA512: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
	} {
		if string(got) != want {
			t.Fatal("signature URIs differ from XML Signature", got, want)
		}
	}
	for got, want := range map[DigestAlgorithm]string{
		DigestSHA1: "http://www.w3.org/2000/09/xmldsig#sha1", DigestSHA256: "http://www.w3.org/2001/04/xmlenc#sha256",
		DigestSHA384: "http://www.w3.org/2001/04/xmldsig-more#sha384", DigestSHA512: "http://www.w3.org/2001/04/xmlenc#sha512",
	} {
		if string(got) != want {
			t.Fatal("digest URIs differ from XML Signature", got, want)
		}
	}
	if string(KeyEncryptionRSAOAEPSHA256) != xmlenc.OAEP_SHA256().Algorithm() || string(KeyEncryptionRSAOAEP) != xmlenc.OAEP().Algorithm() || string(KeyEncryptionRSA15) != xmlenc.PKCS1v15().Algorithm() {
		t.Fatal("key transport URIs differ from the decrypter's")
	}
	if string(DataEncryptionAES256GCM) != xmlenc.AES256GCM.Algorithm() {
		t.Fatal("AES-256-GCM URI differs from the decrypter's")
	}
	if string(DataEncryptionAES128GCM) != xmlenc.AES128GCM.Algorithm() || string(DataEncryptionAES256CBC) != xmlenc.AES256CBC.Algorithm() || string(DataEncryptionTripleDESCBC) != xmlenc.TripleDES.Algorithm() {
		t.Fatal("block cipher URIs differ from the decrypter's")
	}
}
