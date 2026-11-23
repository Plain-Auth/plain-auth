package sso

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/crewjam/saml"
	"math/big"
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
	if got := samlProvisioningDeadline(a, acs, "_id", now); !got.Equal(late) {
		t.Fatal("did not use the last matching confirmation", got)
	}
	a.Conditions.NotOnOrAfter = early.Add(-saml.MaxClockSkew)
	if got := samlProvisioningDeadline(a, acs, "_id", now); !got.Equal(early) {
		t.Fatal("provisioning exceeded assertion conditions", got)
	}
	a.IssueInstant = now.Add(-saml.MaxIssueDelay)
	if got := samlProvisioningDeadline(a, acs, "_id", now); !got.Equal(now) {
		t.Fatal("provisioning exceeded assertion age", got)
	}
}
