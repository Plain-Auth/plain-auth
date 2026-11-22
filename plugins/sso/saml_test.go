package sso

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
)

func TestSAMLConfigurationModes(t *testing.T) {
	const supported = `{"entryPoint":"https://idp.example/sso","idpMetadata":{"entityID":"urn:example:idp"}`
	for _, suffix := range []string{`,"wantAssertionsSigned":false}`, `,"spMetadata":{"metadata":"<xml/>"}}`, `,"privateKey":"unused"}`, `,"spMetadata":{"encPrivateKey":"unused"}}`, `,"spMetadata":{"encPrivateKeyPass":"unused"}}`, `,"idpInitiatedCallbackUrl":"/home"}`, `}{ }`} {
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
