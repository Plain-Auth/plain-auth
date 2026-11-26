package sso

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// SAMLCertificateInfo summarizes one signing certificate of a SAML
// directory, in another runtime's form, or names why it could not be read.
type SAMLCertificateInfo struct {
	// FingerprintSHA256 is the SHA-256 of the certificate as uppercase,
	// colon-separated hex.
	FingerprintSHA256 string `json:"fingerprintSha256,omitempty"`
	// NotBefore and NotAfter are UTC times such as "Jan  2 15:04:05 2026 GMT".
	NotBefore string `json:"notBefore,omitempty"`
	NotAfter  string `json:"notAfter,omitempty"`
	// PublicKeyAlgorithm is RSA, EC, ED25519 or UNKNOWN; another runtime
	// also names DSA keys, which SAML directories do not use.
	PublicKeyAlgorithm string `json:"publicKeyAlgorithm,omitempty"`
	Error              string `json:"error,omitempty"`
}

// signingCertificates summarizes the configured signing certificates:
// idpMetadata.cert, else cert. It is nil when neither is set, as in another
// runtime, even when IdP metadata XML carries certificates.
func signingCertificates(c *SAMLConfig) []SAMLCertificateInfo {
	certs := c.IDPMetadata.Certificates
	if len(certs) == 0 {
		certs = c.Certificates
	}
	var out []SAMLCertificateInfo
	for _, raw := range certs {
		out = append(out, certificateSummary(raw))
	}
	return out
}

func certificateSummary(raw string) SAMLCertificateInfo {
	failed := SAMLCertificateInfo{Error: "Failed to parse certificate"}
	text := strings.TrimSpace(raw)
	// IdP metadata carries bare base64, so add the PEM armour another
	// runtime adds.
	if !strings.Contains(text, "-----BEGIN") {
		text = "-----BEGIN CERTIFICATE-----\n" + text + "\n-----END CERTIFICATE-----"
	}
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return failed
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return failed
	}
	sum := sha256.Sum256(cert.Raw)
	hex := make([]string, len(sum))
	for i, b := range sum {
		hex[i] = fmt.Sprintf("%02X", b)
	}
	algorithm := "UNKNOWN"
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		algorithm = "RSA"
	case *ecdsa.PublicKey:
		algorithm = "EC"
	case ed25519.PublicKey:
		algorithm = "ED25519"
	}
	const layout = "Jan _2 15:04:05 2006 GMT"
	return SAMLCertificateInfo{FingerprintSHA256: strings.Join(hex, ":"), NotBefore: cert.NotBefore.UTC().Format(layout), NotAfter: cert.NotAfter.UTC().Format(layout), PublicKeyAlgorithm: algorithm}
}
