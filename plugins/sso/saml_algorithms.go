package sso

import (
	"errors"
	"slices"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/beevik/etree"
)

// SignatureAlgorithm is an XML Signature method URI (RFC 6931) for SAML
// messages.
type SignatureAlgorithm string

// The XML Signature methods. RSA-SHA1 is deprecated and always refused.
const (
	SignatureRSASHA1     SignatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	SignatureRSASHA256   SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	SignatureRSASHA384   SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	SignatureRSASHA512   SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	SignatureECDSASHA256 SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	SignatureECDSASHA384 SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	SignatureECDSASHA512 SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
)

// DigestAlgorithm is an XML Signature digest method URI.
type DigestAlgorithm string

// The XML Signature digests. SHA-1 is deprecated and always refused.
const (
	DigestSHA1   DigestAlgorithm = "http://www.w3.org/2000/09/xmldsig#sha1"
	DigestSHA256 DigestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256"
	DigestSHA384 DigestAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	DigestSHA512 DigestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha512"
)

// KeyEncryptionAlgorithm is an XML Encryption key transport URI. This service
// decrypts only KeyEncryptionRSAOAEPSHA256, with SHA-256 digest and
// MGF1-SHA256 parameters.
type KeyEncryptionAlgorithm string

// The XML Encryption key transports. RSA 1.5 is deprecated.
const (
	KeyEncryptionRSA15         KeyEncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	KeyEncryptionRSAOAEP       KeyEncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	KeyEncryptionRSAOAEPSHA256 KeyEncryptionAlgorithm = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
)

// DataEncryptionAlgorithm is an XML Encryption content cipher URI. This
// service decrypts only DataEncryptionAES256GCM.
type DataEncryptionAlgorithm string

// The XML Encryption content ciphers. Triple DES is deprecated.
const (
	DataEncryptionTripleDESCBC DataEncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
	DataEncryptionAES128CBC    DataEncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	DataEncryptionAES192CBC    DataEncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
	DataEncryptionAES256CBC    DataEncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	DataEncryptionAES128GCM    DataEncryptionAlgorithm = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	DataEncryptionAES192GCM    DataEncryptionAlgorithm = "http://www.w3.org/2009/xmlenc11#aes192-gcm"
	DataEncryptionAES256GCM    DataEncryptionAlgorithm = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
)

// SAMLAlgorithms narrows the XML signature algorithms SAML responses and
// directory configurations may use. An empty list accepts every supported
// algorithm of its kind. Deprecated algorithms (SHA-1 signatures and
// digests, RSA 1.5 and Triple DES) are always refused and cannot be listed;
// there is no warn or allow mode.
type SAMLAlgorithms struct {
	// AllowedSignatureAlgorithms lists the signature methods a response may
	// use and a directory's samlConfig.signatureAlgorithm may name.
	AllowedSignatureAlgorithms []SignatureAlgorithm
	// AllowedDigestAlgorithms lists the digests a directory's
	// samlConfig.digestAlgorithm may name. Unlike another runtime, the list
	// also applies to the digests of response signatures.
	AllowedDigestAlgorithms []DigestAlgorithm
}

var (
	secureSignatureAlgorithms = []SignatureAlgorithm{SignatureRSASHA256, SignatureRSASHA384, SignatureRSASHA512, SignatureECDSASHA256, SignatureECDSASHA384, SignatureECDSASHA512}
	secureDigestAlgorithms    = []DigestAlgorithm{DigestSHA256, DigestSHA384, DigestSHA512}
)

// validate refuses allow-list entries outside the supported algorithms.
// List full URIs using the exported constants; short forms such as
// rsa-sha256 are accepted only in a directory's samlConfig.
func (a SAMLAlgorithms) validate() error {
	for _, v := range a.AllowedSignatureAlgorithms {
		if !slices.Contains(secureSignatureAlgorithms, v) {
			return errors.New("sso: SAML signature allow-list entries must be RSA or ECDSA with SHA-256, SHA-384 or SHA-512")
		}
	}
	for _, v := range a.AllowedDigestAlgorithms {
		if !slices.Contains(secureDigestAlgorithms, v) {
			return errors.New("sso: SAML digest allow-list entries must be SHA-256, SHA-384 or SHA-512")
		}
	}
	return nil
}

func samlAlgorithmFailure(code, message string) *auth.APIError {
	return &auth.APIError{Status: 400, Code: code, Message: message}
}

// checkSAMLAlgorithm applies an allow-list first, then the deprecated
// algorithm, then the supported ones. shown names the value in the message,
// and is empty for a value the host did not choose.
func checkSAMLAlgorithm[T ~string](kind string, value T, allowed, secure []T, deprecated T, shown, fix string) error {
	if value == "" {
		return nil
	}
	if shown != "" {
		shown = ": " + shown
	}
	if len(allowed) > 0 && !slices.Contains(allowed, value) {
		return samlAlgorithmFailure("SAML_ALGORITHM_NOT_ALLOWED", "SAML "+kind+" algorithm not in allow-list"+shown)
	}
	if value == deprecated {
		return samlAlgorithmFailure("SAML_DEPRECATED_ALGORITHM", "SAML response uses deprecated "+kind+" algorithm"+shown+". Please configure your IdP to use "+fix+".")
	}
	if !slices.Contains(secure, value) {
		return samlAlgorithmFailure("SAML_UNKNOWN_ALGORITHM", "SAML "+kind+" algorithm not recognized"+shown)
	}
	return nil
}

// exportedURI returns uri when it is one of the exported constants, so an
// IdP-supplied string is never copied into a redirect.
func exportedURI[T ~string](uri T, known ...T) string {
	if slices.Contains(known, uri) {
		return string(uri)
	}
	return ""
}

// checkSignatures applies the policy to the enveloped ds:Signature of each
// element before the library verifies it. It can only refuse: the library
// still verifies everything accepted, and RejectSHA1Signatures stays on.
func (a SAMLAlgorithms) checkSignatures(elements ...*etree.Element) error {
	for _, el := range elements {
		if el == nil {
			continue
		}
		signed := false
		for _, child := range el.ChildElements() {
			signed = signed || child.Tag == "Signature"
		}
		if !signed {
			continue
		}
		// A second or foreign Signature child fails closed: the library may
		// still pick a ds:Signature the policy never inspected.
		info := uniqueChild(uniqueChild(el, signatureNS, "Signature"), signatureNS, "SignedInfo")
		if info == nil {
			return errSAMLResponse
		}
		method := SignatureAlgorithm(uniqueAttribute(uniqueChild(info, signatureNS, "SignatureMethod"), "Algorithm"))
		knownSignatures := append(slices.Clone(secureSignatureAlgorithms), SignatureRSASHA1)
		if err := checkSAMLAlgorithm("signature", method, a.AllowedSignatureAlgorithms, secureSignatureAlgorithms, SignatureRSASHA1, exportedURI(method, knownSignatures...), "SHA-256 or stronger"); err != nil {
			return err
		}
		for _, ref := range info.ChildElements() {
			if ref.Tag != "Reference" {
				continue
			}
			digest := DigestAlgorithm(uniqueAttribute(uniqueChild(ref, signatureNS, "DigestMethod"), "Algorithm"))
			knownDigests := append(slices.Clone(secureDigestAlgorithms), DigestSHA1)
			if err := checkSAMLAlgorithm("digest", digest, a.AllowedDigestAlgorithms, secureDigestAlgorithms, DigestSHA1, exportedURI(digest, knownDigests...), "SHA-256 or stronger"); err != nil {
				return err
			}
		}
	}
	return nil
}

// deprecatedSAMLResponseAlgorithm refuses a deprecated encryption algorithm
// of a response.
func deprecatedSAMLResponseAlgorithm(kind, uri, fix string) error {
	return samlAlgorithmFailure("SAML_DEPRECATED_ALGORITHM", "SAML response uses deprecated "+kind+" algorithm: "+uri+". Please configure your IdP to use "+fix+".")
}
