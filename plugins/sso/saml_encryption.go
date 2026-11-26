package sso

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/xmlenc"
	dsig "github.com/russellhaering/goxmldsig"
)

// SAMLEncryption holds the host's RSA key for decrypting SAML assertions.
// Its certificate is published only for directories that require encryption.
type SAMLEncryption struct {
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate
}

const (
	samlAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
	samlProtocolNS  = "urn:oasis:names:tc:SAML:2.0:protocol"
	signatureNS     = "http://www.w3.org/2000/09/xmldsig#"
	encryptionNS    = "http://www.w3.org/2001/04/xmlenc#"
	encryption11NS  = "http://www.w3.org/2009/xmlenc11#"
	rsaOAEP         = string(KeyEncryptionRSAOAEPSHA256)
	sha256Digest    = string(DigestSHA256)
	mgfSHA256       = encryption11NS + "mgf1sha256"
)

func (keys SAMLEncryption) valid() bool {
	if keys.PrivateKey == nil || keys.PrivateKey.N == nil || keys.PrivateKey.N.BitLen() < 2048 || keys.Certificate == nil {
		return false
	}
	published, err := x509.ParseCertificate(keys.Certificate.Raw)
	return err == nil && keys.PrivateKey.PublicKey.Equal(published.PublicKey) && keys.PrivateKey.PublicKey.Equal(keys.Certificate.PublicKey) && keys.PrivateKey.Validate() == nil
}

func boundedSAMLTree(data []byte) (*etree.Element, error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return nil, errSAMLResponse
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	depth, roots, count := 0, 0, 0
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errSAMLResponse
		}
		switch t := token.(type) {
		case xml.Directive:
			return nil, errSAMLResponse
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
			count++
			if roots > 1 || depth > 64 || count > 5000 {
				return nil, errSAMLResponse
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(t)) != 0 {
				return nil, errSAMLResponse
			}
		}
	}
	if depth != 0 || roots != 1 {
		return nil, errSAMLResponse
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, errSAMLResponse
	}
	return doc.Root(), nil
}

func namedElement(e *etree.Element, ns, name string) bool {
	return e != nil && e.Tag == name && e.NamespaceURI() == ns
}
func uniqueChild(parent *etree.Element, ns, name string) *etree.Element {
	if parent == nil {
		return nil
	}
	var found *etree.Element
	for _, child := range parent.ChildElements() {
		if child.Tag != name {
			continue
		}
		if found != nil || child.NamespaceURI() != ns {
			return nil
		}
		found = child
	}
	return found
}
func uniqueAttribute(e *etree.Element, name string) string {
	if e == nil {
		return ""
	}
	var found bool
	var value string
	for _, attr := range e.Attr {
		if attr.Space == "" && attr.Key == name {
			if found {
				return ""
			}
			found = true
			value = attr.Value
		}
	}
	return value
}

// Count the security-relevant elements throughout the document, independently
// of which child a parser would select as the enclosing assertion.
func assertionShape(root *etree.Element) (assertions, encrypted, data, keys, encryptedFields int) {
	todo := []*etree.Element{root}
	for len(todo) > 0 {
		e := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		switch e.Tag {
		case "Assertion":
			assertions++
		case "EncryptedAssertion":
			encrypted++
		case "EncryptedData":
			data++
		case "EncryptedKey":
			keys++
		case "EncryptedAttribute", "EncryptedID", "CipherReference", "RetrievalMethod":
			encryptedFields++
		}
		todo = append(todo, e.ChildElements()...)
	}
	return
}

func inlineCipherValue(parent *etree.Element) bool {
	cd := uniqueChild(parent, encryptionNS, "CipherData")
	value := uniqueChild(cd, encryptionNS, "CipherValue")
	return cd != nil && len(cd.ChildElements()) == 1 && value != nil && len(value.ChildElements()) == 0 && strings.TrimSpace(value.Text()) != ""
}

// errCBCUnsigned refuses AES-CBC content outside a Response the IdP signed.
// AES-CBC is unauthenticated: decrypting it before a signature covers the
// ciphertext opens the XML Encryption padding oracle (SAML Core errata E93).
// Another runtime decrypts it unsigned.
var errCBCUnsigned = errors.New("SAML response must be signed when the assertion is encrypted with AES-CBC")

func encryptedAssertionID(raw []byte, acs, requestID string, key *rsa.PrivateKey, roots []*x509.Certificate, algorithms SAMLAlgorithms) (string, error) {
	response, err := boundedSAMLTree(raw)
	if err != nil || !namedElement(response, samlProtocolNS, "Response") || uniqueAttribute(response, "Destination") != acs {
		return "", errSAMLResponse
	}
	if requestID != "" && response.SelectAttr("InResponseTo") == nil {
		return "", errUnrequested
	}
	if uniqueAttribute(response, "InResponseTo") != requestID {
		return "", errUnknownRequest
	}
	if requestID == "" && response.SelectAttr("InResponseTo") != nil {
		return "", errSAMLResponse
	}
	ciphertext, cbc, err := encryptedData(response, algorithms)
	if err != nil {
		return "", err
	}
	if err := algorithms.checkSignatures(response); err != nil {
		return "", err
	}
	if cbc {
		// Decrypt only what the Response signature covers, so a node that
		// canonicalization drops cannot change the ciphertext.
		verified := signedResponse(response, roots)
		if verified == nil {
			return "", errCBCUnsigned
		}
		if ciphertext, _, err = encryptedData(verified, algorithms); err != nil {
			return "", errSAMLResponse
		}
	}
	// The library accepts a signed outer response without an assertion signature.
	// Inspect the decrypted shape here to require a directly signed assertion in
	// both cases. ParseXMLResponse then verifies the original signatures, decrypts
	// the original document and validates its subject and conditions.
	plaintext, err := xmlenc.Decrypt(key, ciphertext)
	if err != nil {
		return "", errSAMLResponse
	}
	assertion, err := boundedSAMLTree(plaintext)
	if err != nil || !namedElement(assertion, samlAssertionNS, "Assertion") || uniqueChild(assertion, signatureNS, "Signature") == nil {
		return "", errSAMLResponse
	}
	a, enc, data, keys, other := assertionShape(assertion)
	id := uniqueAttribute(assertion, "ID")
	if a != 1 || enc != 0 || data != 0 || keys != 0 || other != 0 || id == "" || len(id) > 512 {
		return "", errSAMLResponse
	}
	if err := algorithms.checkSignatures(assertion); err != nil {
		return "", err
	}
	return id, nil
}

// encryptedData checks the shape and encryption algorithms of the one
// EncryptedAssertion in response and returns its EncryptedData, reporting
// whether the content cipher is AES-CBC. The key transport is checked
// before the content cipher, in the order another runtime checks them.
func encryptedData(response *etree.Element, algorithms SAMLAlgorithms) (*etree.Element, bool, error) {
	a, enc, data, keys, other := assertionShape(response)
	if a != 0 || enc != 1 || data != 1 || keys != 1 || other != 0 {
		return nil, false, errSAMLResponse
	}
	wrapper := uniqueChild(response, samlAssertionNS, "EncryptedAssertion")
	ciphertext := uniqueChild(wrapper, encryptionNS, "EncryptedData")
	if wrapper == nil || len(wrapper.ChildElements()) != 1 || ciphertext == nil {
		return nil, false, errSAMLResponse
	}
	dataMethod := uniqueChild(ciphertext, encryptionNS, "EncryptionMethod")
	info := uniqueChild(ciphertext, signatureNS, "KeyInfo")
	envelope := uniqueChild(info, encryptionNS, "EncryptedKey")
	wrapMethod := uniqueChild(envelope, encryptionNS, "EncryptionMethod")
	wrap, ok := strictAlgorithm(wrapMethod)
	if !ok {
		return nil, false, errSAMLResponse
	}
	if err := checkEncryption("key encryption", KeyEncryptionAlgorithm(wrap), algorithms.AllowedKeyEncryptionAlgorithms, secureKeyEncryption, KeyEncryptionRSA15, "RSA-OAEP"); err != nil {
		return nil, false, err
	}
	cipher, ok := strictAlgorithm(dataMethod)
	if !ok {
		return nil, false, errSAMLResponse
	}
	if err := checkEncryption("data encryption", DataEncryptionAlgorithm(cipher), algorithms.AllowedDataEncryptionAlgorithms, secureDataEncryption, DataEncryptionTripleDESCBC, "AES-GCM"); err != nil {
		return nil, false, err
	}
	if len(dataMethod.ChildElements()) != 0 || !inlineCipherValue(ciphertext) || !oaepParameters(wrapMethod) {
		return nil, false, errSAMLResponse
	}
	if info == nil || len(info.ChildElements()) != 1 || envelope == nil || !inlineCipherValue(envelope) {
		return nil, false, errSAMLResponse
	}
	return ciphertext, slices.Contains(cbcDataEncryption, DataEncryptionAlgorithm(cipher)), nil
}

// oaepParameters checks a key transport's parameters. rsa-oaep-mgf1p may
// carry one digest, SHA-1 or SHA-256, and XML Encryption 1.1 rsa-oaep one
// digest and one MGF1 hash, each SHA-1, SHA-256, SHA-384 or SHA-512; a
// missing one means SHA-1. Anything else, such as OAEPparams, is refused.
func oaepParameters(method *etree.Element) bool {
	digests := []DigestAlgorithm{DigestSHA1, DigestSHA256}
	var mgfs []string
	if alg, _ := strictAlgorithm(method); alg == string(KeyEncryptionRSAOAEPSHA256) {
		digests = append(digests, DigestSHA384, DigestSHA512)
		mgfs = []string{encryption11NS + "mgf1sha1", mgfSHA256, encryption11NS + "mgf1sha384", encryption11NS + "mgf1sha512"}
	}
	seen := map[string]bool{}
	for _, child := range method.ChildElements() {
		value, ok := strictAlgorithm(child)
		switch {
		case namedElement(child, signatureNS, "DigestMethod"):
			ok = ok && slices.Contains(digests, DigestAlgorithm(value))
		case namedElement(child, encryption11NS, "MGF"):
			ok = ok && slices.Contains(mgfs, value)
		default:
			ok = false
		}
		if !ok || seen[child.Tag] || len(child.ChildElements()) != 0 {
			return false
		}
		seen[child.Tag] = true
	}
	return true
}

// signedResponse verifies the Response's own signature with the directory's
// certificates and returns what it covers, parsed from the digested bytes,
// or nil. A KeyInfo without a certificate is dropped first, as the library
// does, so the configured certificates decide.
func signedResponse(response *etree.Element, roots []*x509.Certificate) *etree.Element {
	el := response.Copy()
	sig := uniqueChild(el, signatureNS, "Signature")
	if sig == nil {
		return nil
	}
	if info := uniqueChild(sig, signatureNS, "KeyInfo"); info != nil && info.FindElement(".//X509Certificate") == nil {
		sig.RemoveChild(info)
	}
	for _, cert := range roots {
		ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
		ctx.IdAttribute = "ID"
		if verified, err := ctx.Validate(el); err == nil {
			return verified
		}
	}
	return nil
}

// idpSigningCertificates returns the directory certificates samlSP placed
// in the IdP metadata.
func idpSigningCertificates(sp *saml.ServiceProvider) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, d := range sp.IDPMetadata.IDPSSODescriptors {
		for _, k := range d.KeyDescriptors {
			for _, c := range k.KeyInfo.X509Data.X509Certificates {
				der, err := base64.StdEncoding.DecodeString(c.Data)
				if err != nil {
					continue
				}
				if cert, err := x509.ParseCertificate(der); err == nil {
					certs = append(certs, cert)
				}
			}
		}
	}
	return certs
}

// assertionDocumentID checks the response envelope and the algorithms of
// its signatures, and returns the one assertion's ID.
func assertionDocumentID(raw []byte, sp *saml.ServiceProvider, requestID string, algorithms SAMLAlgorithms) (string, error) {
	if sp.EncryptionKey != nil {
		return encryptedAssertionID(raw, sp.AcsURL.String(), requestID, sp.EncryptionKey, idpSigningCertificates(sp), algorithms)
	}
	id, err := assertionEnvelope(raw, sp.AcsURL.String(), requestID)
	if err != nil {
		return "", err
	}
	response, err := boundedSAMLTree(raw)
	if err != nil {
		return "", errSAMLResponse
	}
	if err := algorithms.checkSignatures(response, uniqueChild(response, samlAssertionNS, "Assertion")); err != nil {
		return "", err
	}
	return id, nil
}

// encryptionMethods lists the allowed content ciphers, then the allowed key
// transports, for the SP metadata. Without lists it names AES-256-GCM and
// XML Encryption 1.1 rsa-oaep, so IdPs are not steered to AES-CBC.
func (a SAMLAlgorithms) encryptionMethods() []saml.EncryptionMethod {
	data := a.AllowedDataEncryptionAlgorithms
	if len(data) == 0 {
		data = []DataEncryptionAlgorithm{DataEncryptionAES256GCM}
	}
	keys := a.AllowedKeyEncryptionAlgorithms
	if len(keys) == 0 {
		keys = []KeyEncryptionAlgorithm{KeyEncryptionRSAOAEPSHA256}
	}
	var out []saml.EncryptionMethod
	for _, v := range data {
		out = append(out, saml.EncryptionMethod{Algorithm: string(v)})
	}
	for _, v := range keys {
		out = append(out, saml.EncryptionMethod{Algorithm: string(v)})
	}
	return out
}

// The metadata model can name a key transport but cannot encode its digest or MGF.
// Publish both parameters on an advertised XML Encryption 1.1 rsa-oaep method,
// because the XML Encryption defaults use SHA-1.
func advertiseOAEPParameters(raw []byte) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, err
	}
	for _, descriptor := range doc.Root().FindElements("./SPSSODescriptor/KeyDescriptor") {
		if descriptor.SelectAttrValue("use", "") != "encryption" {
			continue
		}
		for _, method := range descriptor.SelectElements("EncryptionMethod") {
			if method.SelectAttrValue("Algorithm", "") != rsaOAEP {
				continue
			}
			digest := method.CreateElement("ds:DigestMethod")
			digest.CreateAttr("xmlns:ds", signatureNS)
			digest.CreateAttr("Algorithm", sha256Digest)
			mgf := method.CreateElement("xenc11:MGF")
			mgf.CreateAttr("xmlns:xenc11", encryption11NS)
			mgf.CreateAttr("Algorithm", mgfSHA256)
		}
	}
	return doc.WriteToBytes()
}
