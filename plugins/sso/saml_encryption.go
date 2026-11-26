package sso

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"io"
	"strings"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/xmlenc"
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
	aesGCM256       = string(DataEncryptionAES256GCM)
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

func encryptedAssertionID(raw []byte, acs, requestID string, key *rsa.PrivateKey) (string, error) {
	response, err := boundedSAMLTree(raw)
	if err != nil || !namedElement(response, samlProtocolNS, "Response") || uniqueAttribute(response, "Destination") != acs || uniqueAttribute(response, "InResponseTo") != requestID {
		return "", errSAMLResponse
	}
	if requestID == "" && response.SelectAttr("InResponseTo") != nil {
		return "", errSAMLResponse
	}
	a, enc, data, keys, other := assertionShape(response)
	if a != 0 || enc != 1 || data != 1 || keys != 1 || other != 0 {
		return "", errSAMLResponse
	}
	wrapper := uniqueChild(response, samlAssertionNS, "EncryptedAssertion")
	ciphertext := uniqueChild(wrapper, encryptionNS, "EncryptedData")
	if wrapper == nil || len(wrapper.ChildElements()) != 1 || ciphertext == nil {
		return "", errSAMLResponse
	}
	dataMethod := uniqueChild(ciphertext, encryptionNS, "EncryptionMethod")
	if uniqueAttribute(dataMethod, "Algorithm") != aesGCM256 || len(dataMethod.ChildElements()) != 0 || !inlineCipherValue(ciphertext) {
		return "", errSAMLResponse
	}
	info := uniqueChild(ciphertext, signatureNS, "KeyInfo")
	envelope := uniqueChild(info, encryptionNS, "EncryptedKey")
	if info == nil || len(info.ChildElements()) != 1 || envelope == nil || !inlineCipherValue(envelope) {
		return "", errSAMLResponse
	}
	wrapMethod := uniqueChild(envelope, encryptionNS, "EncryptionMethod")
	digest := uniqueChild(wrapMethod, signatureNS, "DigestMethod")
	mgf := uniqueChild(wrapMethod, encryption11NS, "MGF")
	if uniqueAttribute(wrapMethod, "Algorithm") != rsaOAEP || len(wrapMethod.ChildElements()) != 2 ||
		uniqueAttribute(digest, "Algorithm") != sha256Digest || len(digest.ChildElements()) != 0 ||
		uniqueAttribute(mgf, "Algorithm") != mgfSHA256 || len(mgf.ChildElements()) != 0 {
		return "", errSAMLResponse
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
	a, enc, data, keys, other = assertionShape(assertion)
	id := uniqueAttribute(assertion, "ID")
	if a != 1 || enc != 0 || data != 0 || keys != 0 || other != 0 || id == "" || len(id) > 512 {
		return "", errSAMLResponse
	}
	return id, nil
}

func assertionDocumentID(raw []byte, sp *saml.ServiceProvider, requestID string) (string, error) {
	if sp.EncryptionKey != nil {
		return encryptedAssertionID(raw, sp.AcsURL.String(), requestID, sp.EncryptionKey)
	}
	return assertionEnvelope(raw, sp.AcsURL.String(), requestID)
}

// The metadata model can name a key transport but cannot encode its digest or MGF.
// Publish both parameters because the XML Encryption defaults use SHA-1.
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
			return doc.WriteToBytes()
		}
	}
	return nil, ErrInvalidSAML
}
