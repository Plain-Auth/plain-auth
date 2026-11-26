package sso

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

const maxSAMLMetadataBytes = 1 << 20
const defaultSAMLMetadataBytes = 100 * 1024
const defaultSAMLResponseBytes = 256 * 1024

// responseLimit is the largest SAMLResponse form value the ACS accepts.
func (o SAMLOptions) responseLimit() int {
	if o.MaxResponseSize != 0 {
		return o.MaxResponseSize
	}
	return defaultSAMLResponseBytes
}

func (o SAMLOptions) metadataLimit() int {
	if o.MaxMetadataSize != 0 {
		return o.MaxMetadataSize
	}
	return defaultSAMLMetadataBytes
}

type samlIDPAuthority struct {
	entity, redirect, post, logout, logoutResponse string
	certs                                          Certificates
	validUntil                                     time.Time
	signedRequests                                 bool
}

// IdentityProviderEntityID returns the assertion issuer from a decoded directory configuration.
func (c SAMLConfig) IdentityProviderEntityID() string {
	if c.imported != nil {
		return c.imported.entity
	}
	return c.IDPMetadata.EntityID
}

func (c SAMLConfig) authority() samlIDPAuthority {
	if c.imported != nil {
		return *c.imported
	}
	cs := c.IDPMetadata.Certificates
	if len(cs) == 0 {
		cs = c.Certificates
	}
	logout, _ := logoutLocation(c.IDPMetadata.SingleLogoutService)
	return samlIDPAuthority{entity: c.IDPMetadata.EntityID, redirect: c.EntryPoint, certs: cs, logout: logout}
}

// SameSAMLIdentity reports whether changing only IdP metadata preserves the
// authority that created previously linked accounts. Keys can rotate independently.
func SameSAMLIdentity(current, next SAMLConfig) bool {
	a, b := current.authority(), next.authority()
	return a.entity == b.entity && a.redirect == b.redirect && a.post == b.post
}

func boundedMetadata(data []byte) bool {
	const metadataNS = "urn:oasis:names:tc:SAML:2.0:metadata"
	const signatureNS = "http://www.w3.org/2000/09/xmldsig#"
	if len(data) == 0 || len(data) > maxSAMLMetadataBytes {
		return false
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	depth, roots, elements := 0, 0, 0
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return roots == 1 && depth == 0
		}
		if err != nil {
			return false
		}
		switch t := tok.(type) {
		case xml.Directive:
			return false
		case xml.StartElement:
			if depth == 0 {
				roots++
				if roots != 1 || t.Name != (xml.Name{Space: metadataNS, Local: "EntityDescriptor"}) {
					return false
				}
			} else if t.Name.Local == "EntityDescriptor" || t.Name.Local == "EntitiesDescriptor" {
				return false
			}
			depth++
			elements++
			if depth > 64 || elements > 3000 {
				return false
			}
			switch t.Name.Local {
			case "IDPSSODescriptor", "KeyDescriptor", "SingleSignOnService":
				if t.Name.Space != metadataNS {
					return false
				}
			case "KeyInfo", "X509Data", "X509Certificate":
				if t.Name.Space != signatureNS {
					return false
				}
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(t)) != 0 {
				return false
			}
		}
	}
}

func parseInlineMetadata(raw string) (*samlIDPAuthority, error) {
	data := []byte(raw)
	if !boundedMetadata(data) {
		return nil, ErrInvalidSAML
	}
	// ParseMetadata reads these bytes only. The authenticated directory manager
	// supplies the trust anchors; a self-asserted metadata signature grants no trust.
	entity, err := samlsp.ParseMetadata(data)
	if err != nil || entity.EntityID == "" || len(entity.IDPSSODescriptors) != 1 {
		return nil, ErrInvalidSAML
	}
	role := entity.IDPSSODescriptors[0]
	if !slices.Contains(strings.Fields(role.ProtocolSupportEnumeration), "urn:oasis:names:tc:SAML:2.0:protocol") {
		return nil, ErrInvalidSAML
	}
	idp := &samlIDPAuthority{entity: entity.EntityID, validUntil: entity.ValidUntil, signedRequests: role.WantAuthnRequestsSigned != nil && *role.WantAuthnRequestsSigned}
	if role.ValidUntil != nil && (idp.validUntil.IsZero() || role.ValidUntil.Before(idp.validUntil)) {
		idp.validUntil = *role.ValidUntil
	}
	for _, service := range role.SingleSignOnServices {
		var target *string
		switch service.Binding {
		case saml.HTTPRedirectBinding:
			target = &idp.redirect
		case saml.HTTPPostBinding:
			target = &idp.post
		default:
			continue
		}
		u, e := endpointURL(service.Location)
		if e != nil || u.Scheme != "https" || u.RawQuery != "" || u.ForceQuery {
			return nil, ErrInvalidSAML
		}
		if *target != "" || service.Location == "" {
			return nil, ErrInvalidSAML
		}
		*target = service.Location
	}
	var logoutServices []SAMLService
	for _, endpoint := range role.SingleLogoutServices {
		logoutServices = append(logoutServices, SAMLService{Binding: endpoint.Binding, Location: endpoint.Location})
		if endpoint.Binding == saml.HTTPRedirectBinding {
			idp.logoutResponse = endpoint.ResponseLocation
		}
	}
	// An unsupported or ambiguous optional logout service leaves the existing
	// authentication metadata usable. Only an unambiguous Redirect endpoint can
	// receive a signed NameID.
	idp.logout, _ = logoutLocation(logoutServices)
	if idp.logout != "" && !validInlineLogoutNamespace(data) {
		idp.logout = ""
	}
	if idp.redirect == "" {
		return nil, ErrInvalidSAML
	}
	for _, desc := range role.KeyDescriptors {
		if desc.Use != "" && desc.Use != "signing" {
			continue
		}
		certs := desc.KeyInfo.X509Data.X509Certificates
		if len(certs) != 1 {
			return nil, ErrInvalidSAML
		}
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(certs[0].Data), ""))
		if err != nil {
			return nil, ErrInvalidSAML
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, ErrInvalidSAML
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok || pub.N.BitLen() < 2048 {
			return nil, ErrInvalidSAML
		}
		key := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		if !slices.Contains(idp.certs, key) {
			idp.certs = append(idp.certs, key)
		}
		if len(idp.certs) > 8 {
			return nil, ErrInvalidSAML
		}
	}
	if len(idp.certs) == 0 {
		return nil, ErrInvalidSAML
	}
	return idp, nil
}

// MetadataValidAt checks the earliest XML entity or role expiration. Manual
// directories have no XML validity interval.
func (c SAMLConfig) MetadataValidAt(now time.Time) bool {
	return c.imported == nil || c.imported.validUntil.IsZero() || c.imported.validUntil.After(now)
}

// SAMLTrustChanged compares the signing anchors and the IdP request-signing policy.
func SAMLTrustChanged(current, next SAMLConfig) bool {
	keys := func(cs Certificates) []string {
		var result []string
		for _, v := range cs {
			p, _ := pem.Decode([]byte(strings.TrimSpace(v)))
			if p == nil {
				return nil
			}
			key := string(p.Bytes)
			if !slices.Contains(result, key) {
				result = append(result, key)
			}
		}
		slices.Sort(result)
		return result
	}
	a, b := current.authority(), next.authority()
	return a.signedRequests != b.signedRequests || !slices.Equal(keys(a.certs), keys(b.certs))
}

func validInlineLogoutNamespace(data []byte) bool {
	d := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return true
		}
		if err != nil {
			return false
		}
		if start, ok := tok.(xml.StartElement); ok && start.Name.Local == "SingleLogoutService" && start.Name.Space != "urn:oasis:names:tc:SAML:2.0:metadata" {
			return false
		}
	}
}
