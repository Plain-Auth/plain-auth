package sso

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"strings"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/crewjam/saml"
)

var ErrInvalidSAML = apiError(400, "Invalid or unsupported SAML configuration")

// SAMLOptions enables SP-initiated SAML. Request signing keys stay in the host.
type SAMLOptions struct {
	RequestSigner      crypto.Signer
	RequestCertificate *x509.Certificate
	TrustEmailVerified bool
}

func (o SAMLOptions) validate() error {
	if o.RequestSigner == nil && o.RequestCertificate == nil {
		return nil
	}
	if o.RequestSigner == nil || o.RequestCertificate == nil {
		return errors.New("sso: SAML request signing needs a matching RSA key and certificate")
	}
	key, ok := o.RequestSigner.Public().(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 2048 || !key.Equal(o.RequestCertificate.PublicKey) {
		return errors.New("sso: invalid SAML request signing key or certificate")
	}
	return nil
}

// Certificates accepts either a PEM string or a list for certificate rotation.
type Certificates []string

func (cs Certificates) MarshalJSON() ([]byte, error) {
	if len(cs) == 1 {
		return json.Marshal(cs[0])
	}
	return json.Marshal([]string(cs))
}

func (cs *Certificates) UnmarshalJSON(raw []byte) error {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		*cs = []string{one}
		return nil
	}
	return json.Unmarshal(raw, (*[]string)(cs))
}

type SAMLMapping struct {
	Email         string `json:"email,omitempty"`
	FirstName     string `json:"firstName,omitempty"`
	LastName      string `json:"lastName,omitempty"`
	Name          string `json:"name,omitempty"`
	EmailVerified string `json:"emailVerified,omitempty"`
}
type SAMLIDPMetadata struct {
	EntityID     string       `json:"entityID"`
	Certificates Certificates `json:"cert,omitempty"`
}
type SAMLSPMetadata struct {
	EntityID string `json:"entityID"`
}

type SAMLConfig struct {
	SPMetadata           *SAMLSPMetadata `json:"spMetadata,omitempty"`
	Issuer               string          `json:"issuer,omitempty"`
	EntryPoint           string          `json:"entryPoint"`
	Certificates         Certificates    `json:"cert,omitempty"`
	IDPMetadata          SAMLIDPMetadata `json:"idpMetadata"`
	Audience             string          `json:"audience,omitempty"`
	WantAssertionsSigned *bool           `json:"wantAssertionsSigned,omitempty"`
	AuthnRequestsSigned  bool            `json:"authnRequestsSigned,omitempty"`
	IdentifierFormat     string          `json:"identifierFormat,omitempty"`
	Mapping              SAMLMapping     `json:"mapping,omitempty"`
}

func DecodeSAMLConfig(raw []byte) (*SAMLConfig, error) {
	var c SAMLConfig
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(&struct{}{}) != io.EOF {
		return nil, ErrInvalidSAML
	}
	if c.EntryPoint == "" || c.IDPMetadata.EntityID == "" || c.WantAssertionsSigned != nil && !*c.WantAssertionsSigned {
		return nil, ErrInvalidSAML
	}
	return &c, nil
}
func samlACS(c auth.EndpointContext, id string) (string, error) {
	return c.Auth.CallbackURL(strings.TrimRight(c.Auth.BasePath(), "/") + "/sso/saml2/sp/acs/" + id)
}
func (o Options) samlSP(c auth.EndpointContext, p Provider) (*saml.ServiceProvider, error) {
	cfg := p.SAML
	if o.SAML == nil || cfg == nil || cfg.Issuer != p.Issuer || !MutableProviderID(p.ProviderID) || c.Auth.HasOAuthProvider(p.ProviderID) {
		return nil, ErrInvalidSAML
	}
	spEntity := cfg.Issuer
	if cfg.SPMetadata != nil {
		spEntity = cfg.SPMetadata.EntityID
	}
	entity, err := url.Parse(spEntity)
	if err != nil || !entity.IsAbs() || entity.Fragment != "" || entity.User != nil {
		return nil, ErrInvalidSAML
	}
	if err = secureBrowserEndpoint(c.Auth, cfg.EntryPoint); err != nil {
		return nil, ErrInvalidSAML
	}
	endpoint, _ := url.Parse(cfg.EntryPoint)
	if endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, ErrInvalidSAML
	}
	acs, err := samlACS(c, p.ProviderID)
	if err != nil {
		return nil, err
	}
	acsURL, err := url.Parse(acs)
	if err != nil || acsURL.Scheme != "https" {
		return nil, apiError(400, "SAML requires an HTTPS public callback URL")
	}
	meta, err := c.Auth.CallbackURL(strings.TrimRight(c.Auth.BasePath(), "/") + "/sso/saml2/sp/metadata?providerId=" + url.QueryEscape(p.ProviderID))
	if err != nil {
		return nil, err
	}
	metadataURL, _ := url.Parse(meta)
	certs := cfg.Certificates
	if len(cfg.IDPMetadata.Certificates) > 0 {
		certs = cfg.IDPMetadata.Certificates
	}
	if len(certs) == 0 || len(certs) > 8 {
		return nil, ErrInvalidSAML
	}
	idp := saml.IDPSSODescriptor{SingleSignOnServices: []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: cfg.EntryPoint}}}
	idp.ProtocolSupportEnumeration = "urn:oasis:names:tc:SAML:2.0:protocol"
	for _, raw := range certs {
		block, rest := pem.Decode([]byte(strings.TrimSpace(raw)))
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) > 0 {
			return nil, ErrInvalidSAML
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return nil, ErrInvalidSAML
		}
		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok || key.N.BitLen() < 2048 {
			return nil, ErrInvalidSAML
		}
		x509Data := saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(cert.Raw)}}}
		idp.KeyDescriptors = append(idp.KeyDescriptors, saml.KeyDescriptor{Use: "signing", KeyInfo: saml.KeyInfo{X509Data: x509Data}})
	}
	sp := &saml.ServiceProvider{
		EntityID:                         spEntity,
		MetadataURL:                      *metadataURL,
		AcsURL:                           *acsURL,
		AuthnNameIDFormat:                saml.NameIDFormat(cfg.IdentifierFormat),
		AssertionConsumerServiceBindings: []string{saml.HTTPPostBinding},
		IDPMetadata:                      &saml.EntityDescriptor{EntityID: cfg.IDPMetadata.EntityID, IDPSSODescriptors: []saml.IDPSSODescriptor{idp}},
		RejectUnknownConditions:          true,
		RejectSHA1Signatures:             true,
	}
	if cfg.AuthnRequestsSigned {
		if o.SAML.RequestSigner == nil {
			return nil, apiError(400, "SAML request signing is not configured")
		}
		sp.Key = o.SAML.RequestSigner
		sp.Certificate = o.SAML.RequestCertificate
		sp.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	}
	audience := cfg.Audience
	if audience == "" {
		audience = spEntity
	}
	sp.ValidateAudienceRestriction = func(a *saml.Assertion) error {
		if a.Conditions == nil || len(a.Conditions.AudienceRestrictions) == 0 {
			return errors.New("SAML audience is required")
		}
		for _, group := range a.Conditions.AudienceRestrictions {
			matched := false
			for _, v := range group.AllAudiences() {
				if v.Value == audience {
					matched = true
					break
				}
			}
			if !matched {
				return errors.New("SAML audience mismatch")
			}
		}
		return nil
	}
	return sp, nil
}
func (o Options) samlMetadata(c auth.EndpointContext) (any, error) {
	q := c.Request.URL.Query()
	id := q.Get("providerId")
	store, ok := c.Store().(BrowserStore)
	if !ok || len(q["providerId"]) != 1 || !MutableProviderID(id) {
		return nil, ErrMissing
	}
	p, err := store.FindBrowserProvider(c.Request.Context(), Selector{ProviderID: id, Protocol: "saml"})
	if err != nil {
		return nil, err
	}
	sp, err := o.samlSP(c, p.Provider)
	if err != nil {
		return nil, err
	}
	meta := sp.Metadata()
	for i := range meta.SPSSODescriptors {
		desc := &meta.SPSSODescriptors[i]
		desc.SingleLogoutServices = nil
		descriptors := desc.KeyDescriptors
		desc.KeyDescriptors = nil
		for _, k := range descriptors {
			if k.Use == "signing" {
				desc.KeyDescriptors = append(desc.KeyDescriptors, k)
			}
		}
	}
	raw, err := xml.Marshal(meta)
	return auth.XMLDocument(raw), err
}
func (o Options) samlStart(c auth.EndpointContext, p BrowserProvider, proof, signup bool) (any, error) {
	if _, ok := c.Body["additionalParams"]; ok {
		return nil, apiError(400, "additionalParams is not supported for SAML providers")
	}
	sp, err := o.samlSP(c, p.Provider)
	if err != nil {
		return nil, err
	}
	req, err := sp.MakeAuthenticationRequest(p.SAML.EntryPoint, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return nil, ErrInvalidSAML
	}
	ref := p.Reference
	if proof {
		ref += ".dns"
	}
	flow, err := c.BeginEnterprisePostFlow(p.ProviderID, ref, sp.AcsURL.String(), signup)
	if err != nil {
		return nil, err
	}
	req.ID = "_" + flow.Nonce
	target, err := req.Redirect(flow.State, sp)
	if err != nil {
		return nil, ErrInvalidSAML
	}
	return map[string]any{"url": target.String(), "redirect": true}, nil
}
