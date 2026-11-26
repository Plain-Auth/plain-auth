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
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/crewjam/saml"
)

var ErrInvalidSAML = apiError(400, "Invalid or unsupported SAML configuration")

// errSAMLKeyMaterial refuses private keys in a provider registration or
// update.
var errSAMLKeyMaterial = apiError(400, "SAML private keys are not accepted in a provider registration; configure the request signing and decryption keys on the server")

// samlKeyFields reports whether a samlConfig body carries private key
// material. Keys stay out of the provider catalog: another runtime stores
// them in the row and returns them in the registration response; this host
// signs and decrypts with SAMLOptions.RequestSigner and Encryption.
func samlKeyFields(input map[string]any) bool {
	if _, ok := input["privateKey"]; ok {
		return true
	}
	for _, section := range []string{"spMetadata", "idpMetadata"} {
		fields, _ := input[section].(map[string]any)
		for _, key := range []string{"privateKey", "privateKeyPass", "encPrivateKey", "encPrivateKeyPass"} {
			if _, ok := fields[key]; ok {
				return true
			}
		}
	}
	return false
}

// SAMLOptions enables SP-initiated SAML. Request signing keys stay in the host.
type SAMLOptions struct {
	// EnableSingleLogout enables SP-initiated signed HTTP-Redirect logout.
	EnableSingleLogout bool
	// EnableIDPInitiatedLogout accepts signed Redirect requests from the current directory.
	EnableIDPInitiatedLogout bool
	// LogoutRequestTTL defaults to five minutes.
	LogoutRequestTTL time.Duration
	// RequestTTL is how long a SAML sign-in's state and AuthnRequest stay
	// valid, a positive whole number of seconds. Zero selects five minutes,
	// the default of another runtime's requestTTL.
	RequestTTL time.Duration
	// AllowIDPInitiated is a host-owned directory policy. Nil disables unsolicited sign-in.
	AllowIDPInitiated SAMLDirectoryPolicy
	// IDPInitiatedCallbackURL is the public landing page when a directory provides none.
	IDPInitiatedCallbackURL string
	Encryption              *SAMLEncryption
	// MaxMetadataSize limits inline IdP XML in bytes, defaulting to 100 KiB.
	MaxMetadataSize int
	// MaxResponseSize limits the base64 SAMLResponse form value in bytes,
	// defaulting to 256 KiB. The ACS reads at most 1 MiB of form data.
	MaxResponseSize int
	// ClockSkew is the tolerance for assertion NotBefore, NotOnOrAfter and
	// IssueInstant. Zero selects three minutes, the most the SAML library
	// allows process-wide, so a larger value is refused.
	ClockSkew time.Duration
	// RequireTimestamps refuses an assertion whose Conditions has neither
	// NotBefore nor NotOnOrAfter. Without it such an assertion is accepted
	// and a warning is logged through the auth Logger.
	RequireTimestamps bool
	// Algorithms narrows the signature, digest and encryption algorithms
	// responses and directory configurations may use.
	Algorithms         SAMLAlgorithms
	RequestSigner      crypto.Signer
	RequestCertificate *x509.Certificate
	TrustEmailVerified bool
}

// defaultSAMLClockSkew is three minutes, not five: the SAML library checks
// validity times with its process-wide MaxClockSkew of three minutes before
// this package sees an assertion.
const defaultSAMLClockSkew = 3 * time.Minute

func (o SAMLOptions) clockSkew() time.Duration {
	skew := o.ClockSkew
	if skew == 0 {
		skew = defaultSAMLClockSkew
	}
	return min(skew, saml.MaxClockSkew)
}

func (o SAMLOptions) requestTTL() time.Duration {
	if o.RequestTTL == 0 {
		return 5 * time.Minute
	}
	return o.RequestTTL
}

func (o SAMLOptions) validate() error {
	if o.LogoutRequestTTL < 0 || o.LogoutRequestTTL != 0 && (o.LogoutRequestTTL < time.Second || o.LogoutRequestTTL%time.Second != 0) {
		return errors.New("sso: SAML logout lifetime must be a positive whole number of seconds")
	}
	if o.RequestTTL < 0 || o.RequestTTL != 0 && (o.RequestTTL < time.Second || o.RequestTTL%time.Second != 0) {
		return errors.New("sso: SAML request lifetime must be a positive whole number of seconds")
	}
	if o.EnableIDPInitiatedLogout && !o.EnableSingleLogout {
		return errors.New("sso: IdP-initiated logout requires single logout")
	}
	if o.EnableSingleLogout && (o.RequestSigner == nil || o.RequestCertificate == nil) {
		return errors.New("sso: SAML single logout requires the host signing key and certificate")
	}
	if !validSAMLLanding(o.IDPInitiatedCallbackURL) {
		return errors.New("sso: invalid IdP-initiated SAML callback URL")
	}
	if o.Encryption != nil && !o.Encryption.valid() {
		return errors.New("sso: SAML decryption requires a matching RSA private key and certificate of at least 2048 bits")
	}
	if o.MaxMetadataSize < 0 || o.MaxMetadataSize > maxSAMLMetadataBytes {
		return errors.New("sso: SAML metadata size must be between 1 byte and 1 MiB when set")
	}
	if err := o.Algorithms.validate(); err != nil {
		return err
	}
	if o.ClockSkew < 0 || o.ClockSkew > defaultSAMLClockSkew {
		return errors.New("sso: SAML clock skew must be between zero and three minutes")
	}
	if o.MaxResponseSize < 0 || o.MaxResponseSize > maxSAMLMetadataBytes {
		return errors.New("sso: SAML response size must be between 1 byte and 1 MiB when set")
	}
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
	// ExtraFields maps user field names to SAML attribute names. Only
	// declared user fields that are not ServerOnly are written, when the
	// user is created.
	ExtraFields map[string]string `json:"extraFields,omitempty"`
}

// SAMLService is a published SAML protocol binding and its destination.
type SAMLService struct {
	Binding  string `json:"Binding"`
	Location string `json:"Location"`
}
type SAMLIDPMetadata struct {
	// SingleSignOnService lists a manual IdP's sign-in services. Its
	// HTTP-Redirect entry replaces EntryPoint as the AuthnRequest
	// destination; it is ignored when Metadata is set.
	SingleSignOnService  []SAMLService `json:"singleSignOnService,omitempty"`
	SingleLogoutService  []SAMLService `json:"singleLogoutService,omitempty"`
	IsAssertionEncrypted bool          `json:"isAssertionEncrypted,omitempty"`
	Metadata             string        `json:"metadata,omitempty"`
	EntityID             string        `json:"entityID,omitempty"`
	Certificates         Certificates  `json:"cert,omitempty"`
}
type SAMLSPMetadata struct {
	IsAssertionEncrypted bool   `json:"isAssertionEncrypted,omitempty"`
	EntityID             string `json:"entityID,omitempty"`
	// Binding is stored but unused, as in another runtime.
	Binding string `json:"binding,omitempty"`
}

// errSPMetadataXML refuses SP metadata XML. This host generates its SP
// metadata from the directory's settings and its own keys; another runtime
// serves registrant XML unchanged from the auth origin, which a browser can
// run script from. Each policy the XML carries has a setting here.
var errSPMetadataXML = &auth.APIError{Status: 400, Code: "SAML_INVALID_SP_METADATA", Message: "SP metadata XML is not accepted; set spMetadata.entityID, identifierFormat, wantAssertionsSigned and authnRequestsSigned instead"}

// metadataTooLarge answers an IdP metadata document over the size limit
// with another runtime's message.
func metadataTooLarge(limit int) error {
	return apiError(400, fmt.Sprintf("IdP metadata exceeds maximum allowed size (%d bytes)", limit))
}

type SAMLConfig struct {
	IDPInitiatedCallbackURL string `json:"idpInitiatedCallbackUrl,omitempty"`
	CallbackURL             string `json:"callbackUrl,omitempty"`
	imported                *samlIDPAuthority
	SPMetadata              *SAMLSPMetadata `json:"spMetadata,omitempty"`
	Issuer                  string          `json:"issuer,omitempty"`
	EntryPoint              string          `json:"entryPoint"`
	Certificates            Certificates    `json:"cert,omitempty"`
	IDPMetadata             SAMLIDPMetadata `json:"idpMetadata"`
	Audience                string          `json:"audience,omitempty"`
	WantAssertionsSigned    *bool           `json:"wantAssertionsSigned,omitempty"`
	AuthnRequestsSigned     bool            `json:"authnRequestsSigned,omitempty"`
	IdentifierFormat        string          `json:"identifierFormat,omitempty"`
	Mapping                 SAMLMapping     `json:"mapping,omitempty"`
	// SignatureAlgorithm and DigestAlgorithm record the directory's XML
	// signature algorithms as URIs or short forms such as rsa-sha256 and
	// sha256. Registration checks them against SAMLOptions.Algorithms;
	// requests are still signed with RSA-SHA256.
	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`
	DigestAlgorithm    string `json:"digestAlgorithm,omitempty"`
}

var (
	errAudienceMissing     = errors.New("SAML assertion is missing an AudienceRestriction")
	errAudienceRestriction = errors.New("SAML assertion audience does not match this Service Provider")
	errAudienceMismatch    = errors.New("Audience mismatch")
)

var errCertSourceMissing = &auth.APIError{Status: 400, Code: "CERT_SOURCE_MISSING", Message: "samlConfig requires either a signing certificate (cert or idpMetadata.cert) or an idpMetadata.metadata XML document."}

// requireCertSource refuses a registration without any signing certificate
// source, as another runtime does. Stored rows are not checked again.
func requireCertSource(c *SAMLConfig) error {
	if len(c.Certificates) == 0 && len(c.IDPMetadata.Certificates) == 0 && c.IDPMetadata.Metadata == "" {
		return errCertSourceMissing
	}
	return nil
}

func DecodeSAMLConfig(raw []byte) (*SAMLConfig, error) {
	var c SAMLConfig
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(&struct{}{}) != io.EOF {
		return nil, ErrInvalidSAML
	}
	if !validSAMLLanding(c.IDPInitiatedCallbackURL) || strings.Contains(c.CallbackURL, "#") || c.EntryPoint == "" || (c.IDPMetadata.EntityID == "" && c.IDPMetadata.Metadata == "") {
		return nil, ErrInvalidSAML
	}
	if _, err := logoutLocation(c.IDPMetadata.SingleLogoutService); err != nil {
		return nil, err
	}
	// This host sends AuthnRequests only by Redirect, so a listed sign-in
	// service needs a Redirect entry, where another runtime fails at sign-in.
	if c.IDPMetadata.Metadata == "" {
		redirect, _, err := ssoLocations(c.IDPMetadata.SingleSignOnService)
		if err != nil || c.IDPMetadata.SingleSignOnService != nil && redirect == "" {
			return nil, ErrInvalidSAML
		}
	}
	if c.IDPMetadata.Metadata != "" {
		var err error
		c.imported, err = parseInlineMetadata(c.IDPMetadata.Metadata)
		if err != nil {
			return nil, err
		}
	}
	return &c, nil
}

// assertionSignatureRequired reports whether the assertion needs its own
// signature. An omitted wantAssertionsSigned requires it, where another
// runtime defaults to false: directories stored before false was accepted
// keep their policy.
func (c SAMLConfig) assertionSignatureRequired() bool {
	return c.WantAssertionsSigned == nil || *c.WantAssertionsSigned
}

func samlACS(c auth.EndpointContext, id string) (string, error) {
	return c.CallbackURL(strings.TrimRight(c.Auth.BasePath(), "/") + "/sso/saml2/sp/acs/" + id)
}
func (o Options) samlSP(c auth.EndpointContext, p Provider) (*saml.ServiceProvider, error) {
	cfg := p.SAML
	if o.SAML == nil || cfg == nil || cfg.Issuer != p.Issuer || !MutableProviderID(p.ProviderID) || c.Auth.HasOAuthProvider(p.ProviderID) {
		return nil, ErrInvalidSAML
	}
	spEntity := cfg.spEntityID()
	entity, err := url.Parse(spEntity)
	if err != nil || !entity.IsAbs() || entity.Fragment != "" || entity.User != nil {
		return nil, ErrInvalidSAML
	}
	if _, err := endpointURL(cfg.EntryPoint); err != nil {
		return nil, ErrInvalidSAML
	}
	authority := cfg.authority()
	if len(cfg.IDPMetadata.Metadata) > o.SAML.metadataLimit() || !cfg.MetadataValidAt(time.Now()) {
		return nil, ErrInvalidSAML
	}
	// SAML endpoints use only static trusted origins: another runtime never
	// checks them against trusted origins, and a directory must validate the
	// same way on every route.
	if err = secureBrowserEndpoint(c.Auth.ExplicitlyTrustedOrigin, authority.redirect); err != nil {
		return nil, ErrInvalidSAML
	}
	endpoint, _ := url.Parse(authority.redirect)
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
	meta, err := c.CallbackURL(strings.TrimRight(c.Auth.BasePath(), "/") + "/sso/saml2/sp/metadata?providerId=" + url.QueryEscape(p.ProviderID))
	if err != nil {
		return nil, err
	}
	metadataURL, _ := url.Parse(meta)
	certs := authority.certs
	if len(certs) == 0 || len(certs) > 8 {
		return nil, ErrInvalidSAML
	}
	idp := saml.IDPSSODescriptor{SingleSignOnServices: []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: authority.redirect}}}
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
		// ECDSA directories are refused: the XML signature library checks
		// ECDSA values in ASN.1 form, not the r||s form XML Signature uses.
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
		IDPMetadata:                      &saml.EntityDescriptor{EntityID: authority.entity, IDPSSODescriptors: []saml.IDPSSODescriptor{idp}},
		RejectUnknownConditions:          true,
		RejectSHA1Signatures:             true,
	}
	if cfg.IDPMetadata.IsAssertionEncrypted || (cfg.SPMetadata != nil && cfg.SPMetadata.IsAssertionEncrypted) {
		if o.SAML.Encryption == nil {
			return nil, apiError(400, "SAML assertion decryption is not configured")
		}
		sp.EncryptionKey = o.SAML.Encryption.PrivateKey
		sp.EncryptionCertificate = o.SAML.Encryption.Certificate
		sp.RequireSignedResponseForCBC = true
	}
	if cfg.AuthnRequestsSigned || authority.signedRequests {
		if o.SAML.RequestSigner == nil {
			return nil, apiError(400, "SAML request signing is not configured")
		}
		sp.Key = o.SAML.RequestSigner
		sp.Certificate = o.SAML.RequestCertificate
		sp.SignatureMethod = string(SignatureRSASHA256)
	}
	// Each restriction must name this SP or the configured audience, and a
	// configured audience must appear in one of them. The descriptions are
	// the ones another runtime sends from its two checks.
	// Audience values are trimmed and empty ones dropped first, so an
	// AudienceRestriction without values counts as missing, as in another
	// runtime.
	sp.ValidateAudienceRestriction = func(a *saml.Assertion) error {
		var groups [][]string
		values := 0
		if a.Conditions != nil {
			for _, group := range a.Conditions.AudienceRestrictions {
				var audiences []string
				for _, v := range group.AllAudiences() {
					if value := strings.TrimSpace(v.Value); value != "" {
						audiences = append(audiences, value)
					}
				}
				groups = append(groups, audiences)
				values += len(audiences)
			}
		}
		if values == 0 {
			return errAudienceMissing
		}
		found := cfg.Audience == ""
		for _, audiences := range groups {
			matched := false
			for _, v := range audiences {
				configured := cfg.Audience != "" && v == cfg.Audience
				matched = matched || v == spEntity || configured
				found = found || configured
			}
			if !matched {
				return errAudienceRestriction
			}
		}
		if !found {
			return errAudienceMismatch
		}
		return nil
	}
	return sp, nil
}
func (o Options) samlMetadata(c auth.EndpointContext) (any, error) {
	q := c.Request.URL.Query()
	id := q.Get("providerId")
	store, ok := c.Store().(BrowserStore)
	notFound := apiError(404, "No provider found for the given providerId")
	if !ok || len(q["providerId"]) != 1 {
		return nil, ErrMissing
	}
	if !MutableProviderID(id) {
		return nil, notFound
	}
	p, err := store.FindBrowserProvider(c.Request.Context(), Selector{ProviderID: id, Protocol: "saml"})
	if errors.Is(err, ErrMissing) {
		// A provider of the other protocol answers as another runtime does.
		if _, other := store.FindBrowserProvider(c.Request.Context(), Selector{ProviderID: id}); other == nil {
			return nil, apiError(400, "Invalid SAML configuration")
		}
		return nil, notFound
	}
	if err != nil {
		return nil, err
	}
	sp, err := o.samlSP(c, p.Provider)
	if err != nil {
		return nil, err
	}
	signAuthentication := sp.SignatureMethod != ""
	logout := o.SAML.EnableSingleLogout && availableSAMLLogout(c, p.Provider) == nil
	if logout {
		if err := o.enableLogoutSP(c, p.Provider, sp); err != nil {
			return nil, err
		}
	}
	meta := sp.Metadata()
	wantAssertionsSigned := p.SAML.assertionSignatureRequired()
	for i := range meta.SPSSODescriptors {
		desc := &meta.SPSSODescriptors[i]
		desc.WantAssertionsSigned = &wantAssertionsSigned
		if logout {
			desc.AuthnRequestsSigned = &signAuthentication
		} else {
			desc.SingleLogoutServices = nil
		}
		descriptors := desc.KeyDescriptors
		desc.KeyDescriptors = nil
		for _, k := range descriptors {
			if k.Use == "encryption" && sp.EncryptionKey != nil {
				k.EncryptionMethods = o.SAML.Algorithms.encryptionMethods()
				desc.KeyDescriptors = append(desc.KeyDescriptors, k)
			}
			if k.Use == "signing" {
				desc.KeyDescriptors = append(desc.KeyDescriptors, k)
			}
		}
	}
	raw, err := xml.Marshal(meta)
	if err == nil && sp.EncryptionKey != nil {
		raw, err = advertiseOAEPParameters(raw)
	}
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
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return nil, ErrInvalidSAML
	}
	ref := p.Reference
	if proof {
		ref += ".dns"
	}
	flow, err := c.BeginEnterprisePostFlow(p.ProviderID, ref, sp.AcsURL.String(), signup, o.SAML.requestTTL())
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
