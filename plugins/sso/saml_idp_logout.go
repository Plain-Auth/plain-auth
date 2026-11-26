package sso

import (
	"context"
	"net/url"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/crewjam/saml"
)

var ErrSAMLLogoutRequest = &auth.APIError{Status: 400, Code: "INVALID_LOGOUT_REQUEST", Message: "Invalid LogoutRequest"}

// SAMLIDPLogout is a signed, validated request from one immutable directory.
type SAMLIDPLogout struct {
	ID, ProviderID, Reference, Issuer string
	Identity                          SAMLLogoutIdentity
	IssuedAt                          time.Time
	NotOnOrAfter                      *time.Time
}

// ValidAt bounds the receipt window independently of the transport validator.
func (r SAMLIDPLogout) ValidAt(now time.Time) bool {
	return r.ID != "" && len(r.ID) <= 512 && MutableProviderID(r.ProviderID) && r.Reference != "" && r.Issuer != "" &&
		r.Identity.Valid(strings.TrimSpace(r.Identity.NameID.Value)) &&
		!r.IssuedAt.After(now.Add(3*time.Minute)) && !r.IssuedAt.Before(now.Add(-90*time.Second)) &&
		(r.NotOnOrAfter == nil || now.Before(*r.NotOnOrAfter))
}

// SAMLIDPLogoutStore atomically consumes a verified IdP request and revokes
// every recorded session matching its authority, exact NameID and SessionIndex.
// The result reports only whether the presented browser token was revoked.
type SAMLIDPLogoutStore interface {
	SAMLLogoutStore
	RevokeSAMLIDPSessions(ctx context.Context, request SAMLIDPLogout, browserToken string, requireDomainProof bool, now time.Time) (bool, error)
}

func logoutSignatureAllowed(algorithm string) bool {
	const prefix = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha"
	return algorithm == prefix+"256" || algorithm == prefix+"384" || algorithm == prefix+"512"
}

func (o Options) receiveIDPLogout(c auth.EndpointContext, q url.Values, store SAMLLogoutStore) (any, error) {
	for key, values := range q {
		switch key {
		case "SAMLRequest", "SigAlg", "Signature", "RelayState":
		default:
			return nil, ErrSAMLLogoutRequest
		}
		if len(values) != 1 || values[0] == "" {
			return nil, ErrSAMLLogoutRequest
		}
	}
	relay := q.Get("RelayState")
	if !logoutSignatureAllowed(q.Get("SigAlg")) || q.Get("Signature") == "" || len(relay) > 80 {
		return nil, ErrSAMLLogoutRequest
	}
	p, sp, err := o.logoutProvider(c, store, "/sso/saml2/sp/slo/")
	if err != nil {
		return nil, err
	}
	// Logout accepts a plaintext NameID. Login decryption keys are unnecessary here.
	validator := *sp
	validator.Key, validator.EncryptionKey = nil, nil
	r, err := validator.ValidateLogoutRequest(c.Request)
	if err != nil || r.NameID == nil || r.EncryptedID != nil || r.BaseID != nil || r.Issuer == nil || r.SessionIndex == nil || len(r.AdditionalSessionIndexes) != 0 {
		return nil, ErrSAMLLogoutRequest
	}
	now := time.Now().UTC()
	proof := SAMLIDPLogout{ID: r.ID, ProviderID: p.ProviderID, Reference: p.Reference, Issuer: r.Issuer.Value, Identity: SAMLLogoutIdentity{NameID: *r.NameID, SessionIndex: r.SessionIndex.Value}, IssuedAt: r.IssueInstant, NotOnOrAfter: r.NotOnOrAfter}
	if !proof.ValidAt(now) {
		return nil, ErrSAMLLogoutRequest
	}
	required, err := o.domainGate(c, p)
	if err != nil {
		return nil, err
	}
	if distinct := p.SAML.authority().logoutResponse; distinct != "" {
		target, e := logoutLocation([]SAMLService{{Binding: saml.HTTPRedirectBinding, Location: distinct}})
		responseEndpoint, _ := url.Parse(target)
		reqEndpoint, _ := url.Parse(p.SAML.authority().logout)
		if e != nil || !equalWebOrigin(responseEndpoint, reqEndpoint) || secureBrowserEndpoint(c.Auth, target) != nil {
			return nil, ErrSAMLLogoutRequest
		}
		// This request owns its in-memory IdP descriptor. Sign the exact response
		// destination from metadata when the IdP separates its two SLO endpoints.
		sp.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices[0].Location = target
	}
	target, err := sp.MakeRedirectLogoutResponse(r.ID, relay)
	if err != nil {
		return nil, ErrSAMLLogoutRequest
	}
	token := c.SAMLLogoutBrowserToken()
	// The store asks the request's gate before it removes each binding, so
	// their verification hooks run outside its transaction.
	var revoked bool
	err = c.GateVerifications(func(ctx context.Context) (err error) {
		revoked, err = store.(SAMLIDPLogoutStore).RevokeSAMLIDPSessions(ctx, proof, token, required, time.Now().UTC())
		return err
	})
	if err != nil {
		return nil, err
	}
	return c.SAMLIDPLogoutCompleted(target.String(), token, revoked), nil
}
