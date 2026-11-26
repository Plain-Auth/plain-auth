package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/crewjam/saml"
)

// SAMLLogoutIdentity records the exact NameID and IdP session from a verified assertion.
type SAMLLogoutIdentity struct {
	NameID       saml.NameID
	SessionIndex string
}

func (i SAMLLogoutIdentity) Valid(subject string) bool {
	if subject == "" || strings.TrimSpace(i.NameID.Value) != subject || i.SessionIndex == "" {
		return false
	}
	for _, value := range []string{i.NameID.Value, i.NameID.NameQualifier, i.NameID.SPNameQualifier, i.NameID.SPProvidedID, i.NameID.Format, i.SessionIndex} {
		if len(value) > 1024 {
			return false
		}
	}
	return true
}
func logoutIdentity(a *saml.Assertion) *SAMLLogoutIdentity {
	if a.Subject == nil || a.Subject.NameID == nil || len(a.AuthnStatements) != 1 {
		return nil
	}
	v := SAMLLogoutIdentity{NameID: *a.Subject.NameID, SessionIndex: a.AuthnStatements[0].SessionIndex}
	if !v.Valid(strings.TrimSpace(v.NameID.Value)) {
		return nil
	}
	return &v
}

type SAMLLogoutRequest struct {
	ID, State, BrowserHash, ProviderID, Reference, CallbackURL string
	ExpiresAt                                                  time.Time
}

// SAMLLogoutStore keeps the IdP session, local revocation and single-use return
// in the same shared store as the original SAML session.
type SAMLLogoutStore interface {
	SAMLStore
	SAMLSessionForLogout(context.Context, Actor, string, string, time.Time) (SAMLLogoutIdentity, error)
	StartSAMLLogout(context.Context, Actor, SAMLLogoutIdentity, SAMLLogoutRequest, bool, time.Time) error
	ConsumeSAMLLogout(ctx context.Context, proof SAMLLogoutRequest, now time.Time) (string, error)
}

var (
	ErrSAMLLogoutSession  = apiError(400, "This browser session has no available SAML logout record")
	ErrSAMLLogoutResponse = &auth.APIError{Status: 400, Code: "INVALID_LOGOUT_RESPONSE", Message: "Invalid LogoutResponse"}
)

func logoutLocation(services []SAMLService) (string, error) {
	var target string
	for _, v := range services {
		if v.Binding != saml.HTTPRedirectBinding {
			continue
		}
		u, err := endpointURL(v.Location)
		if target != "" || err != nil || u.Scheme != "https" || u.RawQuery != "" || u.ForceQuery {
			return "", ErrInvalidSAML
		}
		target = v.Location
	}
	return target, nil
}

// errLogoutProvider answers a logout route for an unknown SAML provider with
// another runtime's code.
var errLogoutProvider = &auth.APIError{Status: 404, Code: "SAML_PROVIDER_NOT_FOUND", Message: "SAML provider not found"}

var errLogoutDisabled = &auth.APIError{Status: 400, Code: "SINGLE_LOGOUT_NOT_ENABLED", Message: "Single Logout is not enabled"}

func availableSAMLLogout(c auth.EndpointContext, p Provider) error {
	location := p.SAML.authority().logout
	if location == "" {
		return &auth.APIError{Status: 400, Code: "IDP_SLO_NOT_SUPPORTED", Message: "IdP does not support Single Logout Service"}
	}
	loginEndpoint, _ := url.Parse(p.SAML.authority().redirect)
	logoutEndpoint, e := url.Parse(location)
	if e != nil || !equalWebOrigin(logoutEndpoint, loginEndpoint) {
		return apiError(400, "SAML logout must use the configured IdP sign-in origin")
	}
	if err := secureBrowserEndpoint(c.Auth.ExplicitlyTrustedOrigin, location); err != nil {
		return ErrInvalidSAML
	}
	return nil
}

func (o Options) enableLogoutSP(c auth.EndpointContext, p Provider, sp *saml.ServiceProvider) error {
	location := p.SAML.authority().logout
	if err := availableSAMLLogout(c, p); err != nil {
		return err
	}
	target, err := c.CallbackURL(strings.TrimRight(c.Auth.BasePath(), "/") + "/sso/saml2/sp/slo/" + p.ProviderID)
	if err != nil {
		return err
	}
	endpoint, err := url.Parse(target)
	if err != nil || endpoint.Scheme != "https" {
		return ErrInvalidSAML
	}
	sp.SloURL = *endpoint
	sp.LogoutBindings = []string{saml.HTTPRedirectBinding}
	sp.Key = o.SAML.RequestSigner
	sp.Certificate = o.SAML.RequestCertificate
	sp.SignatureMethod = string(SignatureRSASHA256)
	sp.LimitRelayStateLength = true
	sp.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices = []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: location}}
	return nil
}

func (o Options) logoutProvider(c auth.EndpointContext, store SAMLLogoutStore, prefix string) (BrowserProvider, *saml.ServiceProvider, error) {
	id, ok := strings.CutPrefix(c.Request.URL.EscapedPath(), strings.TrimRight(c.Auth.BasePath(), "/")+prefix)
	if !ok || !MutableProviderID(id) {
		return BrowserProvider{}, nil, errLogoutProvider
	}
	p, err := store.FindBrowserProvider(c.Request.Context(), Selector{ProviderID: id, Protocol: "saml"})
	if errors.Is(err, ErrMissing) {
		return p, nil, errLogoutProvider
	}
	if err != nil {
		return p, nil, err
	}
	if p.ProviderID != id || p.SAML == nil {
		return p, nil, errLogoutProvider
	}
	sp, err := o.samlSP(c, p.Provider)
	if err != nil {
		return p, nil, err
	}
	if err = o.enableLogoutSP(c, p.Provider, sp); err != nil {
		return p, nil, err
	}
	if !sameSAMLOrigin(samlRequestOrigin(c), sp.SloURL.String()) {
		return p, nil, ErrSAMLLogoutResponse
	}
	return p, sp, nil
}

func logoutBrowserHash(value string) string {
	sum := sha256.Sum256([]byte("saml-logout-browser\x00" + value))
	return hex.EncodeToString(sum[:])
}
func (o Options) startLogout(c auth.EndpointContext, _ Store, actor Actor) (any, error) {
	if !c.DirectBrowserSession(actor.SessionToken) {
		return nil, ErrUnauthenticated
	}
	if !o.SAML.EnableSingleLogout {
		return nil, errLogoutDisabled
	}
	store := c.Store().(SAMLLogoutStore)
	p, sp, err := o.logoutProvider(c, store, "/sso/saml2/logout/")
	if err != nil {
		return nil, err
	}
	proof, err := o.domainGate(c, p)
	if err != nil {
		return nil, err
	}
	var callback string
	if v, ok := c.Body["callbackURL"]; ok {
		var valid bool
		callback, valid = v.(string)
		if !valid {
			return nil, apiError(400, "Invalid callbackURL")
		}
	}
	callback, err = c.CallbackURL(callback)
	if err != nil {
		return nil, err
	}
	_, hasCallback := c.Body["callbackURL"]
	if c.Request.URL.RawQuery != "" || len(c.Body) > 1 || (len(c.Body) == 1 && !hasCallback) {
		return nil, apiError(400, "Invalid SAML logout parameters")
	}
	callback = samlLanding(c, sp.SloURL.String(), callback)
	now := time.Now().UTC()
	identity, err := store.SAMLSessionForLogout(c.Request.Context(), actor, p.ProviderID, p.Reference, now)
	if err != nil {
		return nil, err
	}
	req, err := sp.MakeLogoutRequest(sp.GetSLOBindingLocation(saml.HTTPRedirectBinding), identity.NameID.Value, func(r *saml.LogoutRequest) { name := identity.NameID; r.NameID = &name }, saml.WithSessionIndex(identity.SessionIndex))
	if err != nil {
		return nil, ErrInvalidSAML
	}
	state := rand.Text()
	destination, err := sp.RedirectLogoutRequestURL(req, state)
	if err != nil {
		return nil, ErrInvalidSAML
	}
	ttl := o.SAML.LogoutRequestTTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	cookie := req.ID + "." + rand.Text()
	pending := SAMLLogoutRequest{ID: req.ID, State: state, BrowserHash: logoutBrowserHash(cookie), ProviderID: p.ProviderID, Reference: p.Reference, CallbackURL: callback, ExpiresAt: now.Add(ttl)}
	// The store asks the request's gate before it stores the request and
	// removes the binding, so their verification hooks run outside its
	// transaction.
	committed := false
	if err := c.GateVerifications(func(ctx context.Context) error {
		err := store.StartSAMLLogout(ctx, actor, identity, pending, proof, time.Now().UTC())
		committed = err == nil
		return err
	}); err != nil {
		if committed {
			// An after hook failed once the session ended: its cookies still go.
			c.SAMLLogoutStarted(actor.SessionToken, destination.String(), cookie, ttl)
		}
		return nil, err
	}
	return c.SAMLLogoutStarted(actor.SessionToken, destination.String(), cookie, ttl), nil
}

// finishLogout accepts only a signed logout response. IdP logout messages
// must be signed; another runtime accepts unsigned ones unless
// wantLogoutResponseSigned is set, which lets any page end a user's sessions.
func (o Options) finishLogout(c auth.EndpointContext) (any, error) {
	if !o.SAML.EnableSingleLogout {
		return nil, errLogoutDisabled
	}
	store := c.Store().(SAMLLogoutStore)
	if len(c.Request.URL.RawQuery) > 1<<20 {
		return nil, ErrSAMLLogoutResponse
	}
	q, e := url.ParseQuery(c.Request.URL.RawQuery)
	if e == nil && q.Has("SAMLRequest") && o.SAML.EnableIDPInitiatedLogout {
		return o.receiveIDPLogout(c, q, store)
	}
	if e != nil || len(q) != 4 {
		return nil, ErrSAMLLogoutResponse
	}
	for _, key := range []string{"SAMLResponse", "RelayState", "SigAlg", "Signature"} {
		if len(q[key]) != 1 || q.Get(key) == "" {
			return nil, ErrSAMLLogoutResponse
		}
	}
	if !logoutSignatureAllowed(q.Get("SigAlg")) {
		return nil, ErrSAMLLogoutResponse
	}
	state := q.Get("RelayState")
	cookie := c.SAMLLogoutCookie()
	requestID, secret, ok := strings.Cut(cookie, ".")
	if !ok || len(secret) < 20 || len(secret) > 80 || len(requestID) > 128 || requestID == "" || len(state) < 20 || len(state) > 80 {
		return nil, ErrSAMLLogoutResponse
	}
	p, sp, err := o.logoutProvider(c, store, "/sso/saml2/sp/slo/")
	if err != nil {
		return nil, err
	}
	response, err := sp.ParseLogoutResponse(c.Request, []string{requestID})
	if err != nil || response.Issuer == nil || response.Issuer.Value != p.SAML.IdentityProviderEntityID() {
		return nil, ErrSAMLLogoutResponse
	}
	proof := SAMLLogoutRequest{ID: requestID, State: state, BrowserHash: logoutBrowserHash(cookie), ProviderID: p.ProviderID, Reference: p.Reference}
	var target string
	spent := false
	err = c.GateVerifications(func(ctx context.Context) (err error) {
		target, err = store.ConsumeSAMLLogout(ctx, proof, time.Now().UTC())
		spent = err == nil
		return err
	})
	if err != nil {
		if spent {
			c.SAMLLogoutCompleted() // the request was spent; its cookie redeems nothing
		}
		return nil, err
	}
	if _, err := c.CallbackURL(target); err != nil {
		// The logout response no longer trusts the stored target.
		target = "/"
	}
	redirect, err := c.Redirect(target)
	if err != nil {
		return nil, err
	}
	c.SAMLLogoutCompleted()
	return redirect, nil
}
