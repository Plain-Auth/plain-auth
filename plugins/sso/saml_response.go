package sso

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/httporigin"
	"github.com/crewjam/saml"
)

type AssertionReceipt struct {
	Issuer, ID string
	Logout     *SAMLLogoutIdentity
}
type SAMLStore interface {
	BrowserStore
	CompleteSAMLLogin(ctx context.Context, reference string, provision, verified bool, provider, subject string, receipt AssertionReceipt, u auth.User, session auth.StoredSession, opts auth.OAuthLoginOptions) (auth.User, bool, error)
}

var ErrAssertionUsed = apiError(400, "SAML assertion has already been consumed")
var errSAMLResponse = apiError(400, "Invalid SAML response")

// errUnknownRequest answers a response whose InResponseTo names no request
// this sign-in sent.
var errUnknownRequest = errors.New("sso: unknown or expired SAML request ID")

// Bound provisioning work to the lifetime of the assertion the SP already
// verified. Only bearer confirmations for this callback can extend that window.
// The ACS failure descriptions for an assertion's validity times.
const (
	samlNotYetValid       = "SAML assertion is not yet valid"
	samlExpired           = "SAML assertion has expired"
	samlMissingTimestamps = "SAML assertion missing required timestamp conditions"
)

// checkTimestamps bounds the assertion by ClockSkew even when another
// component widens the library's tolerance, and applies RequireTimestamps.
// It returns a failure description, or reports that the assertion has no
// timestamp conditions.
func (o SAMLOptions) checkTimestamps(a *saml.Assertion, now time.Time) (message string, untimed bool) {
	skew := o.clockSkew()
	latest := now.Add(skew)
	if a.Conditions.NotBefore.After(latest) || a.IssueInstant.After(latest) {
		return samlNotYetValid, false
	}
	// The five-minute issue bound guards against a widened MaxIssueDelay.
	if !a.Conditions.NotOnOrAfter.IsZero() && !a.Conditions.NotOnOrAfter.After(now.Add(-skew)) || a.IssueInstant.Before(now.Add(-5*time.Minute)) {
		return samlExpired, false
	}
	if a.Conditions.NotBefore.IsZero() && a.Conditions.NotOnOrAfter.IsZero() {
		if o.RequireTimestamps {
			return samlMissingTimestamps, false
		}
		return "", true
	}
	return "", false
}

func samlProvisioningDeadline(a *saml.Assertion, acs, requestID string, now time.Time, skew time.Duration) time.Time {
	deadline := a.IssueInstant.Add(min(5*time.Minute, saml.MaxIssueDelay))
	if t := a.Conditions.NotOnOrAfter.Add(skew); !a.Conditions.NotOnOrAfter.IsZero() && t.Before(deadline) {
		deadline = t
	}
	var bearer time.Time
	for _, confirmation := range a.Subject.SubjectConfirmations {
		data := confirmation.SubjectConfirmationData
		if confirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" || data == nil ||
			data.Recipient != acs || data.InResponseTo != requestID || data.NotBefore.After(now.Add(skew)) {
			continue
		}
		if expiry := data.NotOnOrAfter.Add(skew); expiry.After(bearer) {
			bearer = expiry
		}
	}
	if bearer.Before(deadline) {
		return bearer
	}
	return deadline
}

// samlAssertionCount counts the Assertion and EncryptedAssertion elements
// anywhere in a response, or reports -1 for a document that does not parse,
// which the envelope checks then refuse.
func samlAssertionCount(raw []byte) int {
	d := xml.NewDecoder(bytes.NewReader(raw))
	count := 0
	for elements := 0; elements <= 5000; {
		tok, err := d.Token()
		if err == io.EOF {
			return count
		}
		if err != nil {
			return -1
		}
		if t, ok := tok.(xml.StartElement); ok {
			elements++
			if t.Name.Local == "Assertion" || t.Name.Local == "EncryptedAssertion" {
				count++
			}
		}
	}
	return -1
}

// The cleartext HTTP-POST profile has one directly signed assertion.
// This pass bounds the XML and checks the envelope;
// all identity data below comes from the library's authenticated assertion.
func assertionEnvelope(raw []byte, acs, requestID string) (string, error) {
	const protocol = "urn:oasis:names:tc:SAML:2.0:protocol"
	const assertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	const ds = "http://www.w3.org/2000/09/xmldsig#"
	attr := func(e xml.StartElement, name string) string {
		var val string
		seen := false
		for _, a := range e.Attr {
			if a.Name == (xml.Name{Local: name}) {
				if seen {
					return ""
				}
				seen = true
				val = a.Value
			}
		}
		return val
	}
	d := xml.NewDecoder(bytes.NewReader(raw))
	var stack []xml.Name
	var id string
	roots, signatures, elements := 0, 0, 0
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", errSAMLResponse
		}
		switch t := tok.(type) {
		case xml.Directive:
			return "", errSAMLResponse
		case xml.StartElement:
			elements++
			if elements > 5000 || len(stack) >= 64 {
				return "", errSAMLResponse
			}
			switch {
			case len(stack) == 0:
				roots++
				if requestID == "" {
					for _, v := range t.Attr {
						if v.Name == (xml.Name{Local: "InResponseTo"}) && v.Value == "" {
							return "", errSAMLResponse
						}
					}
				}
				if roots != 1 || t.Name != (xml.Name{Space: protocol, Local: "Response"}) || attr(t, "Destination") != acs {
					return "", errSAMLResponse
				}
				if attr(t, "InResponseTo") != requestID {
					return "", errUnknownRequest
				}
			case t.Name.Local == "EncryptedAssertion" || t.Name.Local == "EncryptedID" || t.Name.Local == "EncryptedAttribute" || t.Name.Local == "EncryptedData" || t.Name.Local == "EncryptedKey":
				return "", errSAMLResponse
			case t.Name == (xml.Name{Space: assertion, Local: "Assertion"}):
				if len(stack) != 1 || id != "" {
					return "", errSAMLResponse
				}
				id = attr(t, "ID")
				if id == "" || len(id) > 512 {
					return "", errSAMLResponse
				}
			case len(stack) == 2 && stack[1] == (xml.Name{Space: assertion, Local: "Assertion"}) && t.Name == (xml.Name{Space: ds, Local: "Signature"}):
				signatures++
			}
			stack = append(stack, t.Name)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 && len(bytes.TrimSpace(t)) != 0 {
				return "", errSAMLResponse
			}
		}
	}
	if id == "" || signatures != 1 {
		return "", errSAMLResponse
	}
	return id, nil
}
func samlProfile(a *saml.Assertion, m SAMLMapping, trust bool) (auth.OAuthProfile, error) {
	if a.Subject == nil || a.Subject.NameID == nil {
		return auth.OAuthProfile{}, errSAMLResponse
	}
	attrs := map[string][]string{}
	for _, stmt := range a.AttributeStatements {
		for _, v := range stmt.Attributes {
			for _, item := range v.Values {
				if !item.Nil {
					attrs[v.Name] = append(attrs[v.Name], item.Value)
				}
			}
		}
	}
	get := func(configured, fallback string) (string, error) {
		if configured == "" {
			configured = fallback
		}
		values := attrs[configured]
		// Several values for an identity attribute refuse the response, so an
		// ambiguous email cannot pick a mailbox; another runtime takes the
		// first value.
		if len(values) > 1 {
			return "", errSAMLResponse
		}
		if len(values) == 0 {
			return "", nil
		}
		return strings.TrimSpace(values[0]), nil
	}
	email, err := get(m.Email, "email")
	if err != nil {
		return auth.OAuthProfile{}, err
	}
	id := a.Subject.NameID.Value
	if email == "" {
		email = id
	}
	first, err := get(m.FirstName, "givenName")
	if err != nil {
		return auth.OAuthProfile{}, err
	}
	last, err := get(m.LastName, "surname")
	if err != nil {
		return auth.OAuthProfile{}, err
	}
	name := strings.TrimSpace(first + " " + last)
	if name == "" {
		name, err = get(m.Name, "displayName")
		if err != nil {
			return auth.OAuthProfile{}, err
		}
	}
	if name == "" {
		name = id
	}
	// The raw attributes, one value as a string and several as a list.
	raw := make(map[string]any, len(attrs))
	for name, values := range attrs {
		if len(values) == 1 {
			raw[name] = values[0]
		} else {
			raw[name] = values
		}
	}
	result := auth.OAuthProfile{Subject: id, Email: strings.ToLower(email), Name: name, Data: raw}
	// A mapped attribute passes one value as a string and several as a list.
	for field, attribute := range m.ExtraFields {
		values := attrs[attribute]
		if len(values) == 0 {
			continue
		}
		if result.AdditionalFields == nil {
			result.AdditionalFields = map[string]any{}
		}
		if len(values) == 1 {
			result.AdditionalFields[field] = values[0]
			continue
		}
		list := make([]any, len(values))
		for i, v := range values {
			list[i] = v
		}
		result.AdditionalFields[field] = list
	}
	if trust && m.EmailVerified != "" {
		verified, e := get(m.EmailVerified, "")
		if e != nil {
			return result, e
		}
		result.EmailVerified = verified == "true"
	}
	return result, nil
}

// A browser serializes an Origin with a lowercase host and no default port.
// samlRequestOrigin is the origin a SAML request reached: with
// DynamicBaseURL its host or the host a trusted proxy forwarded, otherwise
// the Host header.
func samlRequestOrigin(c auth.EndpointContext) string {
	if origin, ok := c.RequestOrigin(); ok {
		return origin
	}
	return "https://" + c.Request.Host
}

func sameSAMLOrigin(raw, entryPoint string) bool {
	origin, err := endpointURL(raw)
	if err != nil || origin.Path != "" || strings.ContainsAny(raw, "?#") {
		return false
	}
	entry, err := endpointURL(entryPoint)
	if err != nil || origin.Scheme != entry.Scheme || !strings.EqualFold(origin.Hostname(), entry.Hostname()) {
		return false
	}
	port := func(u *url.URL) string {
		if u.Port() != "" {
			return u.Port()
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return port(origin) == port(entry)
}

// samlReturn answers a GET to the ACS, as another runtime does: a signed-in
// browser goes to a trusted RelayState or the application origin, and
// another goes to the error page with invalid_request.
func (o Options) samlReturn(c auth.EndpointContext) (any, error) {
	if session, err := c.Session(); err != nil || session == nil {
		target, err := c.ErrorPageURL()
		if err != nil {
			return nil, err
		}
		return c.Redirect(httporigin.SetQuery(target, url.Values{"error": {"invalid_request"}}))
	}
	acs, err := samlACS(c, strings.TrimPrefix(c.Request.URL.Path[strings.LastIndex(c.Request.URL.Path, "/"):], "/"))
	if err != nil {
		return nil, err
	}
	return c.Redirect(samlLanding(c, acs, c.Request.URL.Query().Get("RelayState")))
}

func (o Options) samlFinish(c auth.EndpointContext) (any, error) {
	store, ok := c.Store().(SAMLStore)
	if !ok {
		return nil, apiError(501, "The configured store does not support SAML sign-in")
	}
	media, _, err := mime.ParseMediaType(c.Request.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" && media != "application/json" {
		return nil, apiError(415, "SAML requires a URL-encoded form or JSON")
	}
	if c.Request.URL.RawQuery != "" {
		return nil, errSAMLResponse
	}
	var form url.Values
	if media == "application/json" {
		// Another runtime also accepts the response as JSON.
		var body struct{ SAMLResponse, RelayState *string }
		d := json.NewDecoder(http.MaxBytesReader(nil, c.Request.Body, 1<<20))
		if d.Decode(&body) != nil || body.SAMLResponse == nil || d.Decode(new(any)) != io.EOF {
			return nil, errSAMLResponse
		}
		form = url.Values{"SAMLResponse": {*body.SAMLResponse}}
		if body.RelayState != nil {
			form.Set("RelayState", *body.RelayState)
		}
	} else {
		if err = c.Request.ParseForm(); err != nil {
			return nil, errSAMLResponse
		}
		form = c.Request.PostForm
	}
	if len(form["SAMLResponse"]) != 1 || form.Get("SAMLResponse") == "" {
		return nil, errSAMLResponse
	}
	flow, unsolicited, err := incomingSAMLFlow(&c, form)
	if err != nil {
		return nil, err
	}
	fail := func(code string) (any, error) { return enterpriseFailure(c, flow, code, "") }
	// The descriptions are the ones another runtime sends.
	const (
		invalidReference = "SSO provider reference missing or invalid"
		notAllowed       = "IdP-initiated SSO not allowed"
	)
	p, err := store.FindBrowserProvider(c.Request.Context(), Selector{ProviderID: flow.Provider, Protocol: "saml"})
	if err != nil {
		if errors.Is(err, ErrMissing) {
			if unsolicited {
				return nil, ErrMissing
			}
			return fail("invalid_provider")
		}
		return nil, err
	}
	if p.SAML == nil || p.ProviderID != flow.Provider || !available(c, p) || (!unsolicited && p.Reference != strings.TrimSuffix(flow.ProviderReference, ".dns")) {
		return enterpriseFailure(c, flow, "invalid_state", invalidReference)
	}
	if unsolicited {
		flow.CallbackURL = samlLanding(c, flow.RedirectURI, p.SAML.IDPInitiatedCallbackURL, o.SAML.IDPInitiatedCallbackURL, p.SAML.CallbackURL)
	}
	// An oversized response is refused before it is decoded or parsed. Like
	// the other ACS failures it redirects to this sign-in's error callback;
	// another runtime uses the directory's fallback landing page because it
	// checks the size before reading RelayState.
	if limit := o.SAML.responseLimit(); len(form.Get("SAMLResponse")) > limit {
		return enterpriseFailure(c, flow, "saml_error", fmt.Sprintf("SAML response exceeds maximum allowed size (%d bytes)", limit))
	}
	if unsolicited && o.SAML.AllowIDPInitiated == nil {
		return enterpriseFailure(c, flow, "unsolicited_response", notAllowed)
	}
	proof, err := o.domainGate(c, p)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(flow.ProviderReference, ".dns") && !proof {
		return nil, ErrDomainUnverified
	}
	sp, err := o.samlSP(c, p.Provider)
	if err != nil || sp.AcsURL.String() != flow.RedirectURI {
		return fail("invalid_provider")
	}
	if origins := c.Request.Header.Values("Origin"); unsolicited || len(origins) != 0 {
		if len(origins) != 1 || !sameSAMLOrigin(origins[0], sp.GetSSOBindingLocation(saml.HTTPRedirectBinding)) {
			return fail("invalid_origin")
		}
	}
	raw, err := base64.StdEncoding.DecodeString(form.Get("SAMLResponse"))
	if err != nil {
		return fail("invalid_saml_response")
	}
	requestID := "_" + flow.Nonce
	requestIDs := []string{requestID}
	if unsolicited {
		// Honor the navigation destination when the browser supplies Fetch Metadata.
		if dest := c.Request.Header.Values("Sec-Fetch-Dest"); len(dest) > 0 && (len(dest) != 1 || dest[0] != "document") {
			return fail("invalid_origin")
		}
		allowed, err := o.SAML.AllowIDPInitiated.authorize(c.Request.Context(), samlDirectory(p))
		if err != nil {
			return nil, apiError(503, "SAML directory authorization is unavailable")
		}
		if !allowed {
			return enterpriseFailure(c, flow, "unsolicited_response", notAllowed)
		}
		sp.AllowIDPInitiated = true
		requestID = ""
		requestIDs = nil
	}
	// A response carries exactly one assertion, plain or encrypted, named by
	// the error codes another runtime uses.
	switch n := samlAssertionCount(raw); {
	case n == 0:
		return enterpriseFailure(c, flow, "saml_no_assertion", "SAML response contains no assertions")
	case n > 1:
		return enterpriseFailure(c, flow, "saml_multiple_assertions", fmt.Sprintf("SAML response contains %d assertions, expected exactly 1", n))
	}
	id, err := assertionDocumentID(raw, sp, requestID, o.SAML.Algorithms)
	if errors.Is(err, errUnknownRequest) {
		return enterpriseFailure(c, flow, "invalid_saml_response", "Unknown or expired request ID")
	}
	var policy *auth.APIError
	if errors.As(err, &policy) && strings.HasPrefix(policy.Code, "SAML_") {
		return enterpriseFailure(c, flow, strings.ToLower(policy.Code), policy.Message)
	}
	if err != nil {
		return fail("invalid_saml_response")
	}
	a, err := sp.ParseXMLResponse(raw, requestIDs, sp.AcsURL)
	switch {
	case errors.Is(err, saml.ErrNotYetValid):
		return enterpriseFailure(c, flow, "saml_error", samlNotYetValid)
	case errors.Is(err, saml.ErrExpired):
		return enterpriseFailure(c, flow, "saml_error", samlExpired)
	}
	// Require bounded assertion validity even if library-wide clock settings
	// are adjusted by another application component. The library requires
	// Conditions for its audience check, so only its timestamps may be absent.
	now := time.Now()
	if err != nil || a == nil || a.ID != id || a.Issuer.Value != p.SAML.IdentityProviderEntityID() || a.Conditions == nil {
		return fail("invalid_saml_response")
	}
	if unsolicited && a.Subject != nil {
		for _, confirmation := range a.Subject.SubjectConfirmations {
			if data := confirmation.SubjectConfirmationData; data != nil && data.InResponseTo != "" {
				return fail("invalid_saml_response")
			}
		}
	}
	message, untimed := o.SAML.checkTimestamps(a, now)
	if message != "" {
		return enterpriseFailure(c, flow, "saml_error", message)
	}
	if untimed {
		// Logged before the sign-in completes, outside any store transaction.
		c.Auth.Logger().WarnContext(c.Request.Context(), "SAML assertion accepted without timestamp conditions", "providerId", p.ProviderID)
	}
	deadline := samlProvisioningDeadline(a, flow.RedirectURI, requestID, now, o.SAML.clockSkew())
	if !deadline.After(now) {
		return enterpriseFailure(c, flow, "saml_error", samlExpired)
	}
	profile, err := samlProfile(a, p.SAML.Mapping, o.SAML.TrustEmailVerified)
	if err != nil || !auth.ValidEnterpriseProfile(profile) {
		return fail("invalid_saml_response")
	}
	var resolved UserResolution
	if o.ResolveUser != nil {
		// The resolver runs before the sign-in transaction, never inside it;
		// the store rechecks the selected user and the identity under lock.
		resolved, err = o.resolveUser(c, UserResolutionInput{Protocol: "saml", ProviderID: p.ProviderID, AccountKey: AccountKey{Issuer: a.Issuer.Value, AccountID: profile.Subject},
			User: providerUser(profile), Claims: cloneClaims(profile.Data), ProviderReference: p.Reference})
		if err != nil {
			return enterpriseFailure(c, flow, errResolution.Code, errResolution.Message)
		}
		if resolved.Action == ResolveReject {
			return enterpriseFailure(c, flow, resolved.Code, resolved.Message)
		}
	}
	complete := func(ctx context.Context, provider, subject string, _ auth.OAuthTokens, u auth.User, session auth.StoredSession, opts auth.OAuthLoginOptions) (auth.User, bool, error) {
		resolved.apply(&opts)
		ctx, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		receipt := AssertionReceipt{Issuer: a.Issuer.Value, ID: id}
		if o.SAML.EnableSingleLogout && availableSAMLLogout(c, p.Provider) == nil {
			receipt.Logout = logoutIdentity(a)
		}
		return store.CompleteSAMLLogin(ctx, p.Reference, !o.DisableOrganizationProvisioning, proof, provider, subject, receipt, u, session, opts)
	}
	// requestSignUp applies to OIDC only, as in another runtime, so
	// DisableImplicitSignUp refuses every SAML sign-up.
	// SAML relays the trusted callback URL for both new and returning users.
	flow.NewUserCallbackURL = ""
	result, err := c.CompleteEnterpriseFlowWith(flow, "sso-saml", profile, auth.OAuthTokens{}, auth.EnterpriseCompletion{DisableSignUp: o.DisableImplicitSignUp, OverrideUserInfo: resolved.updates(),
		Committed: o.provisioned(p.Provider, profile, nil)}, complete)
	if out, e, ok := provisioningFailure(c, err); ok {
		return out, e
	}
	if refused := auth.UserInfoRefusal(err); refused != nil {
		return enterpriseFailure(c, flow, refused.Code, refused.Message)
	}
	if out, e, ok := resolutionFailure(c, flow, resolved, err); ok {
		return out, e
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fail("invalid_saml_response")
	case errors.Is(err, ErrDomainUnverified):
		return nil, err
	case errors.Is(err, auth.ErrOAuthLinkRequired):
		return fail("account_not_linked")
	case errors.Is(err, ErrChanged):
		return fail("SSO_PROVIDER_CHANGED")
	case errors.Is(err, ErrAssertionUsed):
		return enterpriseFailure(c, flow, "replay_detected", "SAML assertion has already been used")
	}
	if out, e, ok := profileFailure(c, flow, err); ok {
		return out, e
	}
	var ae *auth.APIError
	if errors.As(err, &ae) {
		if ae.Code == "SIGN_UP_DISABLED" {
			return fail("signup_disabled")
		}
		return fail("access_denied")
	}
	return result, err
}
