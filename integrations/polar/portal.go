package polar

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/polarsource/polar-go/models/apierrors"
	"github.com/polarsource/polar-go/models/components"
	"github.com/polarsource/polar-go/models/operations"
	"github.com/polarsource/polar-go/retry"
)

// PortalOptions enables a personal customer's merchant-wide portal and customer state.
type PortalOptions struct {
	// URL is the exact public HTTPS portal address without a query, for example https://polar.sh/acme/portal.
	URL string
	// ReturnURL is an optional trusted application URL. Theme can be empty, "light", or "dark".
	ReturnURL string
	Theme     string
}

func (o PortalOptions) validate() error {
	u, err := url.Parse(o.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path == "" || u.Path == "/" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(o.URL, "\\#") {
		return errors.New("polar: configure the exact HTTPS portal URL without a query or fragment")
	}
	if o.Theme != "" && o.Theme != "light" && o.Theme != "dark" {
		return errors.New("polar: portal theme must be light or dark")
	}
	return nil
}

func (s *Service) personalCustomer(c auth.EndpointContext) (*auth.SessionResult, error) {
	session, err := s.owner(c)
	if err != nil {
		return nil, err
	}
	if c.Request.URL.RawQuery != "" {
		return nil, failure(400, "POLAR_CUSTOMER_SELECTION", "Personal billing uses the signed-in account")
	}
	return session, nil
}

func (s *Service) recheckCustomer(c auth.EndpointContext, initial *auth.SessionResult) error {
	now, err := s.owner(c)
	if err != nil {
		return err
	}
	if now.Session.ID != initial.Session.ID || now.User.ID != initial.User.ID || now.User.Email != initial.User.Email {
		return conflict()
	}
	return nil
}

// Opening the portal by GET mints a credential. Same-origin fetches commonly omit Origin.
// Explicit Origin or Referer also allows native clients and configured application origins.
func portalRequestAllowed(c auth.EndpointContext) bool {
	h := c.Request.Header
	origin := h.Get("Origin")
	if origin == "" {
		origin = h.Get("Referer")
	}
	if len(h.Values("Origin")) > 1 || len(h.Values("Referer")) > 1 {
		return false
	}
	if origin == "" {
		return h.Get("Sec-Fetch-Site") == "same-origin" ||
			len(h.Values("Cookie")) == 0 && len(h.Values("Authorization")) == 1 && strings.HasPrefix(strings.ToLower(h.Get("Authorization")), "bearer ")
	}
	u, err := url.Parse(origin)
	if err != nil || !u.IsAbs() || u.Hostname() == "" || u.User != nil {
		return false
	}
	_, err = c.CallbackURL(origin)
	return err == nil
}

func customerProviderError(err error) error {
	var missing *apierrors.ResourceNotFound
	var api *apierrors.APIError
	if errors.As(err, &missing) || (errors.As(err, &api) && api.StatusCode == http.StatusNotFound) {
		return failure(404, "POLAR_CUSTOMER_NOT_FOUND", "This account has no Polar customer")
	}
	return failure(502, "POLAR_CUSTOMER_UNAVAILABLE", "Unable to access the customer at Polar")
}

func customerMismatch() error {
	return failure(502, "POLAR_CUSTOMER_MISMATCH", "Polar returned an unexpected customer or session")
}

func (s *Service) portal(c auth.EndpointContext) (any, error) {
	session, err := s.personalCustomer(c)
	if err != nil {
		return nil, err
	}
	if c.Request.Method == http.MethodGet && !portalRequestAllowed(c) {
		return nil, failure(403, "POLAR_PORTAL_ORIGIN", "A trusted application origin is required")
	}
	redirect := true
	for field, value := range c.Body {
		v, ok := value.(bool)
		if field != "redirect" || !ok {
			return nil, failure(400, "POLAR_PORTAL_FIELD", "Only a boolean redirect is supported")
		}
		redirect = v
	}
	cfg := s.opts.Portal
	req := components.CustomerSessionCustomerExternalIDCreate{ExternalCustomerID: session.User.ID}
	if cfg.ReturnURL != "" {
		back, err := c.CallbackURL(cfg.ReturnURL)
		if err != nil {
			return nil, err
		}
		req.ReturnURL = &back
	}
	reply, err := s.opts.Client.CustomerSessions.Create(c.Request.Context(),
		operations.CreateCustomerSessionsCreateCustomerSessionCreateCustomerSessionCustomerExternalIDCreate(req),
		operations.WithSetHeaders(map[string]string{"Polar-Version": apiVersion}),
		operations.WithRetries(retry.Config{Strategy: "none"}),
	)
	if err != nil {
		return nil, customerProviderError(err)
	}
	p := reply.GetCustomerSession()
	person := p.GetCustomerIndividual()
	if p == nil || person == nil || person.DeletedAt != nil || !canonicalID(person.ID) || !canonicalID(p.ID) ||
		p.CustomerID != person.ID || val(person.ExternalID) != session.User.ID || person.OrganizationID != s.opts.OrganizationID ||
		!p.ExpiresAt.After(time.Now()) || val(p.ReturnURL) != val(req.ReturnURL) {
		return nil, customerMismatch()
	}
	link, err := cfg.customerURL(p)
	if err != nil {
		return nil, err
	}
	if err = s.recheckCustomer(c, session); err != nil {
		return nil, err
	}
	return map[string]any{"url": link, "redirect": redirect}, nil
}

func (o PortalOptions) customerURL(session *components.CustomerSession) (string, error) {
	link, err := url.Parse(session.CustomerPortalURL)
	if err != nil || link.Fragment != "" || strings.ContainsAny(session.CustomerPortalURL, "\\#") {
		return "", customerMismatch()
	}
	query, err := url.ParseQuery(link.RawQuery)
	link.RawQuery = ""
	link.ForceQuery = false
	if err != nil || link.String() != o.URL || session.Token == "" ||
		len(query["customer_session_token"]) != 1 || query.Get("customer_session_token") != session.Token {
		return "", customerMismatch()
	}
	for key, values := range query {
		if len(values) != 1 || key != "customer_session_token" && key != "email" {
			return "", customerMismatch()
		}
	}
	if o.Theme != "" {
		query.Set("theme", o.Theme)
	}
	link.RawQuery = query.Encode()
	return link.String(), nil
}

func (s *Service) customerState(c auth.EndpointContext) (any, error) {
	session, err := s.personalCustomer(c)
	if err != nil {
		return nil, err
	}
	reply, err := s.opts.Client.Customers.GetStateExternal(c.Request.Context(), session.User.ID,
		operations.WithSetHeaders(map[string]string{"Polar-Version": apiVersion}),
	)
	if err != nil {
		return nil, customerProviderError(err)
	}
	person := reply.GetCustomerStateIndividual()
	if person == nil || person.DeletedAt != nil || !canonicalID(person.ID) ||
		val(person.ExternalID) != session.User.ID || person.OrganizationID != s.opts.OrganizationID {
		return nil, customerMismatch()
	}
	if err = s.recheckCustomer(c, session); err != nil {
		return nil, err
	}
	return publicState(person), nil
}
