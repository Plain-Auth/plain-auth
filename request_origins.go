package plainauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/Plain-Org/plain-auth/internal/httporigin"
)

// requestScopeKey holds the requestScope of the HTTP request a context
// belongs to.
type requestScopeKey struct{ a *Auth }

// requestScope is what DynamicBaseURL and TrustedOriginsForRequest resolve
// once for a request.
type requestScope struct {
	// origin is the request's public origin in DynamicBaseURL mode, and
	// matched reports that it came from an allowed host, not the fallback.
	origin  string
	matched bool
	// reached is the origin of the host the request reached, from its Host
	// or a trusted X-Forwarded-Host, whether allowed or not.
	reached string
	// origins are the rules TrustedOriginsForRequest added.
	origins []httporigin.Rule
}

// CheckRequestOrigin applies the handler's cross-site request check to a
// request the application serves itself, such as its own route that
// changes state for a cookie-authenticated browser. Direct Go calls skip
// the check the handler applies, so a host route should call this first. A
// request without cookies passes. One with cookies needs an Origin, or a
// Referer, that is trusted: the base URL, TrustedOrigins,
// TrustedOriginsForRequest or, with DynamicBaseURL, an allowed host it
// reached. A null Origin passes only as a same-origin request. Otherwise it
// returns a 403 *APIError with code INVALID_ORIGIN or MISSING_OR_NULL_ORIGIN.
// With DisableCSRFCheck it returns nil.
func (a *Auth) CheckRequestOrigin(r *http.Request) error {
	scoped, err := a.withRequestScope(r)
	if err != nil {
		return err
	}
	return a.validateRequestOrigin(scoped, false)
}

// withRequestScope resolves the request's origin and its added trusted
// origins once. A nested dispatch of the same request keeps its scope.
func (a *Auth) withRequestScope(r *http.Request) (*http.Request, error) {
	if (a.dynamic == nil && a.opts.TrustedOriginsForRequest == nil) || r.Context().Value(requestScopeKey{a}) != nil {
		return r, nil
	}
	scope := &requestScope{}
	if a.dynamic != nil {
		if err := a.resolveOrigin(r, scope); err != nil {
			return nil, err
		}
	}
	if a.opts.TrustedOriginsForRequest != nil {
		rules, err := a.requestTrustedOrigins(r)
		if err != nil {
			return nil, err
		}
		scope.origins = rules
	}
	return r.WithContext(context.WithValue(r.Context(), requestScopeKey{a}, scope)), nil
}

// requestTrustedOrigins runs TrustedOriginsForRequest for r.
func (a *Auth) requestTrustedOrigins(r *http.Request) ([]httporigin.Rule, error) {
	list, err := a.opts.TrustedOriginsForRequest(accountObserverRequest(r.Context(), r))
	var problem *APIError
	if errors.As(err, &problem) && problem != nil && problem.Status >= 400 && problem.Status <= 599 {
		return nil, problem
	}
	if err != nil {
		a.Logger().ErrorContext(r.Context(), "auth: TrustedOriginsForRequest failed")
		// %v keeps the host's text for OnAPIError but not its error types,
		// so the response is always a generic 500.
		return nil, fmt.Errorf("auth: TrustedOriginsForRequest: %v", err)
	}
	list = slices.DeleteFunc(slices.Clone(list), func(s string) bool { return s == "" })
	rules, err := httporigin.Compile("TrustedOriginsForRequest", list)
	if err != nil {
		a.Logger().ErrorContext(r.Context(), "auth: TrustedOriginsForRequest returned an invalid origin")
		return nil, err
	}
	return rules, nil
}

// originRules returns the static trusted origins, followed by any that
// TrustedOriginsForRequest added for the request ctx belongs to.
func (a *Auth) originRules(ctx context.Context) []httporigin.Rule {
	s, _ := ctx.Value(requestScopeKey{a}).(*requestScope)
	if s == nil || len(s.origins) == 0 {
		return a.trustedOrigins
	}
	return slices.Concat(a.trustedOrigins, s.origins)
}
