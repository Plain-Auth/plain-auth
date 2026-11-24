package plainauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/Plain-Org/plain-auth/internal/httporigin"
)

// requestOriginsKey holds the rules TrustedOriginsForRequest added for the
// HTTP request a context belongs to.
type requestOriginsKey struct{ a *Auth }

// withRequestOrigins resolves TrustedOriginsForRequest once for r. A nested
// dispatch of the same request keeps the rules it already has.
func (a *Auth) withRequestOrigins(r *http.Request) (*http.Request, error) {
	if a.opts.TrustedOriginsForRequest == nil || r.Context().Value(requestOriginsKey{a}) != nil {
		return r, nil
	}
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
	return r.WithContext(context.WithValue(r.Context(), requestOriginsKey{a}, rules)), nil
}

// originRules returns the static trusted origins, followed by any that
// TrustedOriginsForRequest added for the request ctx belongs to.
func (a *Auth) originRules(ctx context.Context) []httporigin.Rule {
	extra, _ := ctx.Value(requestOriginsKey{a}).([]httporigin.Rule)
	if len(extra) == 0 {
		return a.trustedOrigins
	}
	return slices.Concat(a.trustedOrigins, extra)
}
