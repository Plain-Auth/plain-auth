package stonewrit

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
)

// HTMLPage is trusted HTML returned by an endpoint. Escape all dynamic text before constructing it.
type HTMLPage string

// XMLDocument is an XML representation encoded by a trusted plugin.
type XMLDocument []byte

// HTTPRoute describes one registered, enabled HTTP operation. OpenAPI is a private copy for the caller.
type HTTPRoute struct {
	Method, Path, Plugin string
	RawBody              bool
	// SuccessStatus is the endpoint's declared success status. Zero defaults to 200.
	SuccessStatus int
	OpenAPI       json.RawMessage
}

// HTTPDescription describes public settings used to document the handler.
type HTTPDescription struct {
	ServerURL, SessionCookie string
	// SSOStateCookie is the browser binding cookie for installed enterprise OIDC callbacks.
	SSOStateCookie string
	// SAMLStateCookie is set when the SP-initiated SAML form handler is installed.
	SAMLStateCookie          string
	SAMLLogoutCookie         string
	Routes                   []HTTPRoute
	Providers                []string
	MinPassword, MaxPassword int
	DisplayUsername          bool
	CustomSession            bool
}

// DescribeHTTP lists the effective routes, including option-dependent core and plugin routes.
// The server URL is derived from configuration and never trusts an incoming Host header.
func (a *Auth) DescribeHTTP() HTTPDescription {
	o := a.opts
	d := HTTPDescription{ServerURL: strings.TrimRight(o.BaseURL, "/") + o.BasePath, SessionCookie: a.cookieName(),
		MinPassword: o.MinPasswordLength, MaxPassword: o.MaxPasswordLength, CustomSession: a.sessionResponse != nil,
		DisplayUsername: a.username != nil && !a.username.DisableDisplay}
	if a.HasPlugin("sso") {
		d.SSOStateCookie = a.prefixedCookieName("sso_state")
		if ep, ok := a.plugins[endpointKey{http.MethodGet, "/sso/saml2/sp/slo/:providerId"}]; ok && ep.pluginID == "sso" {
			d.SAMLLogoutCookie = a.prefixedCookieName("saml_logout")
		}
		if ep, ok := a.plugins[endpointKey{http.MethodPost, "/sso/saml2/sp/acs/:providerId"}]; ok && ep.pluginID == "sso" {
			d.SAMLStateCookie = a.prefixedCookieName("saml_state")
		}
	}
	for name := range o.SocialProviders {
		d.Providers = append(d.Providers, name)
	}
	slices.Sort(d.Providers)
	for route, method := range coreMethods {
		switch route {
		case "/sign-in/email", "/sign-up/email":
			if !o.EmailAndPassword || route == "/sign-up/email" && o.DisableSignUp {
				continue
			}
		case "/change-email":
			if !o.ChangeEmailEnabled {
				continue
			}
		case "/delete-user", "/delete-user/callback":
			if !o.DeleteUserEnabled {
				continue
			}
		case "/request-password-reset":
			if o.SendResetPassword == nil {
				continue
			}
		case "/send-verification-email":
			if o.SendVerificationEmail == nil {
				continue
			}
		case "/get-access-token", "/refresh-token", "/account-info":
			if len(d.Providers) == 0 {
				continue
			}
		}
		d.Routes = append(d.Routes, HTTPRoute{Method: method, Path: route})
	}
	if o.DeferSessionRefresh && a.sessionResponse == nil {
		d.Routes = append(d.Routes, HTTPRoute{Method: http.MethodPost, Path: "/get-session"})
	}
	if len(d.Providers) != 0 {
		d.Routes = append(d.Routes, HTTPRoute{Method: "POST", Path: "/sign-in/social"}, HTTPRoute{Method: "POST", Path: "/link-social"},
			HTTPRoute{Method: "GET", Path: "/callback/:id"}, HTTPRoute{Method: "POST", Path: "/callback/:id"})
	}
	for _, ep := range a.plugins {
		switch ep.Path {
		case "/email-otp/change-email", "/email-otp/request-email-change":
			if a.emailOTP != nil && !a.emailOTP.ChangeEmail.Enabled {
				continue
			}
		case "/two-factor/verify-otp", "/two-factor/send-otp":
			if a.factorOptions != nil && a.factorOptions.OTP.Send == nil {
				continue
			}
		case "/two-factor/verify-totp", "/two-factor/get-totp-uri":
			if a.factorOptions != nil && a.factorOptions.TOTP.Disabled {
				continue
			}
		}
		d.Routes = append(d.Routes, HTTPRoute{Method: ep.Method, Path: ep.Path, Plugin: ep.pluginID, RawBody: ep.RawBody, SuccessStatus: ep.SuccessStatus, OpenAPI: slices.Clone(ep.OpenAPI)})
	}
	if len(a.disabledPaths) > 0 {
		d.Routes = slices.DeleteFunc(d.Routes, func(r HTTPRoute) bool {
			_, disabled := a.disabledPaths[r.Path]
			return disabled
		})
	}
	slices.SortFunc(d.Routes, func(x, y HTTPRoute) int {
		if x.Path == y.Path {
			return strings.Compare(x.Method, y.Method)
		}
		return strings.Compare(x.Path, y.Path)
	})
	return d
}
