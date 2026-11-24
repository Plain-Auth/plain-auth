package plainauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Plain-Org/plain-auth/internal/httporigin"
	"golang.org/x/oauth2"
)

// OAuthCompletion persists the verified identity, account credentials and session
// in one transaction after checking any plugin-owned identity binding.
type OAuthCompletion func(context.Context, string, string, OAuthTokens, User, StoredSession, OAuthLoginOptions) (User, bool, error)

type enterpriseIssuerLoginKey struct{ auth *Auth }
type enterpriseIssuerLogin struct {
	query  string
	resume OAuthLoginContinuation
}

func withEnterpriseIssuerLogin(r *http.Request, a *Auth, query string, resume OAuthLoginContinuation) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), enterpriseIssuerLoginKey{a}, enterpriseIssuerLogin{query, resume}))
}

// BeginEnterpriseFlow persists the provider reference and browser return destinations.
// Only the random browser binding is placed in a cookie.
func (c EndpointContext) BeginEnterpriseFlow(provider, reference, redirectURI string, signup bool) (OAuthFlow, error) {
	return c.beginEnterpriseFlow(provider, reference, redirectURI, signup, false)
}

// BeginEnterprisePostFlow binds a cross-site form return to an independent
// Secure, SameSite=None cookie. The ordinary session cookie may be absent on POST.
func (c EndpointContext) BeginEnterprisePostFlow(provider, reference, redirectURI string, signup bool) (OAuthFlow, error) {
	return c.beginEnterpriseFlow(provider, reference, redirectURI, signup, true)
}
func (a *Auth) enterpriseStateCookie(form bool, value string, age int) *http.Cookie {
	if !form {
		return a.oauthCookie("sso_state", value, age)
	}
	cookie := a.oauthCookie("saml_state", value, age)
	cookie.SameSite = http.SameSiteNoneMode
	cookie.Secure = true
	return cookie
}
func (c EndpointContext) beginEnterpriseFlow(provider, reference, redirectURI string, signup, form bool) (OAuthFlow, error) {
	a := c.Auth
	store, ok := c.Store().(OAuthStore)
	if !ok {
		return OAuthFlow{}, errors.New("enterprise sign-in requires an OAuth flow store")
	}
	now := a.now().UTC()
	browser := randomID()
	f := OAuthFlow{State: randomID(), Provider: provider, ProviderReference: reference, RedirectURI: redirectURI, Verifier: oauth2.GenerateVerifier(), Nonce: randomID(), RequestSignUp: signup, ExpiresAt: now.Add(10 * time.Minute)}
	// Only the OIDC authorization-code flow carries an issuer request across
	// the provider redirect. The dispatcher has verified this query at entry.
	if login, ok := c.Request.Context().Value(enterpriseIssuerLoginKey{a}).(enterpriseIssuerLogin); !form && ok {
		f.IssuerLoginQuery = login.query
	}
	for field, target := range map[string]*string{"callbackURL": &f.CallbackURL, "errorCallbackURL": &f.ErrorCallbackURL, "newUserCallbackURL": &f.NewUserCallbackURL} {
		raw, present := c.Body[field]
		if !present && field != "callbackURL" {
			continue
		}
		value, ok := raw.(string)
		if !ok || value == "" {
			return OAuthFlow{}, validationError("Invalid " + field)
		}
		resolved, err := c.CallbackURL(value)
		if err != nil {
			return OAuthFlow{}, err
		}
		*target = resolved
	}
	callback, err := url.Parse(redirectURI)
	if err != nil {
		return OAuthFlow{}, err
	}
	namespace := "sso:" + callback.EscapedPath()
	f.Binding = a.oauthBinding(browser, namespace, c.Request)
	if form {
		f.Binding = digest(browser + "\x00" + namespace + "\x00")
	}
	if a.anonymous != nil {
		guest, err := a.guestToken(c.Request)
		if err != nil {
			return OAuthFlow{}, err
		}
		if guest != "" {
			browser = "guest-" + browser
			f.Binding = digest(browser + "\x00" + namespace + "\x00")
			f.AnonymousSessionProof, err = a.sealRecord("guest-oauth:"+f.State, []byte(guest))
			if err != nil {
				return OAuthFlow{}, err
			}
		}
	}
	if err := store.SaveOAuthFlow(c.Request.Context(), f, now); err != nil {
		return OAuthFlow{}, err
	}
	c.ResponseHeader.Add("Set-Cookie", a.enterpriseStateCookie(form, browser, 600).String())
	return f, nil
}

// ConsumeEnterpriseFlow accepts only a single use of the browser-bound state at
// the auth host and callback path originally selected during sign-in.
func (c *EndpointContext) ConsumeEnterpriseFlow() (OAuthFlow, error) {
	q := c.Request.URL.Query()
	if len(q["state"]) != 1 || len(q["code"]) > 1 || len(q["error"]) > 1 || len(q["iss"]) > 1 {
		return OAuthFlow{}, invalidEnterpriseState()
	}
	return c.consumeEnterpriseFlow(q.Get("state"), false)
}

// ConsumeEnterprisePostFlow consumes the RelayState received in the form body.
func (c *EndpointContext) ConsumeEnterprisePostFlow(state string) (OAuthFlow, error) {
	return c.consumeEnterpriseFlow(state, true)
}
func invalidEnterpriseState() *APIError {
	return &APIError{Status: 400, Code: "INVALID_OAUTH_STATE", Message: "Invalid or expired enterprise sign-in state"}
}
func (c *EndpointContext) consumeEnterpriseFlow(state string, form bool) (OAuthFlow, error) {
	a := c.Auth
	bad := invalidEnterpriseState()
	// The flow returns to the host it started on: BaseURL, or with
	// DynamicBaseURL the host this request resolved to.
	own, err := a.origin(c.Request.Context())
	if err != nil {
		return OAuthFlow{}, err
	}
	base, _ := url.Parse(own)
	cookie, e := c.Request.Cookie(a.enterpriseStateCookie(form, "", 0).Name)
	if (a.dynamic == nil && httporigin.Canonical(&url.URL{Scheme: base.Scheme, Host: c.Request.Host}) != httporigin.Canonical(base)) || e != nil || state == "" || len(state) > 128 {
		return OAuthFlow{}, bad
	}
	namespace := "sso:" + c.Request.URL.EscapedPath()
	binding := a.oauthBinding(cookie.Value, namespace, c.Request)
	if form || strings.HasPrefix(cookie.Value, "guest-") {
		binding = digest(cookie.Value + "\x00" + namespace + "\x00")
	}
	store, ok := c.Store().(OAuthStore)
	if !ok {
		return OAuthFlow{}, bad
	}
	f, e := store.ConsumeOAuthFlow(c.Request.Context(), state, binding, a.now().UTC())
	if errors.Is(e, ErrNotFound) {
		return OAuthFlow{}, bad
	}
	if e != nil {
		return OAuthFlow{}, e
	}
	c.ResponseHeader.Add("Set-Cookie", a.enterpriseStateCookie(form, "", -1).String())
	original, e := url.Parse(f.RedirectURI)
	if e != nil || f.ProviderReference == "" || httporigin.Canonical(original) != httporigin.Canonical(base) || original.EscapedPath() != c.Request.URL.EscapedPath() {
		return OAuthFlow{}, bad
	}
	if f.AnonymousSessionProof != "" {
		guest, err := a.openRecord("guest-oauth:"+f.State, f.AnonymousSessionProof)
		current := a.cookieToken(c.Request.Header)
		if err != nil || a.anonymous == nil || current != "" && current != string(guest) {
			return OAuthFlow{}, bad
		}
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), anonymousSourceKey{}, string(guest)))
	}
	if !form && f.IssuerLoginQuery != "" {
		resume, e := a.loginContinuation("/sign-in/sso", c.Request, wireBody{"oauth_query": f.IssuerLoginQuery}, c.ResponseHeader)
		if e != nil {
			return OAuthFlow{}, e
		}
		if resume == nil {
			return OAuthFlow{}, &OAuthError{Status: 400, Code: "invalid_request", Description: "issuer login is unavailable"}
		}
		c.Request = withEnterpriseIssuerLogin(c.Request, a, f.IssuerLoginQuery, resume)
	}
	return f, nil
}

// CompleteEnterpriseFlow applies the host's account and token policy and emits
// the usual session cookies only after the store's transaction has committed.
// method is "sso-oidc" or "sso-saml", as ValidateUserInfo sees it. With
// ValidateUserInfo set, complete must follow the LoginPlan protocol, as the
// SQL store's sign-in methods do; a completion that commits in the dry run
// is refused, though a user it already stored stays.
func (c EndpointContext) CompleteEnterpriseFlow(f OAuthFlow, method string, p OAuthProfile, tokens OAuthTokens, disableSignup bool, complete OAuthCompletion) (any, error) {
	if !validSocialProfile(p) || complete == nil {
		return nil, validationError("Invalid enterprise identity")
	}
	if _, plans := c.Auth.opts.Store.(LoginPlanner); !plans && c.Auth.opts.ValidateUserInfo != nil {
		// The gate runs between a dry run and the real sign-in.
		return nil, &userInfoRejection{&APIError{403, "validation_failed", "User validation failed"}}
	}
	login, _ := c.Request.Context().Value(enterpriseIssuerLoginKey{c.Auth}).(enterpriseIssuerLogin)
	if f.IssuerLoginQuery != "" && (login.query != f.IssuerLoginQuery || login.resume == nil) {
		return nil, invalidEnterpriseState()
	}
	result, created, err := c.Auth.completeProfileWith(c.Request.Context(), c.Request, method, f.Provider, p, tokens, OAuthLoginOptions{DisableSignUp: disableSignup}, complete)
	if err != nil {
		return nil, err
	}
	var next any = login
	if f.IssuerLoginQuery == "" {
		target := f.CallbackURL
		if created && f.NewUserCallbackURL != "" {
			target = f.NewUserCallbackURL
		}
		if target != "" && !c.Auth.trustedURL(c.Request.Context(), target, true) {
			// The provider's callback request no longer trusts the stored
			// target, as with a social sign-in.
			target, _ = c.Auth.origin(c.Request.Context())
		}
		next, err = c.Redirect(target)
		if err != nil {
			return nil, c.Auth.discardUnpublishedSession(c.Request.Context(), result.Token, err)
		}
	}
	if err = c.Auth.addSessionCookieHeaders(c.ResponseHeader, c.Request, result.Token, true); err != nil {
		return nil, c.Auth.discardUnpublishedSession(c.Request.Context(), result.Token, err)
	}
	return next, nil
}
