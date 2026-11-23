package plainauth

import (
	"errors"
	"net/http"
	"strings"
)

type oauthAuthorizationDispatch struct{ request *http.Request }

// ResumeOAuthAuthorization re-enters the mounted GET authorization endpoint.
// Route hooks, disabled paths and rate limits run on the resumed request.
func (c EndpointContext) ResumeOAuthAuthorization(r *http.Request) (any, error) {
	if !c.Auth.isOAuthAuthorizationRequest(r) {
		return nil, errors.New("auth: invalid OAuth login continuation")
	}
	return oauthAuthorizationDispatch{r}, nil
}

func (a *Auth) isOAuthAuthorizationRequest(r *http.Request) bool {
	return r != nil && r.URL != nil && r.Method == http.MethodGet && r.URL.EscapedPath() == strings.TrimRight(a.BasePath(), "/")+"/oauth2/authorize"
}

func (a *Auth) loginContinuation(route string, r *http.Request, body wireBody, h http.Header) (OAuthLoginContinuation, error) {
	raw, present := body["oauth_query"]
	if !present {
		return nil, nil
	}
	prepare := a.prepareOAuthLogin
	switch route {
	case "/sign-in/email", "/sign-up/email", "/sign-in/social", "/sign-in/sso", "/sign-in/username", "/sign-in/phone-number", "/sign-in/email-otp", "/passkey/verify-authentication",
		"/two-factor/verify-totp", "/two-factor/verify-otp", "/two-factor/verify-backup-code":
	case "/organization/set-active", "/organization/set-active-team":
		prepare = a.prepareOAuthSelection
	default:
		return nil, nil
	}
	if prepare == nil {
		return nil, nil
	}
	if strings.HasPrefix(route, "/two-factor/") && a.cookieToken(r.Header) != "" {
		return nil, &OAuthError{Status: 400, Code: "invalid_request", Description: "a pending login challenge is required"}
	}
	if r.Header.Get("Authorization") != "" || r.Context().Value(credentialSessionKey{a}) != nil {
		return nil, &OAuthError{Status: 401, Code: "unauthorized", Description: "direct browser login required"}
	}
	query, ok := raw.(string)
	if !ok || query == "" {
		return nil, &OAuthError{Status: 400, Code: "invalid_request", Description: "signed oauth_query required"}
	}
	return prepare(EndpointContext{Auth: a, Request: r, Body: body, ResponseHeader: h}, query)
}

func (a *Auth) resumeIssuedOAuthLogin(w http.ResponseWriter, r *http.Request, resume OAuthLoginContinuation, priorCookies int) (bool, error) {
	var issued *http.Cookie
	headers := w.Header().Values("Set-Cookie")
	if len(headers) <= priorCookies {
		return false, nil
	}
	for _, line := range headers[priorCookies:] {
		cookie, err := http.ParseSetCookie(line)
		if err == nil && cookie.Name == a.cookieName() {
			issued = cookie
		}
	}
	if issued == nil || issued.Value == "" || issued.MaxAge < 0 {
		return false, nil
	}
	token := a.VerifySignedSessionToken(issued.Value)
	if token == "" {
		return false, nil
	}
	stored, _, err := a.opts.Store.Session(r.Context(), token)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !stored.ExpiresAt.After(a.now()) {
		return false, nil
	}
	// A credential endpoint's own callback no longer applies once this login
	// takes over, including when the signed authorization has just expired.
	w.Header().Del("Location")
	if err = stored.RequireOwner(); err != nil {
		return false, err
	}
	stored.Token = token
	next, err := resume(stored.Session)
	if err != nil {
		return false, err
	}
	if !a.isOAuthAuthorizationRequest(next) {
		return false, errors.New("auth: invalid OAuth login continuation")
	}
	// Keep host cookies such as a tenant selection. Only the newly issued
	// credential may identify the browser on the resumed authorization request.
	cookies := next.Cookies()
	next.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != issued.Name {
			next.AddCookie(cookie)
		}
	}
	next.AddCookie(&http.Cookie{Name: issued.Name, Value: issued.Value})
	a.ServeHTTP(w, next)
	return true, nil
}
