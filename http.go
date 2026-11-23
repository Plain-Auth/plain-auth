// HTTP request handling for the core authentication endpoints.

package plainauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/Plain-Auth/plain-auth/internal/httporigin"
	"github.com/Plain-Auth/plain-auth/internal/jsjson"
)

const maxBodyBytes = 1 << 20

var coreMethods = map[string]string{
	"/error":            http.MethodGet,
	"/get-access-token": http.MethodPost, "/refresh-token": http.MethodPost, "/account-info": http.MethodGet,
	"/change-email": http.MethodPost, "/delete-user": http.MethodPost, "/delete-user/callback": http.MethodGet,
	"/list-accounts": http.MethodGet, "/unlink-account": http.MethodPost,
	"/verify-password": http.MethodPost, "/update-user": http.MethodPost, "/change-password": http.MethodPost,
	"/request-password-reset": http.MethodPost, "/reset-password": http.MethodPost, "/reset-password/:token": http.MethodGet,
	"/send-verification-email": http.MethodPost, "/verify-email": http.MethodGet,
	"/update-session": http.MethodPost, "/ok": http.MethodGet, "/get-session": http.MethodGet, "/list-sessions": http.MethodGet,
	"/sign-up/email": http.MethodPost, "/sign-in/email": http.MethodPost, "/sign-out": http.MethodPost,
	"/revoke-session": http.MethodPost, "/revoke-sessions": http.MethodPost, "/revoke-other-sessions": http.MethodPost,
}

// ServeHTTP serves the auth endpoints beneath the configured base path.
func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if doc, ok := a.wellKnown[r.URL.EscapedPath()]; ok {
		doc.ServeHTTP(w, r)
		return
	}
	route, mounted := strings.CutPrefix(r.URL.EscapedPath(), strings.TrimSuffix(a.opts.BasePath, "/"))
	if mounted && (route == "" || strings.HasPrefix(route, "/")) {
		if a.HTTPPathDisabled(r) {
			http.NotFound(w, r)
			return
		}
		if a.translateError != nil || a.opts.OnAPIError != nil {
			r = a.withErrorContext(r)
		}
		ctx, identity, authErr := a.resolveCredentialSession(r.Context(), r.Header, RequestMeta{IPAddress: a.clientIP(r), UserAgent: r.UserAgent()}, r)
		if authErr != nil {
			w.Header().Set("Cache-Control", "no-store")
			a.writeAuthError(w, r, authErr)
			return
		}
		if identity != nil || ctx.Value(credentialProbedKey{a}) != nil {
			r = r.WithContext(ctx)
		}
		if err := a.runRequestHooks(r, route); err != nil {
			w.Header().Set("Cache-Control", "no-store")
			a.writeAuthError(w, r, err)
			return
		}
	}
	if mounted && a.serveOAuth(w, r, route) {
		return
	}
	if token, ok := strings.CutPrefix(route, "/reset-password/"); ok && token != "" && !strings.ContainsAny(token, "/%") {
		route = "/reset-password/:token"
	}
	for _, prefix := range []string{"/sso/callback/", "/sso/saml2/sp/acs/", "/sso/saml2/logout/", "/sso/saml2/sp/slo/"} {
		if id, ok := strings.CutPrefix(route, prefix); ok && id != "" && !strings.ContainsAny(id, "/%:") {
			_, exact := a.plugins[endpointKey{r.Method, route}]
			if _, exists := a.plugins[endpointKey{r.Method, prefix + ":providerId"}]; exists && !exact {
				route = prefix + ":providerId"
			}
		}
	}
	method, known := coreMethods[route]
	isSessionPost := route == "/get-session" && r.Method == http.MethodPost && a.sessionResponse == nil
	ep, pluginRoute := a.plugins[endpointKey{r.Method, route}]
	if !mounted || (!pluginRoute && (!known || (method != r.Method && !isSessionPost))) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if route == "/get-session" {
		w.Header().Set("Pragma", "no-cache")
	}

	ip := a.clientIP(r)
	if a.rejectRateLimited(w, r, route) {
		return
	}
	if route == "/error" {
		a.serveErrorPage(w, r)
		return
	}
	var body wireBody
	if r.Method != http.MethodGet {
		// A SAML assertion consumer authenticates its cross-site POST using a
		// signed IdP assertion and browser-bound, single-use RelayState.
		if ep.pluginID != "sso" || route != "/sso/saml2/sp/acs/:providerId" || !ep.RawBody {
			if err := a.validateRequestOrigin(r, isEmailRoute(route) || route == "/sign-in/sso" || route == "/sign-in/username" || route == "/sign-in/anonymous" || route == "/sign-in/magic-link" || route == "/sign-in/email-otp" || strings.HasPrefix(route, "/email-otp/") || route == "/forget-password/email-otp"); err != nil {
				a.writeAuthError(w, r, err)
				return
			}
		}
		if ep.RawBody {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		} else if !isSessionPost {
			var err error
			body, err = decodeWireBody(w, r, route)
			if err != nil {
				a.writeAuthError(w, r, err)
				return
			}
		}
		if err := a.validateCallbacks(body, r.URL.Query()); err != nil {
			a.writeAuthError(w, r, err)
			return
		}
	}
	if isSessionPost && !a.opts.DeferSessionRefresh {
		a.writeAuthError(w, r, &APIError{Status: 405, Code: "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED", Message: "POST method requires deferSessionRefresh to be enabled in session config"})
		return
	}
	continuation, err := a.loginContinuation(route, r, body, w.Header())
	if err != nil {
		a.writeAuthError(w, r, err)
		return
	}
	priorCookies := len(w.Header().Values("Set-Cookie"))
	var result any
	if pluginRoute {
		if route == "/sign-in/sso" && continuation != nil {
			r = withEnterpriseIssuerLogin(r, a, body["oauth_query"].(string), continuation)
		}
		result, err = ep.Handler(EndpointContext{Auth: a, Request: r, Body: body, ResponseHeader: w.Header()})
	} else {
		result, err = a.handleCoreRequest(route, w, r, body, ip)
	}
	if err != nil {
		a.writeAuthError(w, r, err)
		return
	}
	// A provider callback can restore a login from its consumed server-side flow.
	restored, fromProvider := result.(enterpriseIssuerLogin)
	if fromProvider {
		continuation = restored.resume
	}
	if continuation != nil {
		done, err := a.resumeIssuedOAuthLogin(w, r, continuation, priorCookies)
		if err != nil {
			a.writeAuthError(w, r, err)
			return
		}
		if done {
			return
		}
		if fromProvider {
			a.writeAuthError(w, r, &OAuthError{Status: 401, Code: "unauthorized", Description: "a new browser session is required"})
			return
		}
	}
	if dispatch, ok := result.(oauthAuthorizationDispatch); ok {
		a.ServeHTTP(w, dispatch.request)
		return
	}
	if redirect, ok := result.(authRedirect); ok {
		w.Header().Set("Location", string(redirect))
		w.WriteHeader(http.StatusFound)
		return
	}
	status := ep.SuccessStatus
	if status == 0 {
		status = http.StatusOK
	}
	if _, empty := result.(EmptyResponse); status == http.StatusNoContent || empty {
		w.WriteHeader(status)
		return
	}
	if doc, ok := result.(XMLDocument); ok {
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(status)
		_, _ = w.Write(doc)
		return
	}
	if page, ok := result.(HTMLPage); ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, string(page))
		return
	}
	writeAuthJSON(w, status, result)
}

func (a *Auth) handleCoreRequest(route string, w http.ResponseWriter, r *http.Request, body wireBody, ip string) (any, error) {
	ctx := r.Context()
	clearCookies := false
	var err error
	switch route {
	case "/ok":
		return map[string]bool{"ok": true}, nil
	case "/update-session":
		return a.sessionFieldsHTTP(w, r, body)
	case "/get-session":
		return a.presentSession(w, r)
	case "/get-access-token", "/refresh-token", "/account-info":
		return a.providerCredentialsHTTP(ctx, route, r, body)
	case "/list-accounts":
		return a.ListUserAccounts(ctx, r.Header)
	case "/unlink-account":
		id, err := requiredString(body, "accountId")
		if err != nil {
			return nil, err
		}
		return map[string]bool{"status": true}, a.UnlinkAccount(ctx, r.Header, id)
	case "/list-sessions":
		return a.ListSessions(ctx, r.Header)
	case "/sign-up/email", "/sign-in/email":
		return a.handleEmail(route, w, r, body, ip)
	case "/sign-out":
		logout, err := a.prepareProviderLogout(ctx, r.Header, body)
		if err != nil {
			return nil, err
		}
		if a.anonymous != nil {
			c := a.oauthCookie("guest_continuation", "", -1)
			if _, err := r.Cookie(c.Name); err == nil {
				http.SetCookie(w, c)
			}
		}
		if err := a.SignOut(ctx, r.Header); err != nil {
			if a.deviceSessions == nil {
				a.expireSessionCookies(w, r)
			}
			return nil, err
		}
		a.expireSessionCookies(w, r)
		if a.deviceSessions != nil {
			for _, token := range a.readDeviceCookies(r.Header).tokens {
				a.clearDeviceCookie(w.Header(), token)
			}
		}
		if logout.URL != "" {
			if logout.Redirect {
				w.Header().Set("Location", logout.URL)
			}
			return logout, nil
		}
		return map[string]bool{"success": true}, nil
	case "/revoke-session":
		token, ok := body["token"].(string)
		if !ok {
			return nil, fieldTypeError("token", "string", body)
		}
		clearCookies = token != "" && token == a.cookieToken(r.Header)
		err = a.RevokeSession(ctx, r.Header, token)
	case "/revoke-sessions":
		clearCookies = true
		err = a.RevokeSessions(ctx, r.Header)
	case "/revoke-other-sessions":
		err = a.RevokeOtherSessions(ctx, r.Header)
	default:
		return a.handleAccountRequest(route, w, r, body, ip)
	}
	if err == nil && clearCookies {
		a.expireSessionCookies(w, r)
	}
	return map[string]bool{"status": true}, err
}

func isEmailRoute(route string) bool {
	return route == "/sign-in/email" || route == "/sign-up/email"
}

func (a *Auth) handleEmail(route string, w http.ResponseWriter, r *http.Request, body wireBody, ip string) (any, error) {
	signup := route == "/sign-up/email"
	if body == nil {
		message := "[body] Invalid input: expected object, received undefined"
		if signup {
			message += "; [body] Invalid input: expected record, received undefined"
		}
		return nil, validationError(message)
	}
	required := []string{"email", "password"}
	if signup {
		required = []string{"name", "email", "password"}
	}
	var issues []string
	for _, field := range required {
		s, ok := body[field].(string)
		switch {
		case !ok:
			issues = append(issues, fieldTypeError(field, "string", body).Message)
		case signup && field == "email" && (!emailPattern.MatchString(s) || strings.Contains(s, "..")):
			issues = append(issues, "[body.email] Invalid email address")
		case signup && field == "password" && s == "":
			issues = append(issues, "[body.password] Too small: expected string to have >=1 characters")
		}
	}
	var image *string
	if value, exists := body["image"]; exists && signup {
		if s, ok := value.(string); ok {
			image = &s
		} else {
			issues = append(issues, fieldTypeError("image", "string", body).Message)
		}
	}
	var remember *bool
	if value, exists := body["rememberMe"]; exists {
		if b, ok := value.(bool); ok {
			remember = &b
		} else {
			issues = append(issues, fieldTypeError("rememberMe", "boolean", body).Message)
		}
	}
	if len(issues) > 0 {
		return nil, validationError(strings.Join(issues, "; "))
	}
	email, password := body["email"].(string), body["password"].(string)
	callback, _ := body["callbackURL"].(string)
	meta := RequestMeta{IPAddress: ip, UserAgent: r.UserAgent(), RememberMe: remember, CallbackURL: callback}
	var result AuthResult
	var err error
	if signup {
		if value, present := body["phoneNumber"]; a.phoneNumber != nil && present && value != nil && value != "" {
			return nil, &APIError{400, "PHONE_NUMBER_CANNOT_BE_SET", "Phone number can only be set by verifying it"}
		}
		in := SignUpInput{AdditionalFields: a.userFieldInput(body), Name: body["name"].(string), Email: email, Password: password, Image: image}
		if a.username != nil {
			in.Username, in.DisplayUsername, err = usernameInput(body)
			if err != nil {
				return nil, err
			}
		}
		result, r, err = a.browserSignUpEmail(r, in, meta)
	} else {
		if c, err := r.Cookie(a.TrustedDeviceCookieName()); err == nil {
			meta.TrustedDeviceCookie = c.Value
		}
		result, err = a.SignInEmail(r.Context(), SignInInput{Email: email, Password: password, RememberMe: remember}, meta)
	}
	if err != nil {
		return nil, err
	}
	return a.writeCredentialResult(w.Header(), r, body, result, remember, signup)
}
func (a *Auth) writeCredentialResult(h http.Header, r *http.Request, body wireBody, result AuthResult, remember *bool, signup bool) (any, error) {
	if result.TrustedDeviceCookie != nil {
		h.Add("Set-Cookie", result.TrustedDeviceCookie.String())
	}
	if result.Challenge != nil {
		guest, err := a.guestToken(r)
		if err != nil {
			return nil, err
		}
		if guest != "" {
			proof, err := a.sealRecord("guest-mfa:"+result.Challenge.Identifier, []byte(guest))
			if err != nil {
				return nil, err
			}
			h.Add("Set-Cookie", a.oauthCookie("guest_continuation", proof, int(a.factorOptions.ChallengeLifetime.Seconds())).String())
		}
		a.expireSessionCookieHeaders(h, r)
		h.Add("Set-Cookie", a.TwoFactorChallengeCookie(*result.Challenge).String())
		if remember != nil && !*remember {
			m := a.sessionCookie("true", false)
			m.Name = strings.TrimSuffix(m.Name, "session_token") + "dont_remember"
			h.Add("Set-Cookie", m.String())
		}
		return map[string]any{"twoFactorRedirect": true, "twoFactorMethods": result.TwoFactorMethods}, nil
	}
	response := map[string]any{"user": result.User, "token": nil}
	if result.Token != "" {
		response["token"] = result.Token
		persistent := remember == nil || *remember
		if err := a.addSessionCookieHeaders(h, r, result.Token, persistent); err != nil {
			return nil, err
		}
		a.writeRememberPreference(h, r, persistent)
	}
	if !signup {
		callback, provided := body["callbackURL"].(string)
		response["redirect"] = callback != ""
		if provided {
			response["url"] = callback
		}
		if callback != "" {
			h.Set("Location", callback)
		}
	}
	return response, nil
}

func (a *Auth) expireSessionCookies(w http.ResponseWriter, r *http.Request) {
	a.expireSessionCookieHeaders(w.Header(), r)
}

func (a *Auth) expireSessionCookieHeaders(h http.Header, r *http.Request) {
	cookie := a.clearSessionCookie()
	expireHostCopy(h, r, cookie)
	h.Add("Set-Cookie", cookie.String())
	prefix := strings.TrimSuffix(cookie.Name, "session_token")
	a.expireStoredSessionData(h, r, true)
	names := []string{"dont_remember"}
	if a.admin != nil {
		names = append(names, "admin_session")
	}
	for _, name := range names {
		cookie.Name = prefix + name
		expireHostCopy(h, r, cookie)
		h.Add("Set-Cookie", cookie.String())
	}

}

func remoteIP(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	if ip, err := netip.ParseAddr(addr); err == nil {
		return ip.Unmap().String()
	}
	return ""
}

func writeAuthJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (a *Auth) writeAuthError(w http.ResponseWriter, r *http.Request, err error) {
	if a.opts.OnAPIError != nil {
		a.reportAPIError(r, err)
	}
	var status interface{ statusOnlyCode() int }
	if errors.As(err, &status) {
		w.WriteHeader(status.statusOnlyCode())
		return
	}
	var oauthErr *OAuthError
	if errors.As(err, &oauthErr) && oauthErr.Status >= 400 && oauthErr.Status <= 599 {
		writeAuthJSON(w, oauthErr.Status, oauthErr)
		return
	}
	var apiErr *APIError
	var originalMessage *string
	if !errors.As(err, &apiErr) {
		apiErr = &APIError{Status: 500, Code: "INTERNAL_SERVER_ERROR", Message: "Internal Server Error"}
	} else if a.translateError != nil && apiErr.Code != "" {
		if message := a.translateError(a.errorContext(r), *apiErr); message != "" {
			originalMessage = &apiErr.Message
			translated := *apiErr
			translated.Message = message
			apiErr = &translated
		}
	}
	var denied *MissingPermissionsError
	switch {
	case errors.As(err, &denied):
		response := &MissingPermissionsError{APIError: apiErr, MissingPermissions: denied.MissingPermissions}
		if originalMessage != nil {
			response.OriginalMessage = *originalMessage
		}
		writeAuthJSON(w, apiErr.Status, response)
	case originalMessage != nil:
		writeAuthJSON(w, apiErr.Status, &LocalizedError{APIError: apiErr, OriginalMessage: *originalMessage})
	default:
		writeAuthJSON(w, apiErr.Status, apiErr)
	}
}

type wireBody map[string]any

func validationError(message string) *APIError {
	return &APIError{Status: 400, Code: "VALIDATION_ERROR", Message: message}
}

func fieldTypeError(field, want string, body wireBody) *APIError {
	got := "undefined"
	if value, exists := body[field]; exists {
		got = jsjson.TypeName(value)
	}
	return validationError("[body." + field + "] Invalid input: expected " + want + ", received " + got)
}

func decodeWireBody(w http.ResponseWriter, r *http.Request, route string) (wireBody, error) {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" && r.ContentLength == 0 {
		return nil, nil
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	formAllowed := isEmailRoute(route) || route == "/sign-in/anonymous"
	if err != nil || (mediaType != "application/json" && !(formAllowed && mediaType == "application/x-www-form-urlencoded")) {
		allowed := "application/json"
		if formAllowed {
			allowed = "application/x-www-form-urlencoded, " + allowed
		}
		return nil, &APIError{Status: 415, Code: "UNSUPPORTED_MEDIA_TYPE", Message: "Content-Type " + strconv.Quote(contentType) + " is not allowed. Allowed types: " + allowed}
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, &APIError{Status: 413, Code: "PAYLOAD_TOO_LARGE", Message: "Request body too large"}
		}
		return nil, &APIError{Status: 400, Code: "BAD_REQUEST", Message: "Invalid request body"}
	}
	if len(data) == 0 {
		return nil, nil
	}
	if mediaType == "application/x-www-form-urlencoded" {
		form, err := url.ParseQuery(string(data))
		if err != nil {
			return nil, validationError("Invalid form data")
		}
		body := wireBody{}
		for key, values := range form {
			if len(values) != 1 {
				return nil, validationError("Duplicate form field: " + key)
			}
			body[key] = values[0]
		}
		return body, nil
	}
	var decoded any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil || dec.Decode(new(any)) != io.EOF {
		return nil, &APIError{Status: 400, Code: "BAD_REQUEST", Message: "Invalid JSON in request body"}
	}
	body, ok := decoded.(map[string]any)
	if !ok {
		message := "[body] Invalid input: expected object, received " + jsjson.TypeName(decoded)
		if route == "/sign-up/email" {
			message += "; [body] Invalid input: expected record, received " + jsjson.TypeName(decoded)
		}
		return nil, validationError(message)
	}
	return body, nil
}

// Browser credential writes must originate from the configured site or an
// explicitly trusted origin. Host and forwarding headers are not trust anchors.
func (a *Auth) validateRequestOrigin(r *http.Request, emailRoute bool) error {
	origin, referer := r.Header.Get("Origin"), r.Header.Get("Referer")
	site, mode := r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Sec-Fetch-Mode")
	hasCookie := len(r.Header.Values("Cookie")) > 0
	metadata := site != "" || mode != "" || r.Header.Get("Sec-Fetch-Dest") != ""
	if emailRoute && !hasCookie && site == "cross-site" && mode == "navigate" {
		return &APIError{Status: 403, Code: "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED", Message: "Cross-site navigation login blocked. This request appears to be a CSRF attack."}
	}
	if !hasCookie && (!emailRoute || (!metadata && origin == "" && referer == "")) {
		return nil
	}
	if len(r.Header.Values("Origin")) > 1 || (origin == "" && len(r.Header.Values("Referer")) > 1) {
		return &APIError{Status: 403, Code: "INVALID_ORIGIN", Message: "Invalid origin"}
	}
	if origin == "null" && site == "same-origin" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		origin = scheme + "://" + r.Host
	} else if origin == "" {
		origin = referer
	}
	if origin == "" || origin == "null" {
		return &APIError{Status: 403, Code: "MISSING_OR_NULL_ORIGIN", Message: "Missing or null Origin"}
	}
	if !a.trustedURL(origin, false) {
		return &APIError{Status: 403, Code: "INVALID_ORIGIN", Message: "Invalid origin"}
	}
	return nil
}

func (a *Auth) validateCallbacks(body wireBody, query url.Values) error {
	if _, found := body["callbackURL"]; !found {
		if values := query["callbackURL"]; len(values) > 0 {
			if len(values) != 1 {
				return validationError("Invalid callbackURL: expected a string")
			}
			// A callback supplied only through the query is checked for trust
			// but does not request a redirect on a credential sign-in.
			if values[0] != "" && !a.trustedURL(values[0], true) {
				return &APIError{Status: 403, Code: "INVALID_CALLBACK_URL", Message: "Invalid callbackURL"}
			}
		}
	}
	for _, field := range []struct{ key, code, label string }{
		{"callbackURL", "INVALID_CALLBACK_URL", "callbackURL"},
		{"redirectTo", "INVALID_REDIRECT_URL", "redirectURL"},
		{"errorCallbackURL", "INVALID_ERROR_CALLBACK_URL", "errorCallbackURL"},
		{"newUserCallbackURL", "INVALID_NEW_USER_CALLBACK_URL", "newUserCallbackURL"},
	} {
		value, exists := body[field.key]
		if !exists {
			continue
		}
		s, ok := value.(string)
		if !ok {
			return validationError("Invalid " + field.label + ": expected a string")
		}
		if s != "" && !a.trustedURL(s, true) {
			return &APIError{Status: 403, Code: field.code, Message: "Invalid " + field.label}
		}
	}
	return nil
}

func (a *Auth) trustedURL(raw string, relative bool) bool {
	if strings.ContainsRune(raw, '\\') || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil {
		return false
	}
	if strings.HasPrefix(raw, "/") {
		path := strings.ToLower(u.EscapedPath())
		return relative && !strings.HasPrefix(raw, "//") && !strings.Contains(path, "%2f") && !strings.Contains(path, "%5c")
	}
	origin := httporigin.Canonical(u)
	if origin == "" {
		return false
	}
	for _, candidate := range a.trustedOrigins {
		if candidate.Matches(u, origin) {
			return true
		}
	}
	base, err := url.Parse(a.opts.BaseURL)
	return err == nil && httporigin.Canonical(base) == origin
}

// CallbackURL resolves an application callback using this instance's trusted origins.
func (a *Auth) CallbackURL(raw string) (string, error) {
	if raw == "" {
		raw = "/"
	}
	if !a.trustedURL(raw, true) {
		return "", &APIError{403, "INVALID_CALLBACK_URL", "Invalid callbackURL"}
	}
	if strings.HasPrefix(raw, "/") {
		return a.opts.BaseURL + raw, nil
	}
	return raw, nil
}
