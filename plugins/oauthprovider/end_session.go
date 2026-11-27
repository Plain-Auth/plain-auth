package oauthprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/httporigin"
	jose "github.com/go-jose/go-jose/v4"
)

// EndSessionStore reads the session an ID token hint names, for
// RP-Initiated Logout at /oauth2/end-session.
type EndSessionStore interface {
	ClientDirectoryStore
	// OAuthLogoutSessionToken returns the token of the session with this
	// ID, or auth.ErrNotFound. A session that already ended is not found.
	OAuthLogoutSessionToken(ctx context.Context, sessionID string) (string, error)
}

const (
	endSessionPath           = "/oauth2/end-session"
	endSessionConfirmPath    = "/oauth2/end-session/confirm"
	logoutConfirmationSuffix = ".oauth_logout_confirmation"
	logoutConfirmationTTL    = 5 * time.Minute
	logoutPagePolicy         = "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
	unregisteredLogoutNote   = "The requested post-logout redirect was not registered."
	logoutFormTypes          = "application/x-www-form-urlencoded, application/json"
)

// logoutRequest holds the RP-Initiated Logout parameters.
type logoutRequest struct {
	hint, clientID, redirect, state string
	hasHint                         bool
}

// logoutConfirmation is the signed state the confirmation cookie carries.
type logoutConfirmation struct {
	SessionID       string `json:"sessionId,omitempty"`
	ClientID        string `json:"clientId,omitempty"`
	RedirectURI     string `json:"postLogoutRedirectUri,omitempty"`
	State           string `json:"state,omitempty"`
	RedirectInvalid bool   `json:"redirectInvalid,omitempty"`
	ExpiresAt       int64  `json:"expiresAt"`
}

// logoutRedirect is where a completed logout goes: uri when the client
// registered it, or invalid when one was asked for and is not registered.
type logoutRedirect struct {
	uri     string
	invalid bool
}

// logoutCall is one end-session or confirmation request.
type logoutCall struct {
	opts    Options
	c       auth.EndpointContext
	store   EndSessionStore
	browser bool
	current *auth.SessionResult
}

// endSession serves GET and POST /oauth2/end-session, as another runtime's
// rpInitiatedLogoutEndpoint does.
func (opts Options) endSession(c auth.EndpointContext) (any, error) {
	l, err := opts.startLogout(c)
	if err != nil {
		return nil, err
	}
	req, err := readLogoutRequest(c.Request)
	if err != nil {
		return nil, err
	}
	if req.redirect != "" && !opts.Registration.redirectTransportAllowed(req.redirect, false) {
		return l.protocolError(http.StatusBadRequest, "invalid_request", insecureRedirectMessage)
	}
	if err := l.readCurrentSession(); err != nil {
		return nil, err
	}
	if !req.hasHint {
		var confirmation logoutConfirmation
		if req.clientID != "" {
			client, err := l.client(req.clientID)
			if err != nil {
				return nil, err
			}
			if answer, err, refused := l.refuseClient(client); refused {
				return answer, err
			}
			confirmation = confirmationFor(*client, req)
		}
		return l.confirmationRequired(confirmation)
	}
	client, err := l.hintClient(req)
	if err != nil {
		return nil, err
	}
	if client == nil {
		if l.current != nil && l.browser {
			return l.confirmationRequired(logoutConfirmation{})
		}
		return l.protocolError(http.StatusBadRequest, "invalid_client", "The logout client does not exist")
	}
	if answer, err, refused := l.refuseClient(client); refused {
		return answer, err
	}
	claims := l.verifyHint(req.hint, *client)
	if claims == nil {
		if l.current != nil && l.browser {
			var confirmation logoutConfirmation
			if req.clientID != "" {
				confirmation = confirmationFor(*client, req)
			}
			return l.confirmationRequired(confirmation)
		}
		return l.protocolError(http.StatusUnauthorized, "invalid_token", "The id_token_hint is invalid")
	}
	sid := claims["sid"].(string)
	hinted, err := l.store.OAuthLogoutSessionToken(c.Request.Context(), sid)
	if errors.Is(err, auth.ErrNotFound) {
		hinted, err = "", nil
	}
	if err != nil {
		return nil, registrationProblem(http.StatusInternalServerError, "server_error", "Unable to read the hinted session")
	}
	matches := l.current != nil && l.current.Session.ID == sid
	if l.current != nil && !matches {
		return l.confirmationRequired(confirmationFor(*client, req))
	}
	redirect := registeredLogoutRedirect(*client, req.redirect, req.state)
	if hinted == "" && matches {
		hinted = l.current.Session.Token
	}
	if hinted != "" {
		if err := l.c.EndSession(hinted); err != nil {
			return nil, registrationProblem(http.StatusInternalServerError, "server_error", "Unable to complete logout")
		}
	}
	l.clearConfirmation()
	return l.finish(redirect)
}

// confirmEndSession serves POST /oauth2/end-session/confirm, as another
// runtime's completeConfirmedLogout does.
func (opts Options) confirmEndSession(c auth.EndpointContext) (any, error) {
	l, err := opts.startLogout(c)
	if err != nil {
		return nil, err
	}
	if err := readConfirmAction(c.Request); err != nil {
		return nil, err
	}
	state := l.readConfirmation()
	if err := l.readCurrentSession(); err != nil {
		return nil, err
	}
	if state == nil || state.ExpiresAt <= time.Now().UnixMilli() {
		return l.protocolError(http.StatusBadRequest, "invalid_request", "The logout confirmation is invalid or expired")
	}
	redirect, err := l.confirmedRedirect(*state)
	if err != nil {
		return nil, err
	}
	if l.current == nil {
		l.clearConfirmation()
		if redirect.uri == "" && !l.browser {
			return l.protocolError(http.StatusBadRequest, "invalid_request", "No active session is available for logout")
		}
		return l.finish(redirect)
	}
	if state.SessionID != "" && state.SessionID != l.current.Session.ID {
		return l.protocolError(http.StatusBadRequest, "invalid_request", "The logout confirmation is invalid or expired")
	}
	if err := l.c.EndSession(l.current.Session.Token); err != nil {
		return nil, registrationProblem(http.StatusInternalServerError, "server_error", "Unable to complete logout")
	}
	l.clearConfirmation()
	return l.finish(redirect)
}

func (opts Options) startLogout(c auth.EndpointContext) (*logoutCall, error) {
	c.ResponseHeader.Set("Cache-Control", "no-store")
	c.ResponseHeader.Set("Pragma", "no-cache")
	store, ok := c.Store().(EndSessionStore)
	if !ok {
		return nil, &auth.APIError{Status: http.StatusNotImplemented, Code: "OAUTH_END_SESSION_UNAVAILABLE", Message: "The configured store does not support OAuth logout"}
	}
	return &logoutCall{opts: opts, c: c, store: store, browser: browserNavigation(c.Request.Header)}, nil
}

// browserNavigation reports a top-level browser request, which gets pages
// instead of JSON, as another runtime decides.
func browserNavigation(h http.Header) bool {
	mode := h.Get("Sec-Fetch-Mode")
	if mode == "cors" {
		return false
	}
	accept := h.Get("Accept")
	return mode == "navigate" || strings.Contains(accept, "text/html") || strings.Contains(accept, "application/xhtml+xml")
}

// readCurrentSession reads the session the browser's signed session cookie
// names, as another runtime reads it: by its stored row, even one that has
// expired, whatever other credentials the request carries.
func (l *logoutCall) readCurrentSession() error {
	token := l.c.SAMLLogoutBrowserToken()
	if token == "" {
		return nil
	}
	row, _, err := l.c.Store().Session(l.c.Request.Context(), token)
	if errors.Is(err, auth.ErrNotFound) {
		return nil
	}
	if err != nil {
		return registrationProblem(http.StatusInternalServerError, "server_error", "Unable to read the current session")
	}
	row.Token = token
	l.current = &auth.SessionResult{Session: row.Session}
	return nil
}

// client looks up a logout client; a missing one is nil.
func (l *logoutCall) client(id string) (*ClientDetails, error) {
	c, err := l.opts.discoverRequestClient(l.c, id)
	if err != nil {
		return nil, err
	}
	l.c = c
	client, err := l.store.LookupOAuthClient(l.c.Request.Context(), id)
	if errors.Is(err, ErrClientNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, registrationProblem(http.StatusInternalServerError, "server_error", "Unable to resolve the logout client")
	}
	return &client, nil
}

// refuseClient answers for a missing, disabled or not end-session client.
func (l *logoutCall) refuseClient(client *ClientDetails) (any, error, bool) {
	switch {
	case client == nil:
		answer, err := l.protocolError(http.StatusBadRequest, "invalid_client", "The logout client does not exist")
		return answer, err, true
	case client.Disabled != nil && *client.Disabled:
		answer, err := l.protocolError(http.StatusBadRequest, "invalid_client", "The logout client is disabled")
		return answer, err, true
	case client.EnableEndSession == nil || !*client.EnableEndSession:
		answer, err := l.protocolError(http.StatusUnauthorized, "invalid_client", "The client is not allowed to initiate logout")
		return answer, err, true
	}
	return nil, nil, false
}

// hintClient resolves the hint's client from client_id or, unverified,
// from its aud or azp, looking up at most one client so a large audience
// list cannot multiply lookups.
func (l *logoutCall) hintClient(req logoutRequest) (*ClientDetails, error) {
	if req.clientID != "" {
		return l.client(req.clientID)
	}
	parts := strings.Split(req.hint, ".")
	if len(parts) != 3 {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil
	}
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil {
		return nil, nil
	}
	candidate, _ := payload["aud"].(string)
	if candidate == "" {
		candidate, _ = payload["azp"].(string)
	}
	if candidate == "" {
		if audiences := hintAudiences(payload["aud"]); len(audiences) == 1 {
			candidate = audiences[0]
		}
	}
	if candidate == "" {
		return nil, nil
	}
	return l.client(candidate)
}

// hintAudiences lists the string audiences of an aud claim.
func hintAudiences(aud any) []string {
	values, ok := aud.([]any)
	if !ok {
		values = []any{aud}
	}
	var out []string
	for _, v := range values {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// verifyHint checks the hint's signature and issuer, that it names the
// client, and that it carries a session and a subject. Expiry is not
// checked, as RP-Initiated Logout accepts an expired ID token.
func (l *logoutCall) verifyHint(hint string, client ClientDetails) map[string]any {
	var claims map[string]any
	if l.opts.DisableJWTPlugin {
		claims = l.verifySecretHint(hint, client.ClientID)
	} else {
		claims, _ = l.c.OAuthIDTokenHint(hint)
	}
	if claims == nil || !slices.Contains(hintAudiences(claims["aud"]), client.ClientID) {
		return nil
	}
	if sid, _ := claims["sid"].(string); sid == "" {
		return nil
	}
	if sub, _ := claims["sub"].(string); sub == "" {
		return nil
	}
	return claims
}

// verifySecretHint verifies an HS256 ID token signed with the client's
// secret, read back from its encrypted storage, as with DisableJWTPlugin.
func (l *logoutCall) verifySecretHint(hint, clientID string) map[string]any {
	reader, ok := l.store.(MachineClientReader)
	if !ok {
		return nil
	}
	ctx := l.c.Request.Context()
	stored, err := reader.LookupMachineClient(ctx, clientID)
	if err != nil || stored.ClientID != clientID || stored.StoredSecret == "" {
		return nil
	}
	secret, err := l.opts.Registration.storedSecret(ctx, l.c.Auth, clientID, stored.StoredSecret)
	if err != nil || secret == "" {
		return nil
	}
	signed, err := jose.ParseSignedCompact(hint, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		return nil
	}
	payload, err := signed.Verify([]byte(l.opts.Registration.SecretPrefix + secret))
	if err != nil {
		return nil
	}
	var claims map[string]any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if decoder.Decode(&claims) != nil {
		return nil
	}
	if issuer, _ := claims["iss"].(string); issuer != l.c.Auth.OAuthIssuer() {
		return nil
	}
	return claims
}

// registeredLogoutRedirect accepts only an exact registered URI and adds
// the state to it.
func registeredLogoutRedirect(client ClientDetails, requested, state string) logoutRedirect {
	if requested == "" {
		return logoutRedirect{}
	}
	if !slices.Contains(client.PostLogoutRedirectURIs, requested) {
		return logoutRedirect{invalid: true}
	}
	if state == "" {
		return logoutRedirect{uri: requested}
	}
	if _, err := url.Parse(requested); err != nil {
		return logoutRedirect{invalid: true}
	}
	return logoutRedirect{uri: httporigin.SetQuery(requested, url.Values{"state": {state}})}
}

// confirmationFor keeps the redirect a confirmed logout may use.
func confirmationFor(client ClientDetails, req logoutRequest) logoutConfirmation {
	if req.redirect == "" {
		return logoutConfirmation{}
	}
	if registeredLogoutRedirect(client, req.redirect, req.state).invalid {
		return logoutConfirmation{RedirectInvalid: true}
	}
	return logoutConfirmation{ClientID: client.ClientID, RedirectURI: req.redirect, State: req.state}
}

// confirmedRedirect checks the kept redirect again, since the client or
// the redirect policy may have changed after the page was shown.
func (l *logoutCall) confirmedRedirect(state logoutConfirmation) (logoutRedirect, error) {
	if state.RedirectInvalid {
		return logoutRedirect{invalid: true}, nil
	}
	if state.ClientID == "" || state.RedirectURI == "" {
		return logoutRedirect{}, nil
	}
	if !l.opts.Registration.redirectTransportAllowed(state.RedirectURI, false) {
		return logoutRedirect{invalid: true}, nil
	}
	client, err := l.client(state.ClientID)
	if err != nil {
		return logoutRedirect{}, err
	}
	if client == nil || client.Disabled != nil && *client.Disabled || client.EnableEndSession == nil || !*client.EnableEndSession {
		return logoutRedirect{invalid: true}, nil
	}
	return registeredLogoutRedirect(*client, state.RedirectURI, state.State), nil
}

// confirmationRequired shows a browser the confirmation page with a
// signed state cookie, or refuses another caller.
func (l *logoutCall) confirmationRequired(confirmation logoutConfirmation) (any, error) {
	if l.current == nil {
		if !l.browser {
			return l.protocolError(http.StatusBadRequest, "invalid_request", "No active session is available for logout")
		}
	} else {
		if !l.browser {
			return l.protocolError(http.StatusBadRequest, "invalid_request", "User confirmation is required to complete logout")
		}
		confirmation.SessionID = l.current.Session.ID
	}
	confirmation.ExpiresAt = time.Now().Add(logoutConfirmationTTL).UnixMilli()
	value, err := json.Marshal(confirmation)
	if err != nil {
		return nil, err
	}
	cookie := l.confirmationCookie(string(value), int(logoutConfirmationTTL/time.Second))
	l.c.ResponseHeader.Add("Set-Cookie", cookie.String())
	action := html.EscapeString(l.c.Auth.PublicURL() + endSessionConfirmPath)
	return l.page("Confirm logout", `<main><h1>Confirm logout</h1><p>Do you want to log out of this account?</p><form method="post" data-oidc-logout-confirmation action="`+action+`"><button type="submit" name="action" value="confirm">Confirm logout</button></form></main>`), nil
}

// finish redirects to the registered URI, or shows a browser the
// logged-out page, or answers JSON null.
func (l *logoutCall) finish(redirect logoutRedirect) (any, error) {
	if redirect.uri != "" {
		return l.c.RegisteredOAuthRedirect(redirect.uri), nil
	}
	if !l.browser {
		return nil, nil
	}
	message := "Logged out."
	if redirect.invalid {
		message += " " + html.EscapeString(unregisteredLogoutNote)
	}
	return l.page("Logged out", `<main><p data-oidc-logout-state="logged-out">`+message+`</p></main>`), nil
}

// protocolError shows a browser an error page and gives other callers an
// OAuth error.
func (l *logoutCall) protocolError(status int, code, description string) (any, error) {
	if !l.browser {
		return nil, registrationProblem(status, code, description)
	}
	page := l.page("Logout error", `<main><h1>Logout error</h1><p data-oidc-logout-state="error">`+html.EscapeString(description)+`</p></main>`)
	return nil, &auth.HTMLError{Status: status, Page: page}
}

func (l *logoutCall) page(title, body string) auth.HTMLPage {
	l.c.ResponseHeader.Set("Content-Security-Policy", logoutPagePolicy)
	return auth.HTMLPage(`<!doctype html><html><head><meta charset="utf-8"><title>` + html.EscapeString(title) + `</title></head><body>` + body + `</body></html>`)
}

// confirmationCookie is named after the session cookie, with that cookie's
// attributes, scoped to the confirmation route.
func (l *logoutCall) confirmationCookie(value string, maxAge int) *http.Cookie {
	cookie := l.c.Auth.SignedCookie("session_token", value, maxAge)
	if maxAge < 0 {
		cookie = l.c.Auth.Cookie("session_token", "", maxAge)
	}
	cookie.Name += logoutConfirmationSuffix
	cookie.HttpOnly, cookie.SameSite = true, http.SameSiteLaxMode
	cookie.Path = endSessionConfirmPath
	if u, err := url.Parse(l.c.Auth.PublicURL() + endSessionConfirmPath); err == nil {
		cookie.Path = u.EscapedPath()
	}
	return cookie
}

func (l *logoutCall) clearConfirmation() {
	l.c.ResponseHeader.Add("Set-Cookie", l.confirmationCookie("", -1).String())
}

// readConfirmation returns the signed confirmation state, or nil when it is
// missing, repeated, tampered with or malformed.
func (l *logoutCall) readConfirmation() *logoutConfirmation {
	cookies := l.c.Request.CookiesNamed(l.c.Auth.Cookie("session_token", "", 0).Name + logoutConfirmationSuffix)
	if len(cookies) != 1 {
		return nil
	}
	value := l.c.Auth.VerifySignedSessionToken(cookies[0].Value)
	if value == "" {
		return nil
	}
	var fields map[string]any
	if json.Unmarshal([]byte(value), &fields) != nil || fields == nil {
		return nil
	}
	text := func(name string, nonEmpty bool) (string, bool) {
		v, present := fields[name]
		if !present {
			return "", true
		}
		s, ok := v.(string)
		return s, ok && (!nonEmpty || s != "")
	}
	var state logoutConfirmation
	var ok bool
	for _, f := range []struct {
		name     string
		nonEmpty bool
		dest     *string
	}{{"sessionId", true, &state.SessionID}, {"clientId", true, &state.ClientID}, {"postLogoutRedirectUri", true, &state.RedirectURI}, {"state", false, &state.State}} {
		if *f.dest, ok = text(f.name, f.nonEmpty); !ok {
			return nil
		}
	}
	if v, present := fields["redirectInvalid"]; present {
		if state.RedirectInvalid, ok = v.(bool); !ok {
			return nil
		}
	}
	if _, present := fields["postLogoutRedirectUri"]; present && state.ClientID == "" {
		return nil
	}
	expires, ok := fields["expiresAt"].(float64)
	if !ok || math.IsInf(expires, 0) || math.IsNaN(expires) {
		return nil
	}
	state.ExpiresAt = int64(expires)
	return &state
}

// readLogoutRequest merges the query with a form or JSON body, the body
// winning, and checks each parameter as another runtime's schema does.
func readLogoutRequest(r *http.Request) (logoutRequest, error) {
	merged := map[string]string{}
	query, _ := url.ParseQuery(r.URL.RawQuery)
	for _, name := range logoutFields {
		values, present := query[name]
		if !present {
			continue
		}
		if len(values) > 1 {
			return logoutRequest{}, logoutFieldProblem(name + " must not appear more than once")
		}
		merged[name] = values[0]
	}
	if r.Method == http.MethodPost {
		body, err := readLogoutBody(r)
		if err != nil {
			return logoutRequest{}, err
		}
		for name, value := range body {
			merged[name] = value
		}
	}
	if raw, present := merged["post_logout_redirect_uri"]; present {
		if problem := redirectSyntax(raw); problem != "" {
			return logoutRequest{}, logoutFieldProblem("post_logout_redirect_uri: " + problem)
		}
	}
	hint, hasHint := merged["id_token_hint"]
	return logoutRequest{hint: hint, hasHint: hasHint, clientID: merged["client_id"], redirect: merged["post_logout_redirect_uri"], state: merged["state"]}, nil
}

var logoutFields = []string{"id_token_hint", "client_id", "post_logout_redirect_uri", "state"}

func logoutFieldProblem(description string) error {
	return registrationProblem(http.StatusBadRequest, "invalid_request", description)
}

// readLogoutBody reads a form or JSON body of string parameters.
func readLogoutBody(r *http.Request) (map[string]string, error) {
	data, err := io.ReadAll(r.Body) // Raw plugin requests are bounded by the auth handler.
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, &auth.APIError{Status: http.StatusRequestEntityTooLarge, Code: "PAYLOAD_TOO_LARGE", Message: "Request body too large"}
		}
		return nil, logoutFieldProblem("Invalid request body")
	}
	media := r.Header.Get("Content-Type")
	base, _, _ := strings.Cut(media, ";")
	base = strings.ToLower(strings.TrimSpace(base))
	out := map[string]string{}
	switch {
	case len(data) == 0 && media == "":
		return out, nil
	case base == tokenFormType:
		form := url.Values{}
		for pair := range strings.SplitSeq(string(data), "&") {
			if pair != "" {
				k, v, _ := strings.Cut(pair, "=")
				form.Add(decodeTokenFormValue(k), decodeTokenFormValue(v))
			}
		}
		// The last of a repeated form field wins, as another runtime reads
		// a form body.
		for _, name := range logoutFields {
			if values := form[name]; len(values) > 0 {
				out[name] = values[len(values)-1]
			}
		}
		return out, nil
	case base == "application/json":
		var body map[string]any
		if len(bytes.TrimSpace(data)) == 0 {
			return out, nil
		}
		if json.Unmarshal(data, &body) != nil {
			return nil, logoutFieldProblem("Invalid request body")
		}
		for _, name := range logoutFields {
			value, present := body[name]
			if !present {
				continue
			}
			switch v := value.(type) {
			case string:
				out[name] = v
			case []any:
				return nil, logoutFieldProblem(name + " must not appear more than once")
			default:
				return nil, logoutFieldProblem(name + " must be a string")
			}
		}
		return out, nil
	}
	msg := "Content-Type is required. Allowed types: " + logoutFormTypes
	if media != "" {
		msg = `Content-Type "` + media + `" is not allowed. Allowed types: ` + logoutFormTypes
	}
	return nil, &auth.APIError{Status: http.StatusUnsupportedMediaType, Code: "UNSUPPORTED_MEDIA_TYPE", Message: msg}
}

// readConfirmAction requires the form field action=confirm.
func readConfirmAction(r *http.Request) error {
	form, err := readTokenForm(r)
	if err != nil {
		return err
	}
	// The last of a repeated field wins, as another runtime reads a form.
	if values := form["action"]; len(values) == 0 || values[len(values)-1] != "confirm" {
		return logoutFieldProblem("action must be one of: confirm")
	}
	return nil
}
