package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/httporigin"
)

// AccountSelectionOptions configures an account chooser hosted by the application.
type AccountSelectionOptions struct {
	// Page is the chooser URL. An explicit prompt=select_account requires it.
	Page string
	// ShouldRedirect runs on the initial authorization with a direct browser
	// session. An explicit account-selection prompt always opens the page.
	ShouldRedirect func(context.Context, RegistrationAccess, []string) (bool, error)
}

// SignupStep asks the browser to finish registration. An empty Page selects
// SignupPage, falling back to LoginPage. A nonempty Page must be a trusted URL.
type SignupStep struct {
	Page string
}

type BrowserAuthorizationOptions struct {
	// LoginPage receives signed requests that need a browser login. SignupPage
	// optionally selects a separate host page for prompt=create.
	LoginPage, SignupPage string
	SelectAccount         AccountSelectionOptions
	PostLogin             *PostLoginOptions
	// CheckSignup runs after login and account selection, including when a
	// signed page resumes. Return nil when this account may proceed to consent.
	CheckSignup func(context.Context, RegistrationAccess, []string) (*SignupStep, error)
	// ConsentPage is the host's trusted page for first-time or forced approval.
	ConsentPage string
	// CodeLifetime defaults to ten minutes and uses whole seconds.
	CodeLifetime time.Duration
	// ConsentReference identifies a host tenant's approval. An empty value selects personal consent.
	ConsentReference func(context.Context, RegistrationAccess, []string) (string, error)
	// ValidateRedirectURI may override the registered match after the HTTPS
	// policy, for a callback without credentials, a fragment or a script
	// scheme. Returning an error rejects the redirect.
	ValidateRedirectURI func(ctx context.Context, requested string, registered []string, defaultMatch bool) (bool, error)
	RateLimit           *auth.RateLimitRule
	// RequestURIResolver resolves a pushed authorization request: it returns
	// the stored parameters for request_uri and the URL's client_id, or nil
	// when the URI is unknown or expired. It runs outside any transaction,
	// and the host owns the pushed request endpoint.
	RequestURIResolver func(ctx context.Context, requestURI, clientID string) (url.Values, error)
	// AllowPublicClientPrelogin serves POST /oauth2/public-client-prelogin to
	// login pages without a session. The signed oauth_query must name the
	// requested client, and its public fields, contacts included, become
	// readable by anyone who can start an authorization request.
	AllowPublicClientPrelogin bool
	// RequireOpenID refuses an authorization request whose scope parameter
	// omits openid with invalid_scope; the client's default scopes do not
	// count. Scopes must include openid.
	RequireOpenID bool
}

func (o *BrowserAuthorizationOptions) defaults() error {
	if o.CodeLifetime == 0 {
		o.CodeLifetime = 10 * time.Minute
	}
	if o.CodeLifetime < time.Second || o.CodeLifetime%time.Second != 0 {
		return errors.New("oauthprovider: code lifetime must be a positive whole number of seconds")
	}
	if o.SelectAccount.ShouldRedirect != nil && o.SelectAccount.Page == "" && o.LoginPage == "" {
		return errors.New("oauthprovider: account selection requires a selection or login page")
	}
	if o.PostLogin != nil && (o.PostLogin.Page == "" || o.PostLogin.ShouldRedirect == nil) {
		return errors.New("oauthprovider: post-login requires both a page and a selection policy")
	}
	o.RateLimit = tokenRouteLimit(o.RateLimit, 30)
	return nil
}

// BrowserClient contains the registration fields used to approve browser requests.
// RowID distinguishes a deleted registration from one that reuses its public ID.
type BrowserClient struct {
	RowID, ClientID, ApplicationType, AuthMethod string
	RedirectURIs, GrantTypes, Scopes             []string
	RequirePKCE                                  *bool
	Disabled, SkipConsent, RequireDPoP           bool
}

// BrowserCodeIssue carries validated public parameters and the verified browser
// owner. The store rechecks the session and consent in the transaction that
// writes the code. Identifier is a storage key, never the public credential.
type BrowserCodeIssue struct {
	Client                                                   BrowserClient
	UserID, SessionID, SessionToken, ReferenceID, Identifier string
	Query                                                    map[string]string
	Scopes                                                   []string
	RequestedUserInfoClaims                                  []string
	MaxAge                                                   *int64
	Lifetime                                                 time.Duration
}

func (i BrowserCodeIssue) SessionFresh(created, now time.Time) bool {
	if i.MaxAge == nil {
		return true
	}
	elapsed := now.UnixMilli() - created.UnixMilli()
	return *i.MaxAge > 0 && (elapsed <= 0 || (elapsed-1)/1000 < *i.MaxAge)
}

func (i BrowserCodeIssue) VerificationValue(created time.Time) ([]byte, error) {
	query := maps.Clone(i.Query)
	if query == nil {
		return nil, errors.New("oauthprovider: missing authorization query")
	}
	query["response_type"], query["client_id"], query["scope"] = "code", i.Client.ClientID, strings.Join(i.Scopes, " ")
	value := map[string]any{"type": "authorization_code", "query": query, "userId": i.UserID, "sessionId": i.SessionID, "authTime": created.UnixMilli(), "resource": []string{}}
	if i.ReferenceID != "" {
		value["referenceId"] = i.ReferenceID
	}
	return json.Marshal(value)
}

var (
	ErrBrowserConsentRequired = errors.New("oauthprovider: browser consent required")
	ErrBrowserClientChanged   = errors.New("oauthprovider: browser client registration changed")
)

type BrowserAuthorizationStore interface {
	LookupAuthorizationClient(context.Context, string) (BrowserClient, error)
	// IssueBrowserCode must reject a changed client, inactive owner session,
	// missing approval or a duplicate identifier without replacing an existing
	// code. A store that implements AuthorizationCodeGater asks the request's
	// gate before storing the code.
	IssueBrowserCode(context.Context, BrowserCodeIssue) error
}

func (opts Options) browserAuthorize(c auth.EndpointContext) (any, error) {
	q, err := url.ParseQuery(c.Request.URL.RawQuery)
	if c.Request.Method == http.MethodPost {
		q, err = readTokenForm(c.Request)
	}
	if err != nil {
		if c.Request.Method == http.MethodPost {
			return nil, err
		}
		q = nil
	}
	return opts.runBrowserAuthorization(c, q, nil)
}

func (opts Options) runBrowserAuthorization(c auth.EndpointContext, q url.Values, decision *browserConsentDecision) (any, error) {
	serverError := func(code, description string) (any, error) {
		if decision != nil && !decision.accept {
			code, description = "access_denied", "User denied access"
		}
		page, err := c.ErrorPageURL()
		if err != nil {
			return nil, err
		}
		return browserRedirect(c, page, url.Values{"error": {code}, "error_description": {description}}, false), nil
	}
	// A pushed request is resolved first, as in another runtime: every
	// parameter but client_id comes from the stored request. Failures go to
	// the error page, where that runtime may use the URL's redirect_uri,
	// which is not part of the pushed request.
	if resolve := opts.Authorization.RequestURIResolver; resolve != nil && q.Has("request_uri") && !q.Has("request") {
		if len(q["client_id"]) != 1 || q.Get("client_id") == "" {
			return serverError("invalid_request", "client_id is required")
		}
		resolved, err := resolve(c.Request.Context(), q.Get("request_uri"), q.Get("client_id"))
		if err != nil {
			return nil, err
		}
		if resolved == nil {
			return serverError("invalid_request_uri", "request_uri is invalid or expired")
		}
		next := url.Values{}
		for k, v := range resolved {
			if k != "request" && k != "request_uri" {
				next[k] = slices.Clone(v)
			}
		}
		next.Set("client_id", q.Get("client_id"))
		q = next
	}
	selection := opts.Authorization.SelectAccount
	if selection.Page == "" && slices.Contains(promptValues(q.Get("prompt")), "select_account") {
		return serverError("unsupported_prompt_select_account", "unsupported prompt type")
	}
	store, ok := c.Store().(BrowserAuthorizationStore)
	if !ok {
		return nil, &auth.APIError{Status: 501, Code: "OAUTH_AUTHORIZE_STORE_UNAVAILABLE", Message: "The configured store does not support browser authorization"}
	}
	if len(q["client_id"]) != 1 || q.Get("client_id") == "" {
		return serverError("invalid_request", "client_id is required")
	}
	if len(q["redirect_uri"]) != 1 {
		return serverError("invalid_redirect", "invalid redirect uri")
	}
	ctx := c.Request.Context()
	client, err := store.LookupAuthorizationClient(ctx, q.Get("client_id"))
	if errors.Is(err, ErrClientNotFound) {
		return serverError("invalid_client", "client not found")
	}
	if err != nil {
		return nil, err
	}
	continued, _ := ctx.Value(continuedClientKey{}).(browserContinuation)
	if continued.client != "" && continued.client != tokenDigest(client.RowID) {
		return serverError("invalid_client", "client registration changed")
	}
	if client.Disabled {
		return serverError("client_disabled", "client is disabled")
	}
	if len(client.GrantTypes) > 0 && !slices.Contains(client.GrantTypes, "authorization_code") {
		return serverError("unauthorized_client", "client is not authorized to use the authorization_code grant")
	}
	// As in another runtime, only the HTTPS policy is checked here; the
	// registered match, or the host's ValidateRedirectURI for a callback
	// whose syntax is safe, decides the rest and fails closed.
	callback := q.Get("redirect_uri")
	if callback != "" && !opts.Registration.redirectTransportAllowed(callback, client.ApplicationType == "web") {
		return serverError("invalid_request", insecureRedirectMessage)
	}
	match := callback != "" && client.matchesCallback(callback)
	if validate := opts.Authorization.ValidateRedirectURI; validate != nil {
		match = false
		if _, unsafe := redirectURL(callback); unsafe == nil {
			match, err = validate(ctx, callback, slices.Clone(client.RedirectURIs), client.matchesCallback(callback))
		}
	}
	if !match || err != nil {
		return serverError("invalid_redirect", "invalid redirect uri")
	}
	state := ""
	if len(q["state"]) == 1 {
		state = q.Get("state")
	}
	result := func(values url.Values, fragment bool) (any, error) {
		if state != "" {
			values.Set("state", state)
		}
		values.Set("iss", c.Auth.OAuthIssuer())
		return browserRedirect(c, callback, values, fragment), nil
	}
	reject := func(code, description string) (any, error) {
		return result(url.Values{"error": {code}, "error_description": {description}}, browserFragmentError(q))
	}
	if decision != nil && !decision.accept {
		current, err := store.LookupAuthorizationClient(ctx, client.ClientID)
		if err != nil && !errors.Is(err, ErrClientNotFound) {
			return nil, err
		}
		if err != nil || !reflect.DeepEqual(current, client) || tokenDigest(client.RowID) != decision.clientFingerprint {
			return serverError("access_denied", "User denied access")
		}
		return reject("access_denied", "User denied access")
	}
	grant, problem := opts.browserGrant(client, q)
	if problem != nil {
		return reject(problem.Code, problem.Description)
	}
	issue := grant.BrowserCodeIssue
	if slices.Contains(issue.Scopes, "openid") && !canIssueIDToken(c) {
		return reject("invalid_request", "ID token issuance is unavailable")
	}
	var session *auth.SessionResult
	if decision != nil {
		session = decision.session
	} else {
		session, err = c.Auth.GetSession(ctx, c.Request.Header)
		if err != nil {
			return nil, err
		}
	}
	if session == nil || session.Session.RequireOwner() != nil || !c.DirectBrowserSession(session.Session.Token) || !issue.SessionFresh(session.Session.CreatedAt, time.Now()) || slices.Contains(grant.prompts, "login") || slices.Contains(grant.prompts, "create") {
		if decision == nil && !slices.Contains(grant.prompts, "none") {
			if page := opts.loginPage(grant.prompts); page != "" {
				return opts.openAccountPage(c, page, "pa_login", q, issue)
			}
		}
		return reject("login_required", "authentication required")
	}
	// A real login or a choice on the host page has already selected the
	// current browser account. Only an initial request may open the chooser.
	if decision == nil && continued.client == "" {
		choose := slices.Contains(grant.prompts, "select_account")
		if !choose && selection.ShouldRedirect != nil {
			choose, err = selection.ShouldRedirect(ctx, RegistrationAccess{SessionResult: *session, Headers: c.Request.Header.Clone()}, slices.Clone(issue.Scopes))
			if err != nil {
				return nil, err
			}
		}
		if choose {
			if slices.Contains(grant.prompts, "none") {
				return reject("account_selection_required", "End-User account selection is required")
			}
			page := selection.Page
			if page == "" {
				page = opts.Authorization.LoginPage
			}
			return opts.openAccountPage(c, page, "pa_select", q, issue)
		}
	}
	issue.UserID, issue.SessionID, issue.SessionToken = session.User.ID, session.Session.ID, session.Session.Token
	if decision != nil {
		if decision.scopes != nil {
			issue.Scopes = decision.scopes
			if !slices.Contains(issue.Scopes, "openid") {
				delete(issue.Query, "claims")
				issue.RequestedUserInfoClaims = nil
			}
		}
		remaining := slices.DeleteFunc(slices.Clone(grant.prompts), func(p string) bool { return p == "consent" })
		if len(remaining) == 0 {
			delete(issue.Query, "prompt")
		} else {
			issue.Query["prompt"] = strings.Join(remaining, " ")
		}
	}
	// A consent page attests to post-login clearance for its own session.
	// Signup still runs, including when the browser has already given consent.
	cleared := continued.clearedSession != "" && continued.clearedSession == session.Session.ID
	if decision != nil {
		cleared = decision.clearedSession != "" && decision.clearedSession == session.Session.ID
	}
	step, err := opts.Authorization.requiredAccountStep(c, *session, issue.Scopes, continued.postLogin, cleared)
	if err != nil {
		return nil, err
	}
	var deferredRedirect any
	if step != nil {
		if slices.Contains(grant.prompts, "none") {
			return reject("interaction_required", "End-User interaction is required")
		}
		if step.page == "" {
			return nil, errors.New("oauthprovider: required account step has no page")
		}
		// A different login starts a new approval for its selected account.
		// It cannot consume the original browser's consent or drop its prompt.
		newSession := decision != nil && step.marker == "pa_post" && decision.clearedSession != "" && !cleared
		if newSession {
			if decision.clientFingerprint != tokenDigest(client.RowID) {
				return serverError("invalid_client", "client registration changed")
			}
			issue.Query["prompt"] = "consent"
		}
		deferredRedirect, err = opts.openAccountPage(c, step.page, step.marker, q, issue)
		if err != nil || decision == nil || newSession {
			return deferredRedirect, err
		}
	}
	if resolve := opts.Authorization.ConsentReference; resolve != nil {
		issue.ReferenceID, err = resolve(ctx, RegistrationAccess{SessionResult: *session, Headers: c.Request.Header.Clone()}, slices.Clone(issue.Scopes))
		if err != nil {
			return nil, err
		}
	}
	// A signed clearance used at /continue can only resume in its original
	// approval namespace. A consent submission checks this binding in storage.
	if cleared && continued.clearedSession != "" && continued.binding != consentBinding(c.Auth.OAuthIssuer(), continued.client, issue) {
		return nil, registrationProblem(400, "invalid_request", "post-login approval context changed")
	}
	consentPage := func() (any, error) {
		if opts.Authorization.ConsentPage == "" || slices.Contains(grant.prompts, "none") {
			return reject("consent_required", "End-User consent is required")
		}
		return opts.openConsentPage(c, q, issue)
	}
	if decision == nil && slices.Contains(grant.prompts, "consent") {
		return consentPage()
	}
	if decision != nil {
		decision.request.Binding = consentBinding(c.Auth.OAuthIssuer(), tokenDigest(client.RowID), issue)
	}
	var code string
	if deferredRedirect != nil {
		err = decision.store.(DeferredConsentStore).ApproveBrowserConsent(ctx, issue, decision.request)
	} else {
		code, err = randomCredential("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
		if err != nil {
			return nil, err
		}
		issue.Identifier, err = opts.Tokens.storedAuthorizationCode(ctx, code)
		if err != nil {
			return nil, err
		}
		// The store asks the request's gate before storing the code, so its
		// verification hooks run outside the store's transaction.
		if decision != nil {
			err = c.GateVerifications(func(ctx context.Context) error {
				return decision.store.FinishBrowserConsent(ctx, issue, decision.request, true)
			})
		} else {
			err = c.GateVerifications(func(ctx context.Context) error { return store.IssueBrowserCode(ctx, issue) })
		}
	}
	switch {
	case errors.Is(err, ErrClientNotFound), errors.Is(err, ErrBrowserClientChanged):
		return serverError("invalid_client", "client registration changed")
	case errors.Is(err, ErrAuthorizationSessionExpired):
		return reject("login_required", "authentication required")
	case errors.Is(err, ErrBrowserConsentRequired) && decision == nil:
		return consentPage()
	case errors.Is(err, ErrBrowserConsentExpired):
		return nil, consentDecisionError(err)
	case err != nil:
		return nil, err
	}
	if deferredRedirect != nil {
		return deferredRedirect, nil
	}
	return result(url.Values{"code": {code}}, false)
}

func browserRedirect(c auth.EndpointContext, target string, values url.Values, fragment bool) any {
	// target is a validated registered URI or the host's configured public
	// URL. Building on its own spelling keeps the "//" of a deep link such
	// as myapp://, which url.URL.String drops for an empty host.
	if fragment {
		base, _, _ := strings.Cut(target, "#")
		return c.RegisteredOAuthRedirect(base + "#" + values.Encode())
	}
	set := url.Values{}
	for k := range values {
		set.Set(k, values.Get(k))
	}
	return c.RegisteredOAuthRedirect(httporigin.SetQuery(target, set))
}
