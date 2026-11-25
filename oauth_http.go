package plainauth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Plain-Org/plain-auth/internal/httporigin"
	"golang.org/x/oauth2"
)

func (a *Auth) serveOAuth(w http.ResponseWriter, r *http.Request, route string) bool {
	if a.oauthProxy != nil && a.serveOAuthProxyCompletion(w, r, route) {
		return true
	}
	link := route == "/link-social"
	start := route == "/sign-in/social" || link
	id, callback := strings.CutPrefix(route, "/callback/")
	if !start && (!callback || !providerName.MatchString(id)) {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if (start && r.Method != http.MethodPost) || (!start && r.Method != http.MethodGet && r.Method != http.MethodPost) {
		w.WriteHeader(http.StatusNotFound)
		return true
	}
	if a.rejectRateLimited(w, r, route) {
		return true
	}
	path := route
	var body wireBody
	if start {
		err := a.validateRequestOrigin(r, true)
		if err == nil {
			body, err = decodeWireBody(w, r, "/sign-in/social")
		}
		if err == nil {
			err = a.validateCallbacks(r.Context(), body, nil)
		}
		if err != nil {
			a.writeAuthError(w, r, err)
			return true
		}
	} else {
		path = "/callback/:id"
	}
	result, err := a.callEndpoint(w, r, path, route, body, func(r *http.Request, body wireBody) (any, error) {
		if start {
			return a.startOAuth(w, r, body, link)
		}
		if r.Method == http.MethodPost {
			return a.redirectOAuthForm(w, r, id)
		}
		return a.finishOAuth(w, r, id)
	})
	a.writeOutcome(w, r, 0, result, err)
	return true
}

func (a *Auth) providerConfig(ctx context.Context, id string) (OAuthProvider, error) {
	p, ok := a.opts.SocialProviders[id]
	if !ok {
		return p, &APIError{404, "PROVIDER_NOT_FOUND", "Provider not found"}
	}
	// The provider's own redirect URL wins over the callback route, which is
	// on the request's own host with DynamicBaseURL.
	if p.Config.RedirectURL == "" {
		base, err := a.publicURL(ctx)
		if err != nil {
			return p, err
		}
		p.Config.RedirectURL = base + "/callback/" + id
	}
	return p, nil
}

func (a *Auth) oauthBinding(browser, id string, r *http.Request) string {
	return digest(browser + "\x00" + id + "\x00" + a.cookieToken(r.Header))
}

func (a *Auth) startOAuth(w http.ResponseWriter, r *http.Request, body wireBody, link bool) (any, error) {
	id, ok := body["provider"].(string)
	if !ok {
		return nil, fieldTypeError("provider", "string", body)
	}
	p, err := a.providerConfig(r.Context(), id)
	if err != nil {
		return nil, err
	}
	disable := false
	if value, found := body["disableRedirect"]; found {
		disable, ok = value.(bool)
		if !ok {
			return nil, fieldTypeError("disableRedirect", "boolean", body)
		}
	}
	requestedParams, err := authorizationOptions(body, p.Config.Scopes)
	if err != nil {
		return nil, err
	}
	requestSignUp, ok := body["requestSignUp"].(bool)
	if _, present := body["requestSignUp"]; present && !ok {
		return nil, fieldTypeError("requestSignUp", "boolean", body)
	}
	linkUserID := ""
	var resume OAuthLoginContinuation
	if link {
		current, err := a.requireOwnerSession(r.Context(), r.Header)
		if err != nil {
			return nil, err
		}
		linkUserID = current.User.ID
	} else {
		resume, err = a.loginContinuation("/sign-in/social", r, body, w.Header())
		if err != nil {
			return nil, err
		}
	}
	if value, found := body["idToken"]; found {
		callback, _ := body["callbackURL"].(string)
		return a.directOAuth(w, r, id, p, value, linkUserID, requestSignUp, callback, resume)
	}
	flow := OAuthFlow{Provider: id, LinkUserID: linkUserID, RequestSignUp: requestSignUp}
	if resume != nil {
		flow.IssuerLoginQuery, _ = body["oauth_query"].(string)
	}
	target, _, err := a.beginBrowserOAuth(w.Header(), r, p, body, flow, requestedParams)
	if err != nil {
		return nil, err
	}
	if !disable {
		w.Header().Set("Location", target)
	}
	return map[string]any{"url": target, "redirect": !disable}, nil
}

// beginBrowserOAuth creates the same provider-bound grant for redirect and
// popup sign-in. The database strategy makes it single-use.
func (a *Auth) beginBrowserOAuth(h http.Header, r *http.Request, p OAuthProvider, body wireBody, flow OAuthFlow, requestedParams []oauth2.AuthCodeOption) (string, string, error) {
	browser := randomID()
	now := a.now().UTC()
	id := flow.Provider
	flow.State, flow.Binding = randomID(), a.oauthBinding(browser, id, r)
	flow.Verifier, flow.Nonce, flow.ExpiresAt = oauth2.GenerateVerifier(), randomID(), now.Add(10*time.Minute)
	if a.anonymous != nil && flow.LinkUserID == "" {
		guest, err := a.guestToken(r)
		if err != nil {
			return "", "", err
		}
		if guest != "" {
			browser = "guest-" + browser
			flow.Binding = digest(browser + "\x00" + id + "\x00")
			flow.AnonymousSessionProof, err = a.sealRecord("guest-oauth:"+flow.State, []byte(guest))
			if err != nil {
				return "", "", err
			}
		}
	}
	flow.CallbackURL, _ = body["callbackURL"].(string)
	flow.ErrorCallbackURL, _ = body["errorCallbackURL"].(string)
	flow.NewUserCallbackURL, _ = body["newUserCallbackURL"].(string)
	if flow.CallbackURL == "" {
		origin, err := a.origin(r.Context())
		if err != nil {
			return "", "", err
		}
		flow.CallbackURL = origin
	}
	var opts []oauth2.AuthCodeOption
	if !p.OmitNonce {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", flow.Nonce))
	}
	if !p.DisablePKCE {
		opts = append(opts, oauth2.S256ChallengeOption(flow.Verifier))
	}
	for key, values := range p.AuthorizationParams {
		if len(values) > 0 {
			opts = append(opts, oauth2.SetAuthURLParam(key, values[0]))
		}
	}
	opts = append(opts, requestedParams...)
	providerState := flow.State
	if a.oauthProxy != nil {
		current := a.proxyCurrentOrigin(r)
		if current != a.oauthProxy.ProductionURL && r.Header.Get("X-Skip-OAuth-Proxy") == "" {
			if current == "" {
				return "", "", validationError("OAuth proxy requires a secure preview origin")
			}
			flow.ProxyOrigin = current
			if a.opts.SocialProviders[id].Config.RedirectURL == "" {
				p.Config.RedirectURL = a.oauthProxy.ProductionURL + a.opts.BasePath + "/callback/" + id
			}
			var err error
			providerState, err = a.packProxyState(flow)
			if err != nil {
				return "", "", err
			}
		}
	}
	if a.dynamic != nil && flow.ProxyOrigin == "" {
		// The callback must return to the host the sign-in started on.
		flow.RedirectURI = p.Config.RedirectURL
	}
	target := p.Config.AuthCodeURL(providerState, opts...)
	if p.CustomizeAuthorization != nil {
		u, err := url.Parse(target)
		if err != nil {
			return "", "", err
		}
		p.CustomizeAuthorization(u)
		target = u.String()
	}
	if err := a.keepOAuthFlow(r.Context(), h, "oauth_state", a.oauthCookie("oauth_state", "", 600), browser, flow, now); err != nil {
		return "", "", err
	}
	return target, flow.State, nil
}

func (a *Auth) finishOAuth(w http.ResponseWriter, r *http.Request, id string) (any, error) {
	p, err := a.providerConfig(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if a.oauthProxy != nil && strings.HasPrefix(r.URL.Query().Get("state"), recordPrefix) {
		return a.exchangeProxyCallback(w, r, id, p)
	}
	// The configured origin is the only destination sent in the code
	// exchange. With DynamicBaseURL the flow's stored redirect URL is checked
	// instead, since the Host header is not the public host behind a proxy.
	if base, _ := url.Parse(a.opts.BaseURL); a.dynamic == nil && httporigin.Canonical(&url.URL{Scheme: base.Scheme, Host: r.Host}) != httporigin.Canonical(base) {
		return nil, &APIError{400, "INVALID_CALLBACK_URL", "Invalid OAuth callback"}
	}
	q := r.URL.Query()
	state := q.Get("state")
	return a.finishBrowserOAuth(w, r, id, p, state, q, nil)
}

func (a *Auth) finishBrowserOAuth(w http.ResponseWriter, r *http.Request, id string, p OAuthProvider, state string, q url.Values, returned *oauthProxyResult) (out any, resultErr error) {
	if returned == nil && (len(q["state"]) > 1 || len(q["code"]) > 1 || len(q["error"]) > 1) {
		return nil, validationError("Duplicate OAuth callback field")
	}
	var popup *popupOpener
	if state != "" && len(state) <= 128 {
		popup = a.callbackPopup(w.Header(), r, state)
	}
	if popup != nil {
		defer func() {
			if resultErr != nil {
				out, resultErr = popup.page(w.Header(), "", "", &popupError{Code: "popup_sign_in_failed", Description: "Unable to complete social sign-in"}), nil
			}
		}()
	}
	// A state the callback cannot use goes to the configured error page with
	// its code. Nothing from the request or an unverified flow chooses the
	// destination.
	rejectState := func(code string) (any, error) {
		if returned != nil {
			code = "state_mismatch"
		}
		if popup != nil {
			return popup.page(w.Header(), "", "", &popupError{Code: code}), nil
		}
		if returned != nil {
			return nil, proxyBrowserError(code)
		}
		target, err := a.errorPageURL(r.Context())
		if err != nil {
			return nil, err
		}
		return Redirect(httporigin.SetQuery(target, url.Values{"error": {code}})), nil
	}
	if state == "" {
		return rejectState("state_not_found")
	}
	cookie, err := r.Cookie(a.oauthCookie("oauth_state", "", 0).Name)
	if err != nil || len(state) > 128 {
		return rejectState("state_mismatch")
	}
	binding := func(browser string) string {
		if strings.HasPrefix(browser, "guest-") {
			return digest(browser + "\x00" + id + "\x00")
		}
		return a.oauthBinding(browser, id, r)
	}
	flow, err := a.takeOAuthFlow(r.Context(), "oauth_state", cookie.Value, state, binding, a.now().UTC())
	var failure *stateFailure
	if errors.As(err, &failure) {
		return rejectState(failure.code)
	}
	if err != nil {
		return nil, err
	}
	http.SetCookie(w, a.oauthCookie("oauth_state", "", -1))
	if flow.RedirectURI != "" && flow.RedirectURI != p.Config.RedirectURL {
		return nil, &APIError{400, "INVALID_CALLBACK_URL", "Invalid OAuth callback"}
	}
	failWithDescription := func(code, description string) (any, error) {
		if popup != nil {
			return popup.page(w.Header(), "", "", &popupError{Code: code, Description: description}), nil
		}
		if flow.ErrorCallbackURL != "" && a.trustedURL(r.Context(), flow.ErrorCallbackURL, true) {
			set := url.Values{"error": {code}}
			if description != "" {
				set.Set("error_description", description)
			}
			return Redirect(httporigin.SetQuery(flow.ErrorCallbackURL, set)), nil
		}
		return nil, &APIError{400, code, "Unable to complete social sign-in"}
	}
	fail := func(code string) (any, error) { return failWithDescription(code, "") }
	// A verified flow whose browser state no longer fits it is a mismatch,
	// sent to its error callback or the error page.
	mismatch := func() (any, error) {
		if flow.ErrorCallbackURL == "" {
			if returned != nil {
				flow.ErrorCallbackURL = strings.TrimRight(a.opts.BasePath, "/") + "/error"
			} else {
				flow.ErrorCallbackURL, _ = a.errorPageURL(r.Context())
			}
		}
		return fail("state_mismatch")
	}
	if (returned == nil && flow.ProxyOrigin != "") || (returned != nil && (flow.ProxyOrigin != returned.Preview || flow.CallbackURL != returned.Callback)) {
		return mismatch()
	}
	if flow.AnonymousSessionProof != "" {
		guest, err := a.openRecord("guest-oauth:"+flow.State, flow.AnonymousSessionProof)
		current := a.cookieToken(r.Header)
		if err != nil || a.anonymous == nil || current != "" && current != string(guest) {
			return mismatch()
		}
		r = r.WithContext(context.WithValue(r.Context(), anonymousSourceKey{}, string(guest)))
	}
	if popup != nil && flow.Provider == id && q.Get("error") != "" {
		return popup.page(w.Header(), "", "", &popupError{Code: q.Get("error"), Description: q.Get("error_description")}), nil
	}
	if flow.Provider != id || (returned == nil && (q.Get("error") != "" || q.Get("code") == "")) {
		return fail("OAUTH_CALLBACK_ERROR")
	}
	var resume OAuthLoginContinuation
	if flow.IssuerLoginQuery != "" {
		resume, err = a.loginContinuation("/sign-in/social", r, wireBody{"oauth_query": flow.IssuerLoginQuery}, w.Header())
		if err != nil {
			return nil, err
		}
		if resume == nil || flow.LinkUserID != "" || popup != nil {
			return nil, &OAuthError{Status: 400, Code: "invalid_request", Description: "issuer login is unavailable"}
		}
	}
	ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), oauth2.HTTPClient, p.HTTPClient), 30*time.Second)
	defer cancel()
	if flow.PopupAdditionalData != nil {
		ctx = context.WithValue(ctx, popupDataKey{}, flow.PopupAdditionalData)
	}
	var profile OAuthProfile
	var tokens OAuthTokens
	var accountFields *MappedAccountFields
	disableSignUp := p.DisableImplicitSignUp && !flow.RequestSignUp
	if returned != nil && flow.ErrorCallbackURL == "" {
		flow.ErrorCallbackURL = a.opts.BasePath + "/error"
	}
	if returned == nil {
		grant, failure := a.exchangeProviderCode(ctx, p, flow, q)
		if failure != "" {
			return fail(failure)
		}
		profile, tokens = grant.Profile, grant.Tokens
		var fieldErr *APIError
		accountFields, fieldErr = a.mapAccountFields(ctx, p, grant)
		if fieldErr != nil {
			if flow.ErrorCallbackURL == "" {
				flow.ErrorCallbackURL, _ = a.errorPageURL(ctx)
			}
			return failWithDescription(fieldErr.Code, fieldErr.Message)
		}
	} else {
		if returned.Error != "" {
			return fail(returned.Error)
		}
		profile, tokens = returned.Profile, returned.Tokens
		profile.AdditionalFields = returned.Fields
		if returned.ProfileData != nil {
			profile.Data = returned.ProfileData
		} else if returned.GoogleHostedDomain != "" {
			profile.Data = map[string]any{"hd": returned.GoogleHostedDomain}
		}
		if !validSocialProfile(profile) {
			return fail("OAUTH_PROFILE_INVALID")
		}
		disableSignUp = disableSignUp || returned.DisableSignUp
		p.RequireEmailVerification = p.RequireEmailVerification || returned.RequireEmailVerification
	}
	result, created, err := a.completeProfile(ctx, r, id, flow.CallbackURL, profile, tokens, OAuthLoginOptions{AccountFields: accountFields, DisableSignUp: disableSignUp, RequireEmailVerification: p.RequireEmailVerification, AllowVerifiedEmailLink: p.AllowVerifiedEmailLink, LinkUserID: flow.LinkUserID, LinkSessionToken: a.cookieToken(r.Header)})
	// A refusal by ValidateUserInfo comes first, so no other mapping can
	// rewrite the application's code.
	var refused *userInfoRejection
	if errors.As(err, &refused) {
		if flow.ErrorCallbackURL == "" {
			flow.ErrorCallbackURL, _ = a.errorPageURL(ctx)
		}
		return failWithDescription(refused.Code, refused.Message)
	}
	var apiError *APIError
	if errors.As(err, &apiError) && apiError.Code == "EMAIL_NOT_VERIFIED" {
		if flow.ErrorCallbackURL == "" {
			flow.ErrorCallbackURL, _ = a.errorPageURL(ctx)
		}
		return fail("email_not_verified")
	}
	if errors.As(err, &apiError) && apiError.Code == "SIGN_UP_DISABLED" {
		if flow.ErrorCallbackURL == "" {
			flow.ErrorCallbackURL, _ = a.errorPageURL(ctx)
		}
		return fail("signup_disabled")
	}
	var fieldError oauthProfileFieldError
	if errors.As(err, &apiError) && (errors.As(err, &fieldError) || apiError.Code == "MISSING_FIELD" || apiError.Code == "VALIDATION_ERROR") {
		if flow.ErrorCallbackURL == "" {
			flow.ErrorCallbackURL, _ = a.errorPageURL(ctx)
		}
		return failWithDescription(apiError.Code, apiError.Message)
	}
	linkFailed := errors.Is(err, ErrOAuthLinkingDisabled) || errors.Is(err, ErrOAuthLinkNotAllowed) || (flow.LinkUserID != "" && errors.Is(err, ErrNotFound))
	if (linkFailed || errors.Is(err, ErrOAuthLinkEmailMismatch) || errors.Is(err, ErrOAuthAccountAlreadyLinked)) && flow.ErrorCallbackURL == "" {
		flow.ErrorCallbackURL, _ = a.errorPageURL(ctx)
	}
	if linkFailed {
		return fail("unable_to_link_account")
	}
	if errors.Is(err, ErrOAuthLinkEmailMismatch) {
		return fail("email_does_not_match")
	}
	if errors.Is(err, ErrOAuthAccountAlreadyLinked) {
		return fail("account_already_linked_to_different_user")
	}
	if errors.As(err, &apiError) && apiError.Code == "OAUTH_PROFILE_CONFLICT" {
		return fail("profile_conflict")
	}
	if errors.Is(err, ErrOAuthLinkRequired) || errors.Is(err, ErrNotFound) {
		return fail("account_not_linked")
	}
	if errors.Is(err, errPlannedUserSkipped) {
		return fail("unable_to_create_user")
	}
	if errors.Is(err, errPlannedSessionSkipped) {
		return fail("unable_to_create_session")
	}
	if err != nil {
		return nil, err
	}
	if flow.LinkUserID == "" {
		out, err := a.publishSocialLogin(w, r, result.Token, resume)
		if err == nil {
			a.setAccountCookie(w.Header(), r, result.User.ID, id, profile.Subject)
		}
		if out != nil || err != nil {
			return out, err
		}
	}
	target := flow.CallbackURL
	if created && flow.NewUserCallbackURL != "" {
		target = flow.NewUserCallbackURL
	}
	if !a.trustedURL(r.Context(), target, true) {
		target, _ = a.origin(r.Context())
	}
	if popup != nil && flow.LinkUserID == "" {
		return popup.page(w.Header(), a.sessionCookie(result.Token, true).Value, target, nil), nil
	}
	return Redirect(target), nil
}

func (a *Auth) exchangeProviderCode(ctx context.Context, p OAuthProvider, flow OAuthFlow, q url.Values) (OAuthAccountFieldInput, string) {
	var params []oauth2.AuthCodeOption
	if !p.DisablePKCE {
		params = append(params, oauth2.VerifierOption(flow.Verifier))
	}
	var err error
	var token *oauth2.Token
	if p.ExchangeCode == nil {
		token, err = p.Config.Exchange(ctx, q.Get("code"), params...)
	} else {
		token, err = p.ExchangeCode(ctx, p.Config, q.Get("code"), flow.Verifier, q)
	}
	if err != nil || token == nil {
		return OAuthAccountFieldInput{}, "OAUTH_TOKEN_EXCHANGE_FAILED"
	}
	profile, err := p.Resolve(ctx, token, flow.Nonce)
	if err != nil || !validSocialProfile(profile) {
		return OAuthAccountFieldInput{}, "OAUTH_PROFILE_INVALID"
	}
	if p.FormPostName && q.Get("user") != "" {
		var newUser struct {
			Name struct{ FirstName, LastName string }
		}
		if json.Unmarshal([]byte(q.Get("user")), &newUser) == nil {
			if name := strings.TrimSpace(newUser.Name.FirstName + " " + newUser.Name.LastName); name != "" {
				profile.Name = name
			}
		}
	}
	idToken, _ := token.Extra("id_token").(string)
	var scopes []string
	switch v := token.Extra("scope").(type) {
	case string:
		scopes = strings.Fields(v)
	case []any:
		for _, value := range v {
			if field, ok := value.(string); ok && strings.TrimSpace(field) != "" {
				scopes = append(scopes, strings.TrimSpace(field))
			}
		}
	}
	scope := strings.Join(scopes, ",")
	tokens := OAuthTokens{AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, IDToken: idToken, Scope: scope, ExpiresAt: token.Expiry}
	if lifetime := refreshLifetime(token); lifetime > 0 {
		tokens.RefreshExpiresAt = a.now().Add(lifetime)
	}
	return OAuthAccountFieldInput{Profile: profile, Tokens: tokens, ExchangedToken: token}, ""
}

func validSocialProfile(p OAuthProfile) bool {
	return p.Subject != "" && len(p.Subject) <= 1024 && len(p.Email) <= 254 && emailPattern.MatchString(p.Email) && !strings.Contains(p.Email, "..")
}

// A cross-site form POST does not carry SameSite=Lax cookies. Redirect to the
// fixed callback origin for a top-level GET, then consume the bound state.
func (a *Auth) redirectOAuthForm(w http.ResponseWriter, r *http.Request, id string) (any, error) {
	p, err := a.providerConfig(r.Context(), id)
	if err != nil {
		return nil, err
	}
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if media != "application/x-www-form-urlencoded" {
		return nil, &APIError{415, "UNSUPPORTED_MEDIA_TYPE", "Expected a form-encoded callback"}
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		return nil, validationError("Invalid OAuth callback form")
	}
	fields, err := url.ParseQuery(string(data))
	if err != nil {
		return nil, validationError("Invalid OAuth callback form")
	}
	q := url.Values{}
	for _, key := range []string{"state", "code", "error", "error_description", "user", "iss", "device_id"} {
		values := fields[key]
		if len(values) > 1 {
			return nil, validationError("Duplicate OAuth callback field")
		}
		if len(values) == 1 {
			q.Set(key, values[0])
		}
	}
	// The GET callback answers a missing state with state_not_found.
	return Redirect(p.Config.RedirectURL + "?" + q.Encode()), nil
}

func (a *Auth) completeProfile(ctx context.Context, r *http.Request, id, callback string, p OAuthProfile, tokens OAuthTokens, options OAuthLoginOptions) (AuthResult, bool, error) {
	complete := a.opts.Store.(OAuthIdentityStore).CompleteOAuth
	provider, registered := a.opts.SocialProviders[id]
	if options.LinkUserID == "" {
		options.RequireEmailVerification = options.RequireEmailVerification || provider.RequireEmailVerification
		signupFields := registered && len(a.opts.UserAdditionalFields) > 0 && !options.DisableSignUp && !a.opts.DisableSignUp && !provider.DisableSignUp
		if options.RequireEmailVerification || provider.OverrideUserInfoOnSignIn || signupFields {
			var err error
			complete, err = a.socialProfileCompletion(p, provider.OverrideUserInfoOnSignIn, options.RequireEmailVerification)
			if err != nil {
				return AuthResult{}, false, err
			}
		}
	}
	if a.opts.DisableAccountLinking && options.LinkUserID != "" {
		store, ok := a.opts.Store.(OAuthLinkRefreshStore)
		if options.IDTokenValidUntil.IsZero() || !ok {
			return AuthResult{}, false, ErrOAuthLinkingDisabled
		}
		complete = store.RefreshOwnedOAuthLink
	}
	trusted, err := a.TrustedProviderIDs(r)
	if err != nil {
		return AuthResult{}, false, err
	}
	options.TrustedProvider = slices.Contains(trusted, id)
	options.AllowDifferentEmails = options.LinkUserID != "" && a.opts.AllowDifferentEmails
	result, created, err := a.completeProfileWith(ctx, r, "oauth", id, p, tokens, options, complete)
	blocked := errors.Is(err, ErrOAuthEmailUnverified)
	if (err == nil || blocked) && options.LinkUserID == "" && !result.User.EmailVerified && a.opts.SendVerificationEmail != nil {
		send := blocked && a.opts.SendVerificationOnSignIn
		if created {
			send = a.sendVerificationOnSignup(options.RequireEmailVerification)
		}
		if send {
			if link, err := a.emailProofLink(ctx, result.User, "", "", callback); err != nil {
				a.Logger().ErrorContext(ctx, "Could not deliver social sign-in verification email")
			} else {
				a.sendMailLink(ctx, "Could not deliver social sign-in verification email", link, a.opts.SendVerificationEmail)
			}
		}
	}
	if blocked {
		return AuthResult{}, created, &APIError{403, "EMAIL_NOT_VERIFIED", "Email not verified"}
	}
	return result, created, err
}

// completeProfileWith signs in with a provider identity. method names the
// provider kind for ValidateUserInfo: "oauth", "sso-oidc" or "sso-saml".
func (a *Auth) completeProfileWith(ctx context.Context, r *http.Request, method, id string, p OAuthProfile, tokens OAuthTokens, options OAuthLoginOptions, complete OAuthCompletion) (AuthResult, bool, error) {
	options.DisableAccountUpdateOnSignIn = a.opts.DisableAccountUpdateOnSignIn && options.LinkUserID == ""
	if a.opts.DisableImplicitAccountLinking || a.opts.DisableAccountLinking {
		options.DisableImplicitLinking = true
		options.AllowVerifiedEmailLink = false
	}
	// The store prepares the fields only when it links. A profile that fails
	// validation skips the copy and still links.
	if a.opts.UpdateUserInfoOnLink && (options.LinkUserID != "" || !options.DisableImplicitLinking) {
		options.UpdateUserInfoOnLink = true
		options.LinkUserFields = sync.OnceValues(func() (UserFieldValues, bool) {
			values, err := a.prepareUserFields(a.writableProfileFields(p), false, false)
			if err != nil {
				a.Logger().WarnContext(ctx, "Could not update user info on account link", "provider", id)
				return UserFieldValues{}, false
			}
			return values, true
		})
	}
	options.DisableSignUp = options.DisableSignUp || a.opts.DisableSignUp || a.opts.SocialProviders[id].DisableSignUp
	if id == "google" && !googleDomainAllowed(a.opts.SocialProviders[id].GoogleHostedDomain, p) {
		return AuthResult{}, false, &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	candidate := User{ID: randomID(), Name: p.Name, Email: strings.ToLower(p.Email), EmailVerified: p.EmailVerified, Image: p.Image, CreatedAt: now, UpdatedAt: now}
	session := a.oauthSessionDraft(candidate.ID, RequestMeta{IPAddress: a.clientIP(r), UserAgent: r.UserAgent()}, options.RequireEmailVerification)
	if !options.IDTokenValidUntil.IsZero() {
		options.IDTokenHash = sha256.Sum256([]byte(id + "\x00" + tokens.IDToken))
	}
	if a.opts.EncryptOAuthTokens {
		var err error
		tokens, err = a.transformOAuthTokens(id, p.Subject, tokens, true)
		if err != nil {
			return AuthResult{}, false, err
		}
	}
	var user User
	var created bool
	write := func(ctx context.Context) (err error) {
		user, created, err = complete(ctx, id, p.Subject, tokens, candidate, session, options)
		return err
	}
	gate := &signInGate{method: method, provider: id, profile: profileMap(p.Data), candidate: candidate, fields: profileMap(a.writableProfileFields(p))}
	var err error
	if options.LinkUserID != "" {
		// The gate runs only for a live linking session, as in the
		// reference. The store checks the session again under lock.
		if a.opts.ValidateUserInfo != nil {
			if stored, owner, serr := a.opts.Store.Session(ctx, options.LinkSessionToken); serr != nil || owner.ID != options.LinkUserID || !stored.ExpiresAt.After(a.now()) {
				if serr != nil && !errors.Is(serr, ErrNotFound) {
					return AuthResult{}, false, serr
				}
				return AuthResult{}, false, ErrNotFound
			}
		}
		linked := candidate
		linked.ID, linked.CreatedAt, linked.UpdatedAt = options.LinkUserID, time.Time{}, time.Time{}
		check := UserInfoValidation{Action: UserInfoLinkAccount, Method: gate.method, Provider: id, Profile: gate.profile, User: UserRecord{User: linked, Fields: gate.fields}, Request: r}
		if err = a.ValidateUserInfo(ctx, check); err == nil {
			err = write(ctx)
		}
	} else {
		err = a.planSignIn(ctx, gate, write)
		if errors.Is(err, errLoginNotPlanned) {
			// Issue no session for a sign-in the gate did not see.
			return AuthResult{}, false, a.discardUnpublishedSession(ctx, session.Token, err)
		}
	}
	if created && errors.Is(err, ErrOAuthEmailUnverified) {
		// The user is stored without a session until the address is verified.
		if hookErr := a.afterUserCreate(ctx, user, nil); hookErr != nil {
			return AuthResult{}, created, hookErr
		}
	}
	if err == nil && options.LinkUserID == "" {
		err = a.afterDecidedSignIn(ctx, user, created, session.Token)
	}
	if errors.Is(err, ErrOAuthProfileConflict) {
		return AuthResult{}, false, &APIError{409, "OAUTH_PROFILE_CONFLICT", "Provider profile conflicts with an existing profile"}
	}
	if errors.Is(err, ErrOAuthSignupDisabled) {
		return AuthResult{}, false, &APIError{403, "SIGN_UP_DISABLED", "Sign-up is disabled"}
	}
	if err != nil {
		return AuthResult{User: user}, created, err
	}
	err = a.readPublicUserFields(ctx, &user)
	return AuthResult{User: user, Token: session.Token}, created, err
}

// publishSocialLogin issues the session cookie. With a login continuation it
// returns the authorization request to dispatch in place of the usual result.
func (a *Auth) publishSocialLogin(w http.ResponseWriter, r *http.Request, token string, resume OAuthLoginContinuation) (any, error) {
	prior := len(w.Header().Values("Set-Cookie"))
	if err := a.setSessionCookie(w, r, token, true); err != nil {
		return nil, a.discardUnpublishedSession(r.Context(), token, err)
	}
	if resume == nil {
		return nil, nil
	}
	next, err := a.resumeIssuedOAuthLogin(w, r, resume, prior)
	if err != nil {
		return nil, err
	}
	if next == nil {
		return nil, &OAuthError{Status: 401, Code: "unauthorized", Description: "a new browser session is required"}
	}
	return oauthAuthorizationDispatch{next}, nil
}

func (a *Auth) directOAuth(w http.ResponseWriter, r *http.Request, id string, p OAuthProvider, value any, linkUserID string, requestSignUp bool, callback string, resume OAuthLoginContinuation) (any, error) {
	if p.DisableIDTokenSignIn || p.VerifyIDToken == nil {
		return nil, &APIError{404, "ID_TOKEN_NOT_SUPPORTED", "Provider does not support ID token sign-in"}
	}
	data, ok := value.(map[string]any)
	if !ok {
		return nil, validationError("Expected an ID token object")
	}
	raw, _ := data["token"].(string)
	nonce, _ := data["nonce"].(string)
	if raw == "" || nonce == "" {
		return nil, &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), oauth2.HTTPClient, p.HTTPClient), 30*time.Second)
	defer cancel()
	profile, expires, err := p.VerifyIDToken(ctx, raw, nonce)
	if err != nil || !expires.After(a.now()) {
		return nil, &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	// A verified token whose profile has no email cannot name an account.
	if profile.Email == "" {
		a.Logger().ErrorContext(ctx, "The provider's ID token has no email", "provider", id)
		return nil, &APIError{401, "USER_EMAIL_NOT_FOUND", "User email not found"}
	}
	if !validSocialProfile(profile) {
		return nil, &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	// Direct grants authenticate the signed ID token. A client-supplied access
	// or refresh token has no independently verified binding to its subject.
	tokens := OAuthTokens{IDToken: raw}
	input := OAuthAccountFieldInput{Profile: profile, Tokens: tokens}
	input.ClientAccessToken, _ = data["accessToken"].(string)
	input.ClientRefreshToken, _ = data["refreshToken"].(string)
	fields, fieldErr := a.mapAccountFields(ctx, p, input)
	if fieldErr != nil {
		return nil, fieldErr
	}
	account, _, err := a.completeProfile(ctx, r, id, callback, profile, tokens, OAuthLoginOptions{AccountFields: fields, DisableSignUp: p.DisableImplicitSignUp && !requestSignUp, AllowVerifiedEmailLink: p.AllowVerifiedEmailLink, LinkUserID: linkUserID, LinkSessionToken: a.cookieToken(r.Header), IDTokenValidUntil: expires})
	var refused *userInfoRejection
	if errors.As(err, &refused) {
		return nil, refused.APIError
	}
	var signupError *APIError
	if errors.As(err, &signupError) && signupError.Code == "SIGN_UP_DISABLED" {
		return nil, &APIError{401, "OAUTH_LINK_ERROR", "signup disabled"}
	}
	if errors.Is(err, ErrIDTokenUsed) {
		return nil, &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	if errors.Is(err, ErrOAuthLinkingDisabled) || errors.Is(err, ErrOAuthLinkNotAllowed) {
		return nil, &APIError{401, "LINKING_NOT_ALLOWED", "Account not linked - linking not allowed"}
	}
	if errors.Is(err, ErrOAuthLinkEmailMismatch) {
		return nil, &APIError{401, "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED", "Account not linked - different emails not allowed"}
	}
	if errors.Is(err, ErrOAuthAccountAlreadyLinked) {
		return nil, &APIError{409, "SOCIAL_ACCOUNT_ALREADY_LINKED", "Social account already linked"}
	}
	if linkUserID != "" && errors.Is(err, ErrNotFound) {
		return nil, &APIError{401, "UNAUTHORIZED", "Unauthorized"}
	}
	if errors.Is(err, ErrOAuthLinkRequired) || errors.Is(err, ErrNotFound) {
		return nil, &APIError{401, "ACCOUNT_NOT_LINKED", "Account not linked"}
	}
	if errors.Is(err, errPlannedUserSkipped) {
		return nil, &APIError{401, "OAUTH_LINK_ERROR", "unable to create user"}
	}
	if errors.Is(err, errPlannedSessionSkipped) {
		return nil, &APIError{401, "OAUTH_LINK_ERROR", "unable to create session"}
	}
	if err != nil {
		return nil, err
	}
	if linkUserID != "" {
		return map[string]any{"url": "", "status": true, "redirect": false}, nil
	}
	out, err := a.publishSocialLogin(w, r, account.Token, resume)
	if err == nil {
		a.setAccountCookie(w.Header(), r, account.User.ID, id, profile.Subject)
	}
	if out != nil || err != nil {
		return out, err
	}
	return map[string]any{"redirect": false, "token": account.Token, "user": account.User}, nil
}
