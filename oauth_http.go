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
	"strings"
	"time"

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
	var err error
	if start {
		err = a.startOAuth(w, r, link)
	} else if r.Method == http.MethodPost {
		err = a.redirectOAuthForm(w, r, id)
	} else {
		err = a.finishOAuth(w, r, id)
	}
	if err != nil {
		a.writeAuthError(w, r, err)
	}
	return true
}

func (a *Auth) providerConfig(id string) (OAuthProvider, error) {
	p, ok := a.opts.SocialProviders[id]
	if !ok {
		return p, &APIError{404, "PROVIDER_NOT_FOUND", "Provider not found"}
	}
	p.Config.RedirectURL = a.opts.BaseURL + strings.TrimRight(a.opts.BasePath, "/") + "/callback/" + id
	return p, nil
}

func (a *Auth) oauthBinding(browser, id string, r *http.Request) string {
	return digest(browser + "\x00" + id + "\x00" + a.cookieToken(r.Header))
}

func (a *Auth) startOAuth(w http.ResponseWriter, r *http.Request, link bool) error {
	if err := a.validateRequestOrigin(r, true); err != nil {
		return err
	}
	body, err := decodeWireBody(w, r, "/sign-in/social")
	if err != nil {
		return err
	}
	if err = a.validateCallbacks(body, nil); err != nil {
		return err
	}
	id, ok := body["provider"].(string)
	if !ok {
		return fieldTypeError("provider", "string", body)
	}
	p, err := a.providerConfig(id)
	if err != nil {
		return err
	}
	disable := false
	if value, found := body["disableRedirect"]; found {
		disable, ok = value.(bool)
		if !ok {
			return fieldTypeError("disableRedirect", "boolean", body)
		}
	}
	requestedParams, err := authorizationOptions(body, p.Config.Scopes)
	if err != nil {
		return err
	}
	requestSignUp, ok := body["requestSignUp"].(bool)
	if _, present := body["requestSignUp"]; present && !ok {
		return fieldTypeError("requestSignUp", "boolean", body)
	}
	linkUserID := ""
	if link {
		current, err := a.requireOwnerSession(r.Context(), r.Header)
		if err != nil {
			return err
		}
		linkUserID = current.User.ID
	}
	if value, found := body["idToken"]; found {
		callback, _ := body["callbackURL"].(string)
		return a.directOAuth(w, r, id, p, value, linkUserID, requestSignUp, callback)
	}
	flow := OAuthFlow{Provider: id, LinkUserID: linkUserID, RequestSignUp: requestSignUp}
	target, _, err := a.beginBrowserOAuth(w.Header(), r, p, body, flow, requestedParams)
	if err != nil {
		return err
	}
	if !disable {
		w.Header().Set("Location", target)
	}
	writeAuthJSON(w, 200, map[string]any{"url": target, "redirect": !disable})
	return nil
}

// beginBrowserOAuth creates the same provider-bound, single-use grant for redirect and popup sign-in.
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
		flow.CallbackURL = a.opts.BaseURL
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
			p.Config.RedirectURL = a.oauthProxy.ProductionURL + a.opts.BasePath + "/callback/" + id
			var err error
			providerState, err = a.packProxyState(flow)
			if err != nil {
				return "", "", err
			}
		}
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
	if err := a.opts.Store.(OAuthStore).SaveOAuthFlow(r.Context(), flow, now); err != nil {
		return "", "", err
	}
	h.Add("Set-Cookie", a.oauthCookie("oauth_state", browser, 600).String())
	return target, flow.State, nil
}

func (a *Auth) finishOAuth(w http.ResponseWriter, r *http.Request, id string) error {
	p, err := a.providerConfig(id)
	if err != nil {
		return err
	}
	if a.oauthProxy != nil && strings.HasPrefix(r.URL.Query().Get("state"), recordPrefix) {
		return a.exchangeProxyCallback(w, r, id, p)
	}
	// The configured origin is the only destination sent in the code exchange.
	base, _ := url.Parse(a.opts.BaseURL)
	if canonicalOrigin(&url.URL{Scheme: base.Scheme, Host: r.Host}) != canonicalOrigin(base) {
		return &APIError{400, "INVALID_CALLBACK_URL", "Invalid OAuth callback"}
	}
	q := r.URL.Query()
	state := q.Get("state")
	return a.finishBrowserOAuth(w, r, id, p, state, q, nil)
}

func (a *Auth) finishBrowserOAuth(w http.ResponseWriter, r *http.Request, id string, p OAuthProvider, state string, q url.Values, returned *oauthProxyResult) (resultErr error) {
	var popup *popupOpener
	if (returned != nil || len(q["state"]) == 1) && state != "" && len(state) <= 128 {
		popup = a.callbackPopup(w.Header(), r, state)
	}
	if popup != nil {
		defer func() {
			if resultErr != nil {
				popup.write(w, "", "", &popupError{Code: "popup_sign_in_failed", Description: "Unable to complete social sign-in"})
				resultErr = nil
			}
		}()
	}
	cookie, err := r.Cookie(a.oauthCookie("oauth_state", "", 0).Name)
	if err != nil || state == "" || len(state) > 128 || (returned == nil && (len(q["state"]) != 1 || len(q["code"]) > 1 || len(q["error"]) > 1)) {
		return &APIError{400, "INVALID_OAUTH_STATE", "Invalid or expired OAuth state"}
	}
	store := a.opts.Store.(OAuthStore)
	binding := a.oauthBinding(cookie.Value, id, r)
	if strings.HasPrefix(cookie.Value, "guest-") {
		binding = digest(cookie.Value + "\x00" + id + "\x00")
	}
	flow, err := store.ConsumeOAuthFlow(r.Context(), state, binding, a.now().UTC())
	if errors.Is(err, ErrNotFound) {
		if popup != nil {
			popup.write(w, "", "", &popupError{Code: "INVALID_OAUTH_STATE", Description: "Invalid or expired OAuth state"})
			return nil
		}
		return &APIError{400, "INVALID_OAUTH_STATE", "Invalid or expired OAuth state"}
	}
	if err != nil {
		return err
	}
	http.SetCookie(w, a.oauthCookie("oauth_state", "", -1))
	failWithDescription := func(code, description string) error {
		if popup != nil {
			popup.write(w, "", "", &popupError{Code: code, Description: description})
			return nil
		}
		if flow.ErrorCallbackURL != "" && a.trustedURL(flow.ErrorCallbackURL, true) {
			target, _ := url.Parse(flow.ErrorCallbackURL)
			v := target.Query()
			v.Set("error", code)
			if description != "" {
				v.Set("error_description", description)
			}
			target.RawQuery = v.Encode()
			http.Redirect(w, r, target.String(), http.StatusFound)
			return nil
		}
		return &APIError{400, code, "Unable to complete social sign-in"}
	}
	fail := func(code string) error { return failWithDescription(code, "") }
	if (returned == nil && flow.ProxyOrigin != "") || (returned != nil && (flow.ProxyOrigin != returned.Preview || flow.CallbackURL != returned.Callback)) {
		return fail("INVALID_OAUTH_STATE")
	}
	if flow.AnonymousSessionProof != "" {
		guest, err := a.openRecord("guest-oauth:"+flow.State, flow.AnonymousSessionProof)
		current := a.cookieToken(r.Header)
		if err != nil || a.anonymous == nil || current != "" && current != string(guest) {
			return fail("INVALID_OAUTH_STATE")
		}
		r = r.WithContext(context.WithValue(r.Context(), anonymousSourceKey{}, string(guest)))
	}
	if popup != nil && flow.Provider == id && q.Get("error") != "" {
		popup.write(w, "", "", &popupError{Code: q.Get("error"), Description: q.Get("error_description")})
		return nil
	}
	if flow.Provider != id || (returned == nil && (q.Get("error") != "" || q.Get("code") == "")) {
		return fail("OAUTH_CALLBACK_ERROR")
	}
	ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), oauth2.HTTPClient, p.HTTPClient), 30*time.Second)
	defer cancel()
	if flow.PopupAdditionalData != nil {
		ctx = context.WithValue(ctx, popupDataKey{}, flow.PopupAdditionalData)
	}
	var profile OAuthProfile
	var tokens OAuthTokens
	disableSignUp := p.DisableImplicitSignUp && !flow.RequestSignUp
	if returned != nil && flow.ErrorCallbackURL == "" {
		flow.ErrorCallbackURL = a.opts.BasePath + "/error"
	}
	if returned == nil {
		var failure string
		profile, tokens, failure = a.exchangeProviderCode(ctx, p, flow, q)
		if failure != "" {
			return fail(failure)
		}
	} else {
		if returned.Error != "" {
			return fail(returned.Error)
		}
		profile, tokens = returned.Profile, returned.Tokens
		profile.AdditionalFields = returned.Fields
		if returned.GoogleHostedDomain != "" {
			profile.Data = map[string]any{"hd": returned.GoogleHostedDomain}
		}
		if !validSocialProfile(profile) {
			return fail("OAUTH_PROFILE_INVALID")
		}
		disableSignUp = disableSignUp || returned.DisableSignUp
		p.RequireEmailVerification = p.RequireEmailVerification || returned.RequireEmailVerification
	}
	result, created, err := a.completeProfile(ctx, r, id, flow.CallbackURL, profile, tokens, OAuthLoginOptions{DisableSignUp: disableSignUp, RequireEmailVerification: p.RequireEmailVerification, AllowVerifiedEmailLink: p.AllowVerifiedEmailLink, LinkUserID: flow.LinkUserID, LinkSessionToken: a.cookieToken(r.Header)})
	var apiError *APIError
	if errors.As(err, &apiError) && apiError.Code == "EMAIL_NOT_VERIFIED" {
		if flow.ErrorCallbackURL == "" {
			flow.ErrorCallbackURL = a.opts.BaseURL + a.opts.BasePath + "/error"
		}
		return fail("email_not_verified")
	}
	if errors.As(err, &apiError) && apiError.Code == "SIGN_UP_DISABLED" {
		if flow.ErrorCallbackURL == "" {
			flow.ErrorCallbackURL = a.opts.BaseURL + a.opts.BasePath + "/error"
		}
		return fail("signup_disabled")
	}
	var fieldError oauthProfileFieldError
	if errors.As(err, &fieldError) && errors.As(fieldError, &apiError) {
		if flow.ErrorCallbackURL == "" {
			flow.ErrorCallbackURL = a.opts.BaseURL + a.opts.BasePath + "/error"
		}
		return failWithDescription(apiError.Code, apiError.Message)
	}
	if errors.Is(err, ErrOAuthLinkingDisabled) {
		return fail("unable_to_link_account")
	}
	if errors.As(err, &apiError) && apiError.Code == "OAUTH_PROFILE_CONFLICT" {
		return fail("profile_conflict")
	}
	if errors.Is(err, ErrOAuthLinkRequired) || errors.Is(err, ErrNotFound) {
		return fail("account_not_linked")
	}
	if err != nil {
		return err
	}
	if flow.LinkUserID == "" {
		if err := a.setSessionCookie(w, r, result.Token, true); err != nil {
			return a.discardUnpublishedSession(ctx, result.Token, err)
		}
	}
	target := flow.CallbackURL
	if created && flow.NewUserCallbackURL != "" {
		target = flow.NewUserCallbackURL
	}
	if !a.trustedURL(target, true) {
		target = a.opts.BaseURL
	}
	if popup != nil && flow.LinkUserID == "" {
		popup.write(w, a.sessionCookie(result.Token, true).Value, target, nil)
		return nil
	}
	http.Redirect(w, r, target, http.StatusFound)
	return nil
}

func (a *Auth) exchangeProviderCode(ctx context.Context, p OAuthProvider, flow OAuthFlow, q url.Values) (OAuthProfile, OAuthTokens, string) {
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
	if err != nil {
		return OAuthProfile{}, OAuthTokens{}, "OAUTH_TOKEN_EXCHANGE_FAILED"
	}
	profile, err := p.Resolve(ctx, token, flow.Nonce)
	if err != nil || !validSocialProfile(profile) {
		return OAuthProfile{}, OAuthTokens{}, "OAUTH_PROFILE_INVALID"
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
	return profile, tokens, ""
}

func validSocialProfile(p OAuthProfile) bool {
	return p.Subject != "" && len(p.Subject) <= 1024 && len(p.Email) <= 254 && emailPattern.MatchString(p.Email) && !strings.Contains(p.Email, "..")
}

// A cross-site form POST does not carry SameSite=Lax cookies. Redirect to the
// fixed callback origin for a top-level GET, then consume the bound state.
func (a *Auth) redirectOAuthForm(w http.ResponseWriter, r *http.Request, id string) error {
	p, err := a.providerConfig(id)
	if err != nil {
		return err
	}
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if media != "application/x-www-form-urlencoded" {
		return &APIError{415, "UNSUPPORTED_MEDIA_TYPE", "Expected a form-encoded callback"}
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		return validationError("Invalid OAuth callback form")
	}
	fields, err := url.ParseQuery(string(data))
	if err != nil {
		return validationError("Invalid OAuth callback form")
	}
	q := url.Values{}
	for _, key := range []string{"state", "code", "error", "error_description", "user", "iss", "device_id"} {
		values := fields[key]
		if len(values) > 1 {
			return validationError("Duplicate OAuth callback field")
		}
		if len(values) == 1 {
			q.Set(key, values[0])
		}
	}
	if q.Get("state") == "" {
		return &APIError{400, "INVALID_OAUTH_STATE", "Invalid or expired OAuth state"}
	}
	http.Redirect(w, r, p.Config.RedirectURL+"?"+q.Encode(), http.StatusFound)
	return nil
}

func (a *Auth) completeProfile(ctx context.Context, r *http.Request, id, callback string, p OAuthProfile, tokens OAuthTokens, options OAuthLoginOptions) (AuthResult, bool, error) {
	complete := a.opts.Store.(OAuthStore).CompleteOAuth
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
	result, created, err := a.completeProfileWith(ctx, r, id, p, tokens, options, complete)
	blocked := errors.Is(err, ErrOAuthEmailUnverified)
	if (err == nil || blocked) && options.LinkUserID == "" && !result.User.EmailVerified && a.opts.SendVerificationEmail != nil {
		send := blocked && a.opts.SendVerificationOnSignIn
		if created {
			send = a.sendVerificationOnSignup(options.RequireEmailVerification)
		}
		if send {
			if err := a.sendEmailProof(ctx, result.User, "", "", callback, a.opts.SendVerificationEmail); err != nil {
				a.Logger().ErrorContext(ctx, "Could not deliver social sign-in verification email")
			}
		}
	}
	if blocked {
		return AuthResult{}, created, &APIError{403, "EMAIL_NOT_VERIFIED", "Email not verified"}
	}
	return result, created, err
}

func (a *Auth) completeProfileWith(ctx context.Context, r *http.Request, id string, p OAuthProfile, tokens OAuthTokens, options OAuthLoginOptions, complete OAuthCompletion) (AuthResult, bool, error) {
	options.DisableAccountUpdateOnSignIn = a.opts.DisableAccountUpdateOnSignIn && options.LinkUserID == ""
	if a.opts.DisableImplicitAccountLinking || a.opts.DisableAccountLinking {
		options.DisableImplicitLinking = true
		options.AllowVerifiedEmailLink = false
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
	user, created, err := complete(ctx, id, p.Subject, tokens, candidate, session, options)
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

func (a *Auth) directOAuth(w http.ResponseWriter, r *http.Request, id string, p OAuthProvider, value any, linkUserID string, requestSignUp bool, callback string) error {
	if p.VerifyIDToken == nil {
		return &APIError{404, "ID_TOKEN_NOT_SUPPORTED", "Provider does not support ID token sign-in"}
	}
	data, ok := value.(map[string]any)
	if !ok {
		return validationError("Expected an ID token object")
	}
	raw, _ := data["token"].(string)
	nonce, _ := data["nonce"].(string)
	if raw == "" || nonce == "" {
		return &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), oauth2.HTTPClient, p.HTTPClient), 30*time.Second)
	defer cancel()
	profile, expires, err := p.VerifyIDToken(ctx, raw, nonce)
	if err != nil || !validSocialProfile(profile) || !expires.After(a.now()) {
		return &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	// Direct grants authenticate the signed ID token. A client-supplied access
	// or refresh token has no independently verified binding to its subject.
	account, _, err := a.completeProfile(ctx, r, id, callback, profile, OAuthTokens{IDToken: raw}, OAuthLoginOptions{DisableSignUp: p.DisableImplicitSignUp && !requestSignUp, AllowVerifiedEmailLink: p.AllowVerifiedEmailLink, LinkUserID: linkUserID, LinkSessionToken: a.cookieToken(r.Header), IDTokenValidUntil: expires})
	var signupError *APIError
	if errors.As(err, &signupError) && signupError.Code == "SIGN_UP_DISABLED" {
		return &APIError{401, "OAUTH_LINK_ERROR", "signup disabled"}
	}
	if errors.Is(err, ErrIDTokenUsed) {
		return &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	if errors.Is(err, ErrOAuthLinkingDisabled) {
		return &APIError{401, "LINKING_NOT_ALLOWED", "Account not linked - linking not allowed"}
	}
	if errors.Is(err, ErrOAuthAccountAlreadyLinked) {
		return &APIError{409, "SOCIAL_ACCOUNT_ALREADY_LINKED", "Social account already linked"}
	}
	if errors.Is(err, ErrOAuthLinkRequired) || errors.Is(err, ErrNotFound) {
		return &APIError{401, "ACCOUNT_NOT_LINKED", "Account not linked"}
	}
	if err != nil {
		return err
	}
	if linkUserID != "" {
		writeAuthJSON(w, 200, map[string]any{"url": "", "status": true, "redirect": false})
		return nil
	}
	if err := a.setSessionCookie(w, r, account.Token, true); err != nil {
		return err
	}
	writeAuthJSON(w, 200, map[string]any{"redirect": false, "token": account.Token, "user": account.User})
	return nil
}
