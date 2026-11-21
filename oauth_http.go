package frostauth

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
		writeAuthError(w, err)
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
	linkUserID := ""
	if link {
		current, err := a.requireOwnerSession(r.Context(), r.Header)
		if err != nil {
			return err
		}
		linkUserID = current.User.ID
	}
	if value, found := body["idToken"]; found {
		return a.directOAuth(w, r, id, p, value, linkUserID)
	}
	browser := randomID()
	now := a.now().UTC()
	flow := OAuthFlow{State: randomID(), Binding: a.oauthBinding(browser, id, r), Provider: id, Verifier: oauth2.GenerateVerifier(),
		Nonce: randomID(), ExpiresAt: now.Add(10 * time.Minute)}
	flow.LinkUserID = linkUserID
	if a.anonymous != nil && !link {
		guest, err := a.guestToken(r)
		if err != nil {
			return err
		}
		if guest != "" {
			browser = "guest-" + browser
			flow.Binding = digest(browser + "\x00" + id + "\x00")
			flow.AnonymousSessionProof, err = a.sealRecord("guest-oauth:"+flow.State, []byte(guest))
			if err != nil {
				return err
			}
		}
	}
	flow.CallbackURL, _ = body["callbackURL"].(string)
	flow.ErrorCallbackURL, _ = body["errorCallbackURL"].(string)
	flow.NewUserCallbackURL, _ = body["newUserCallbackURL"].(string)
	if flow.CallbackURL == "" {
		flow.CallbackURL = a.opts.BaseURL
	}
	if err := a.opts.Store.(OAuthStore).SaveOAuthFlow(r.Context(), flow, now); err != nil {
		return err
	}
	http.SetCookie(w, a.oauthCookie("oauth_state", browser, 600))
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
	target := p.Config.AuthCodeURL(flow.State, opts...)
	if p.CustomizeAuthorization != nil {
		u, err := url.Parse(target)
		if err != nil {
			return err
		}
		p.CustomizeAuthorization(u)
		target = u.String()
	}
	if !disable {
		w.Header().Set("Location", target)
	}
	writeAuthJSON(w, 200, map[string]any{"url": target, "redirect": !disable})
	return nil
}

func (a *Auth) finishOAuth(w http.ResponseWriter, r *http.Request, id string) error {
	p, err := a.providerConfig(id)
	if err != nil {
		return err
	}
	// The configured origin is the only destination sent in the code exchange.
	base, _ := url.Parse(a.opts.BaseURL)
	if canonicalOrigin(&url.URL{Scheme: base.Scheme, Host: r.Host}) != canonicalOrigin(base) {
		return &APIError{400, "INVALID_CALLBACK_URL", "Invalid OAuth callback"}
	}
	q := r.URL.Query()
	state := q.Get("state")
	cookie, err := r.Cookie(a.oauthCookie("oauth_state", "", 0).Name)
	if err != nil || len(q["state"]) != 1 || len(state) > 128 || state == "" || len(q["code"]) > 1 || len(q["error"]) > 1 {
		return &APIError{400, "INVALID_OAUTH_STATE", "Invalid or expired OAuth state"}
	}
	store := a.opts.Store.(OAuthStore)
	binding := a.oauthBinding(cookie.Value, id, r)
	if strings.HasPrefix(cookie.Value, "guest-") {
		binding = digest(cookie.Value + "\x00" + id + "\x00")
	}
	flow, err := store.ConsumeOAuthFlow(r.Context(), state, binding, a.now().UTC())
	if errors.Is(err, ErrNotFound) {
		return &APIError{400, "INVALID_OAUTH_STATE", "Invalid or expired OAuth state"}
	}
	if err != nil {
		return err
	}
	http.SetCookie(w, a.oauthCookie("oauth_state", "", -1))
	fail := func(code string) error {
		if flow.ErrorCallbackURL != "" && a.trustedURL(flow.ErrorCallbackURL, true) {
			target, _ := url.Parse(flow.ErrorCallbackURL)
			v := target.Query()
			v.Set("error", code)
			target.RawQuery = v.Encode()
			http.Redirect(w, r, target.String(), http.StatusFound)
			return nil
		}
		return &APIError{400, code, "Unable to complete social sign-in"}
	}
	if flow.AnonymousSessionProof != "" {
		guest, err := a.openRecord("guest-oauth:"+flow.State, flow.AnonymousSessionProof)
		current := a.cookieToken(r.Header)
		if err != nil || a.anonymous == nil || current != "" && current != string(guest) {
			return fail("INVALID_OAUTH_STATE")
		}
		r = r.WithContext(context.WithValue(r.Context(), anonymousSourceKey{}, string(guest)))
	}
	if flow.Provider != id || q.Get("error") != "" || q.Get("code") == "" {
		return fail("OAUTH_CALLBACK_ERROR")
	}
	ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), oauth2.HTTPClient, p.HTTPClient), 30*time.Second)
	defer cancel()
	var params []oauth2.AuthCodeOption
	if !p.DisablePKCE {
		params = append(params, oauth2.VerifierOption(flow.Verifier))
	}
	var token *oauth2.Token
	if p.ExchangeCode == nil {
		token, err = p.Config.Exchange(ctx, q.Get("code"), params...)
	} else {
		token, err = p.ExchangeCode(ctx, p.Config, q.Get("code"), flow.Verifier, q)
	}
	if err != nil {
		return fail("OAUTH_TOKEN_EXCHANGE_FAILED")
	}
	profile, err := p.Resolve(ctx, token, flow.Nonce)
	if err != nil || !validSocialProfile(profile) {
		return fail("OAUTH_PROFILE_INVALID")
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
	result, created, err := a.completeProfile(ctx, r, id, profile, tokens, OAuthLoginOptions{AllowVerifiedEmailLink: p.AllowVerifiedEmailLink, LinkUserID: flow.LinkUserID, LinkSessionToken: a.cookieToken(r.Header)})
	if errors.Is(err, ErrOAuthLinkRequired) || errors.Is(err, ErrNotFound) {
		return fail("ACCOUNT_NOT_LINKED")
	}
	if err != nil {
		return err
	}
	if flow.LinkUserID == "" {
		if err := a.setSessionCookie(w, r, result.Token, true); err != nil {
			return err
		}
	}
	target := flow.CallbackURL
	if created && flow.NewUserCallbackURL != "" {
		target = flow.NewUserCallbackURL
	}
	if !a.trustedURL(target, true) {
		target = a.opts.BaseURL
	}
	http.Redirect(w, r, target, http.StatusFound)
	return nil
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

func (a *Auth) completeProfile(ctx context.Context, r *http.Request, id string, p OAuthProfile, tokens OAuthTokens, options OAuthLoginOptions) (AuthResult, bool, error) {
	options.DisableSignUp = options.DisableSignUp || a.opts.DisableSignUp || a.opts.SocialProviders[id].DisableSignUp
	if id == "google" && !googleDomainAllowed(a.opts.SocialProviders[id].GoogleHostedDomain, p) {
		return AuthResult{}, false, &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	candidate := User{ID: randomID(), Name: p.Name, Email: strings.ToLower(p.Email), EmailVerified: p.EmailVerified, Image: p.Image, CreatedAt: now, UpdatedAt: now}
	session, raw := a.newSession(candidate.ID, RequestMeta{IPAddress: a.clientIP(r), UserAgent: r.UserAgent()})
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
	user, created, err := a.opts.Store.(OAuthStore).CompleteOAuth(ctx, id, p.Subject, tokens, candidate, session, options)
	if errors.Is(err, ErrOAuthSignupDisabled) {
		return AuthResult{}, false, &APIError{403, "SIGN_UP_DISABLED", "Sign-up is disabled"}
	}
	if err == nil {
		err = a.readGuestFlag(ctx, &user)
	}
	return AuthResult{User: user, Token: raw}, created, err
}

func (a *Auth) directOAuth(w http.ResponseWriter, r *http.Request, id string, p OAuthProvider, value any, linkUserID string) error {
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
	account, _, err := a.completeProfile(ctx, r, id, profile, OAuthTokens{IDToken: raw}, OAuthLoginOptions{AllowVerifiedEmailLink: p.AllowVerifiedEmailLink, LinkUserID: linkUserID, LinkSessionToken: a.cookieToken(r.Header), IDTokenValidUntil: expires})
	if errors.Is(err, ErrIDTokenUsed) {
		return &APIError{401, "INVALID_TOKEN", "Invalid token"}
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
