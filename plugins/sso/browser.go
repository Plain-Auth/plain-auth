package sso

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/httporigin"
	"golang.org/x/oauth2"
)

type Selector struct{ ProviderID, Domain, OrganizationSlug, Protocol string }
type BrowserProvider struct {
	Provider
	Reference string
}

// BrowserStore resolves and completes enterprise sign-ins. Their flows are
// kept by the auth instance's OAuthStateStrategy. CompleteEnterpriseLogin
// applies opts.ProfileFields: Create for a new user, and Update, when set,
// to the returning owner.
type BrowserStore interface {
	auth.OAuthIdentityStore
	FindBrowserProvider(context.Context, Selector) (BrowserProvider, error)
	// role is the organization role to provision, or "" for none.
	CompleteEnterpriseLogin(ctx context.Context, reference string, role string, provider, subject string, tokens auth.OAuthTokens, user auth.User, session auth.StoredSession, opts auth.OAuthLoginOptions) (auth.User, bool, error)
}

var ErrChanged = &auth.APIError{Status: 409, Code: "SSO_PROVIDER_CHANGED", Message: "The enterprise provider changed during authentication"}

func callbackURI(c auth.EndpointContext, id string, shared bool) (string, error) {
	path := strings.TrimSuffix(c.Auth.BasePath(), "/") + "/sso/callback"
	if !shared {
		path += "/" + id
	}
	return c.CallbackURL(path)
}

// DomainMatch returns the length of the most specific DNS suffix, or -1 for no match.
func DomainMatch(domain, list string) int {
	best := -1
	for _, name := range strings.Split(list, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" && (domain == name || strings.HasSuffix(domain, "."+name)) && len(name) > best {
			best = len(name)
		}
	}
	return best
}

func available(c auth.EndpointContext, p BrowserProvider) bool {
	return (p.OIDC != nil || p.SAML != nil) && p.Reference != "" && MutableProviderID(p.ProviderID) && !c.Auth.HasOAuthProvider(p.ProviderID)
}
func (o Options) start(c auth.EndpointContext) (any, error) {
	store, ok := c.Store().(BrowserStore)
	if !ok {
		return nil, apiError(501, "The configured store does not support enterprise sign-in")
	}
	body := c.Body
	read := func(key string) string { v, _ := body[key].(string); return v }
	for _, k := range []string{"providerId", "organizationSlug", "domain", "email", "providerType", "loginHint"} {
		if _, has := body[k]; has {
			if _, ok := body[k].(string); !ok {
				return nil, apiError(400, "Invalid "+k)
			}
		}
	}
	kind := read("providerType")
	if kind != "" && kind != "oidc" && (kind != "saml" || o.SAML == nil) {
		return nil, apiError(400, "OIDC provider is not configured")
	}
	sel := Selector{ProviderID: read("providerId"), OrganizationSlug: read("organizationSlug"), Domain: read("domain")}
	sel.Protocol = kind
	if o.SAML == nil {
		sel.Protocol = "oidc"
	}
	if sel.Domain == "" && read("email") != "" {
		_, sel.Domain, _ = strings.Cut(read("email"), "@")
	}
	if sel.ProviderID == "" && sel.OrganizationSlug == "" {
		if sel.Domain == "" {
			return nil, apiError(400, "email, organizationSlug, domain or providerId is required")
		}
		var err error
		sel.Domain, err = domains(sel.Domain)
		if err != nil || strings.Contains(sel.Domain, ",") {
			return nil, apiError(400, "Invalid provider domain")
		}
	}
	signup, ok := body["requestSignUp"].(bool)
	if _, found := body["requestSignUp"]; found && !ok {
		return nil, apiError(400, "Invalid requestSignUp")
	}
	find := store.FindBrowserProvider
	if o.DomainVerification != nil {
		find = store.(DomainStore).FindVerifiedBrowserProvider
	}
	p, err := find(c.Request.Context(), sel)
	if errors.Is(err, ErrMissing) && kind != "" {
		// Like another runtime, name the protocol a found provider lacks.
		any := sel
		any.Protocol = ""
		// A provider whose domain is not verified yet still lacks the protocol.
		if other, e := find(c.Request.Context(), any); e == nil && available(c, other) || errors.Is(e, ErrDomainUnverified) {
			if kind == "saml" {
				return nil, apiError(400, "SAML provider is not configured")
			}
			return nil, apiError(400, "OIDC provider is not configured")
		}
	}
	if err != nil {
		return nil, err
	}
	if !available(c, p) {
		return nil, ErrMissing
	}
	proof, err := o.domainGate(c, p)
	if err != nil {
		return nil, err
	}
	if p.SAML != nil {
		return o.samlStart(c, p, proof, signup)
	}
	if p, err = o.withRuntimeDiscovery(c.Request.Context(), c.Auth, p); err != nil {
		return nil, err
	}
	opts := []oauth2.AuthCodeOption{}
	login := read("loginHint")
	if login == "" {
		login = read("email")
	}
	if login != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", login))
	}
	var scopes []string
	if raw, ok := body["scopes"]; ok {
		items, ok := raw.([]any)
		if !ok {
			return nil, apiError(400, "Invalid scopes")
		}
		scopes = []string{}
		for _, item := range items {
			s, ok := item.(string)
			if !ok || s == "" {
				return nil, apiError(400, "Invalid scopes")
			}
			scopes = append(scopes, s)
		}
	}
	if raw, ok := body["additionalParams"]; ok {
		args, ok := raw.(map[string]any)
		if !ok {
			return nil, apiError(400, "Invalid additionalParams")
		}
		for k, v := range args {
			value, ok := v.(string)
			if !ok || k == "" || slices.Contains([]string{"client_id", "client_secret", "state", "nonce", "response_type", "response_mode", "code_challenge", "code_challenge_method", "redirect_uri", "scope", "request", "request_uri"}, strings.ToLower(k)) {
				return nil, apiError(400, "Invalid additional authorization parameter")
			}
			opts = append(opts, oauth2.SetAuthURLParam(k, value))
		}
	}
	target, err := o.authorize(c, p, proof, signup, scopes, opts)
	if err != nil {
		return nil, err
	}
	return map[string]any{"url": target, "redirect": true}, nil
}

// authorize begins a browser flow for p and returns the provider's
// authorization URL. scopes, when not nil, replace the configured scopes;
// extra carries the request's login hint and additional parameters.
func (o Options) authorize(c auth.EndpointContext, p BrowserProvider, proof, signup bool, scopes []string, extra []oauth2.AuthCodeOption) (string, error) {
	cfg, err := o.oauthConfig(c, p)
	if err != nil {
		return "", err
	}
	if scopes != nil {
		cfg.Scopes = scopes
	}
	reference := p.Reference
	if proof {
		reference += ".dns"
	}
	flow, err := c.BeginEnterpriseFlow(p.ProviderID, reference, cfg.RedirectURL, signup)
	if err != nil {
		return "", err
	}
	opts := append(slices.Clone(extra), oauth2.SetAuthURLParam("nonce", flow.Nonce))
	if p.OIDC.PKCE != nil && *p.OIDC.PKCE {
		opts = append(opts, oauth2.S256ChallengeOption(flow.Verifier))
	}
	// Merge through URL.Values so a query on the configured endpoint cannot
	// duplicate a protocol parameter supplied for this authorization.
	base, _ := url.Parse(cfg.Endpoint.AuthURL)
	fixed := base.Query()
	base.RawQuery = ""
	cfg.Endpoint.AuthURL = base.String()
	target, err := url.Parse(cfg.AuthCodeURL(flow.State, opts...))
	if err != nil {
		return "", err
	}
	for key, values := range target.Query() {
		fixed[key] = values
	}
	target.RawQuery = fixed.Encode()
	return target.String(), nil
}
func (o Options) oauthConfig(c auth.EndpointContext, p BrowserProvider) (oauth2.Config, error) {
	var cfg oauth2.Config
	idp := p.OIDC
	for _, v := range []string{p.Issuer, idp.AuthorizationEndpoint, idp.TokenEndpoint, idp.JWKSEndpoint} {
		if err := secureBrowserEndpoint(c.Auth, v); err != nil {
			return cfg, err
		}
	}
	if idp.UserInfoEndpoint != "" {
		if e := secureBrowserEndpoint(c.Auth, idp.UserInfoEndpoint); e != nil {
			return cfg, e
		}
	}
	if idp.ClientID == "" || idp.Issuer != "" && idp.Issuer != p.Issuer {
		return cfg, apiError(400, "Invalid persisted OpenID Connect configuration")
	}
	style, secret := oauth2.AuthStyleInHeader, idp.ClientSecret
	switch idp.TokenEndpointAuthentication {
	case "", "client_secret_basic":
	case "client_secret_post":
		style = oauth2.AuthStyleInParams
	case privateKeyJWT:
		if o.ResolvePrivateKey == nil {
			return cfg, apiError(400, "Unsupported OpenID Connect client authentication method")
		}
		// The exchange sends client_id with a signed assertion and never a secret.
		style, secret = oauth2.AuthStyleInParams, ""
	default:
		return cfg, apiError(400, "Unsupported OpenID Connect client authentication method")
	}
	if secret == "" && idp.TokenEndpointAuthentication != privateKeyJWT {
		return cfg, apiError(400, "Invalid persisted OpenID Connect configuration")
	}
	uri, err := callbackURI(c, p.ProviderID, o.SharedCallback)
	if err != nil {
		return cfg, err
	}
	scopes := idp.Scopes
	if scopes == nil {
		scopes = []string{"openid", "email", "profile", "offline_access"}
	}
	return oauth2.Config{ClientID: idp.ClientID, ClientSecret: secret, RedirectURL: uri, Scopes: scopes, Endpoint: oauth2.Endpoint{AuthURL: idp.AuthorizationEndpoint, TokenURL: idp.TokenEndpoint, AuthStyle: style}}, nil
}
func (o Options) finish(c auth.EndpointContext) (any, error) {
	store, ok := c.Store().(BrowserStore)
	if !ok {
		return nil, apiError(501, "The configured store does not support enterprise sign-in")
	}
	if o.AllowIDPInitiatedOIDC != nil {
		if out, handled, err := o.restartIDPInitiated(c, store); handled {
			return out, err
		}
	}
	flow, err := c.ConsumeEnterpriseFlow()
	if code := auth.OAuthStateFailure(err); code != "" {
		// As with a social sign-in, a state the callback cannot use goes
		// to the configured error page with its code.
		target, err := c.ErrorPageURL()
		if err != nil {
			return nil, err
		}
		return c.Redirect(httporigin.SetQuery(target, url.Values{"error": {code}}))
	}
	if err != nil {
		return nil, err
	}
	fail := func(code string) (any, error) { return enterpriseFailure(c, flow, code, "") }
	q := c.Request.URL.Query()
	if idpError := q.Get("error"); idpError != "" || q.Get("code") == "" {
		// Send the identity provider's error back, as another runtime does.
		code, description := idpError, q.Get("error_description")
		if code == "" {
			code = "invalid_request"
		}
		if description == "" {
			description = idpError
		}
		if description == "" {
			description = "authorization_code_not_found"
		}
		return enterpriseFailure(c, flow, code, description)
	}
	p, err := store.FindBrowserProvider(c.Request.Context(), Selector{ProviderID: flow.Provider})
	if errors.Is(err, ErrMissing) {
		return enterpriseFailure(c, flow, "invalid_provider", "provider not found")
	}
	if err != nil {
		return nil, err
	}
	if p.OIDC == nil || !available(c, p) || strings.TrimSuffix(flow.ProviderReference, ".dns") != p.Reference {
		return enterpriseFailure(c, flow, "invalid_state", "sso_provider_changed_during_authentication")
	}
	proof, err := o.domainGate(c, p)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(flow.ProviderReference, ".dns") && !proof {
		return nil, ErrDomainUnverified
	}
	if iss := q.Get("iss"); iss != "" && iss != p.Issuer {
		return fail("invalid_provider")
	}
	if p, err = o.withRuntimeDiscovery(c.Request.Context(), c.Auth, p); err != nil {
		var ae *auth.APIError
		if errors.As(err, &ae) {
			return enterpriseFailure(c, flow, "discovery_failed", callbackDiscoveryMessage(ae.Message))
		}
		return enterpriseFailure(c, flow, "discovery_failed", "unexpected_discovery_error")
	}
	cfg, err := o.oauthConfig(c, p)
	if err != nil || cfg.RedirectURL != flow.RedirectURI {
		return fail("invalid_provider")
	}
	client := providerHTTP(c.Auth, o.HTTPClient)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	var params []oauth2.AuthCodeOption
	if p.OIDC.PKCE != nil && *p.OIDC.PKCE {
		params = append(params, oauth2.VerifierOption(flow.Verifier))
	}
	if p.OIDC.TokenEndpointAuthentication == privateKeyJWT {
		assertion, ok := o.clientAssertion(ctx, p)
		if !ok {
			return enterpriseFailure(c, flow, "invalid_provider", "no_private_key_available")
		}
		params = append(params, oauth2.SetAuthURLParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"), oauth2.SetAuthURLParam("client_assertion", assertion))
	}
	token, err := cfg.Exchange(ctx, q.Get("code"), params...)
	if err != nil {
		return fail("invalid_grant")
	}
	profile, idClaims, err := resolveIdentity(ctx, client, p, token, flow.Nonce)
	if err != nil {
		return fail("invalid_provider")
	}
	if !auth.ValidEnterpriseProfile(profile) {
		return enterpriseFailure(c, flow, "invalid_provider", "missing_user_info")
	}
	var resolved UserResolution
	if o.ResolveUser != nil {
		if idClaims == nil {
			return enterpriseFailure(c, flow, "invalid_provider", "id_token_required_for_user_resolution")
		}
		// The resolver runs before the sign-in transaction, never inside it;
		// the store rechecks the selected user and the identity under lock.
		resolved, err = o.resolveUser(c, UserResolutionInput{Protocol: "oidc", ProviderID: p.ProviderID, AccountKey: AccountKey{Issuer: p.Issuer, AccountID: profile.Subject},
			User: providerUser(profile), Claims: cloneClaims(profile.Data), IDTokenClaims: cloneClaims(idClaims), ProviderReference: p.Reference})
		if err != nil {
			return enterpriseFailure(c, flow, errResolution.Code, errResolution.Message)
		}
		if resolved.Action == ResolveReject {
			return enterpriseFailure(c, flow, resolved.Code, resolved.Message)
		}
	}
	idToken, _ := token.Extra("id_token").(string)
	scope, _ := token.Extra("scope").(string)
	tokens := auth.OAuthTokens{AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, IDToken: idToken, Scope: strings.Join(strings.Fields(scope), ","), ExpiresAt: token.Expiry}
	// The organization role is chosen before the sign-in transaction.
	role, err := o.membershipRole(c.Request.Context(), p.Provider, profile, &tokens)
	if err != nil {
		return nil, roleFailure(c, err)
	}
	complete := func(ctx context.Context, id, sub string, t auth.OAuthTokens, u auth.User, s auth.StoredSession, opts auth.OAuthLoginOptions) (auth.User, bool, error) {
		resolved.apply(&opts)
		if proof {
			return store.(DomainStore).CompleteVerifiedEnterpriseLogin(ctx, p.Reference, role, id, sub, t, u, s, opts)
		}
		return store.CompleteEnterpriseLogin(ctx, p.Reference, role, id, sub, t, u, s, opts)
	}
	raw := tokens
	result, err := c.CompleteEnterpriseFlowWith(flow, "sso-oidc", profile, tokens, auth.EnterpriseCompletion{DisableSignUp: o.DisableImplicitSignUp && !flow.RequestSignUp, OverrideUserInfo: p.OIDC.OverrideUserInfo || resolved.updates(),
		Committed: o.provisioned(p.Provider, profile, &raw)}, complete)
	if out, e, ok := provisioningFailure(c, err); ok {
		return out, e
	}
	if refused := auth.UserInfoRefusal(err); refused != nil {
		return enterpriseFailure(c, flow, refused.Code, refused.Message)
	}
	if out, e, ok := resolutionFailure(c, flow, resolved, err); ok {
		return out, e
	}
	if errors.Is(err, ErrDomainUnverified) {
		return nil, err
	}
	if errors.Is(err, auth.ErrOAuthLinkRequired) {
		return fail("account_not_linked")
	}
	if errors.Is(err, ErrChanged) {
		return enterpriseFailure(c, flow, "SSO_PROVIDER_CHANGED", providerChanged)
	}
	if out, e, ok := profileFailure(c, flow, err); ok {
		return out, e
	}
	var ae *auth.APIError
	if errors.As(err, &ae) {
		if ae.Code == "SIGN_UP_DISABLED" {
			// The OIDC code has a space, as another runtime sends it; SAML
			// and social sign-ins use signup_disabled.
			return fail("signup disabled")
		}
		return fail("access_denied")
	}
	return result, err
}

// profileFailure redirects a refused user field with its code and message,
// and a profile another user's email conflicts with as profile_conflict.
func profileFailure(c auth.EndpointContext, flow auth.OAuthFlow, err error) (any, error, bool) {
	var ae *auth.APIError
	if !errors.As(err, &ae) {
		return nil, nil, false
	}
	switch ae.Code {
	case "MISSING_FIELD", "VALIDATION_ERROR", "FIELD_NOT_ALLOWED":
		out, e := enterpriseFailure(c, flow, ae.Code, ae.Message)
		return out, e, true
	case "OAUTH_PROFILE_CONFLICT":
		out, e := enterpriseFailure(c, flow, "profile_conflict", ae.Message)
		return out, e, true
	}
	return nil, nil, false
}

func enterpriseFailure(c auth.EndpointContext, flow auth.OAuthFlow, code, description string) (any, error) {
	target := flow.ErrorCallbackURL
	if target == "" {
		target = flow.CallbackURL
	}
	if _, err := c.CallbackURL(target); err != nil {
		// The provider's callback request no longer trusts the stored target.
		target, _ = c.ErrorPageURL()
	}
	if _, e := url.Parse(target); e != nil {
		return nil, e
	}
	set := url.Values{"error": {code}}
	if description != "" {
		set.Set("error_description", description)
	}
	return c.Redirect(httporigin.SetQuery(target, set))
}

// providerChanged describes a provider that changed inside the sign-in
// transaction, as another runtime does.
const providerChanged = "SSO provider changed while account linking was in progress"

// callbackDiscoveryMessage drops the registration prefix from a discovery
// message, as another runtime's callback sends the raw one.
func callbackDiscoveryMessage(message string) string {
	for _, prefix := range []string{"OIDC discovery document is missing required fields: ", "OIDC issuer mismatch: "} {
		if rest, ok := strings.CutPrefix(message, prefix); ok {
			return rest
		}
	}
	return message
}
