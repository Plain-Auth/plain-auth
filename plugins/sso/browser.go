package sso

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"golang.org/x/oauth2"
)

type Selector struct{ ProviderID, Domain, OrganizationSlug, Protocol string }
type BrowserProvider struct {
	Provider
	Reference string
}
type BrowserStore interface {
	auth.OAuthStore
	FindBrowserProvider(context.Context, Selector) (BrowserProvider, error)
	CompleteEnterpriseLogin(ctx context.Context, reference string, provision bool, provider, subject string, tokens auth.OAuthTokens, user auth.User, session auth.StoredSession, opts auth.OAuthLoginOptions) (auth.User, bool, error)
}

var ErrChanged = &auth.APIError{Status: 409, Code: "SSO_PROVIDER_CHANGED", Message: "The enterprise provider changed during authentication"}

func callbackURI(c auth.EndpointContext, id string, shared bool) (string, error) {
	path := strings.TrimSuffix(c.Auth.BasePath(), "/") + "/sso/callback"
	if !shared {
		path += "/" + id
	}
	return c.Auth.CallbackURL(path)
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
	cfg, err := o.oauthConfig(c, p)
	if err != nil {
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
	if raw, ok := body["scopes"]; ok {
		items, ok := raw.([]any)
		if !ok {
			return nil, apiError(400, "Invalid scopes")
		}
		cfg.Scopes = nil
		for _, item := range items {
			s, ok := item.(string)
			if !ok || s == "" {
				return nil, apiError(400, "Invalid scopes")
			}
			cfg.Scopes = append(cfg.Scopes, s)
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
	reference := p.Reference
	if proof {
		reference += ".dns"
	}
	flow, err := c.BeginEnterpriseFlow(p.ProviderID, reference, cfg.RedirectURL, signup)
	if err != nil {
		return nil, err
	}
	opts = append(opts, oauth2.SetAuthURLParam("nonce", flow.Nonce))
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
		return nil, err
	}
	for key, values := range target.Query() {
		fixed[key] = values
	}
	target.RawQuery = fixed.Encode()
	return map[string]any{"url": target.String(), "redirect": true}, nil
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
	if idp.ClientID == "" || idp.ClientSecret == "" || idp.Issuer != "" && idp.Issuer != p.Issuer {
		return cfg, apiError(400, "Invalid persisted OpenID Connect configuration")
	}
	style := oauth2.AuthStyleInHeader
	switch idp.TokenEndpointAuthentication {
	case "", "client_secret_basic":
	case "client_secret_post":
		style = oauth2.AuthStyleInParams
	default:
		return cfg, apiError(400, "Unsupported OpenID Connect client authentication method")
	}
	uri, err := callbackURI(c, p.ProviderID, o.SharedCallback)
	if err != nil {
		return cfg, err
	}
	scopes := idp.Scopes
	if scopes == nil {
		scopes = []string{"openid", "email", "profile", "offline_access"}
	}
	return oauth2.Config{ClientID: idp.ClientID, ClientSecret: idp.ClientSecret, RedirectURL: uri, Scopes: scopes, Endpoint: oauth2.Endpoint{AuthURL: idp.AuthorizationEndpoint, TokenURL: idp.TokenEndpoint, AuthStyle: style}}, nil
}
func (o Options) finish(c auth.EndpointContext) (any, error) {
	store, ok := c.Store().(BrowserStore)
	if !ok {
		return nil, apiError(501, "The configured store does not support enterprise sign-in")
	}
	flow, err := c.ConsumeEnterpriseFlow()
	if err != nil {
		var ae *auth.APIError
		if errors.As(err, &ae) {
			return c.Redirect(strings.TrimSuffix(c.Auth.BasePath(), "/") + "/error?error=invalid_state")
		}
		return nil, err
	}
	fail := func(code string) (any, error) { return enterpriseFailure(c, flow, code) }
	q := c.Request.URL.Query()
	if q.Get("error") != "" || q.Get("code") == "" {
		return fail("invalid_request")
	}
	p, err := store.FindBrowserProvider(c.Request.Context(), Selector{ProviderID: flow.Provider})
	if errors.Is(err, ErrMissing) {
		return fail("invalid_provider")
	}
	if err != nil {
		return nil, err
	}
	if p.OIDC == nil || !available(c, p) || strings.TrimSuffix(flow.ProviderReference, ".dns") != p.Reference {
		return fail("invalid_state")
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
	token, err := cfg.Exchange(ctx, q.Get("code"), params...)
	if err != nil {
		return fail("invalid_grant")
	}
	profile, err := resolveIdentity(ctx, client, p, token, flow.Nonce)
	if err != nil {
		return fail("invalid_provider")
	}
	idToken, _ := token.Extra("id_token").(string)
	scope, _ := token.Extra("scope").(string)
	tokens := auth.OAuthTokens{AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, IDToken: idToken, Scope: strings.Join(strings.Fields(scope), ","), ExpiresAt: token.Expiry}
	complete := func(ctx context.Context, id, sub string, t auth.OAuthTokens, u auth.User, s auth.StoredSession, opts auth.OAuthLoginOptions) (auth.User, bool, error) {
		if proof {
			return store.(DomainStore).CompleteVerifiedEnterpriseLogin(ctx, p.Reference, !o.DisableOrganizationProvisioning, id, sub, t, u, s, opts)
		}
		return store.CompleteEnterpriseLogin(ctx, p.Reference, !o.DisableOrganizationProvisioning, id, sub, t, u, s, opts)
	}
	result, err := c.CompleteEnterpriseFlow(flow, profile, tokens, o.DisableImplicitSignUp && !flow.RequestSignUp, complete)
	if errors.Is(err, ErrDomainUnverified) {
		return nil, err
	}
	if errors.Is(err, auth.ErrOAuthLinkRequired) {
		return fail("account_not_linked")
	}
	if errors.Is(err, ErrChanged) {
		return fail("SSO_PROVIDER_CHANGED")
	}
	var ae *auth.APIError
	if errors.As(err, &ae) {
		if ae.Code == "SIGN_UP_DISABLED" {
			return fail("signup_disabled")
		}
		return fail("access_denied")
	}
	return result, err
}

func enterpriseFailure(c auth.EndpointContext, flow auth.OAuthFlow, code string) (any, error) {
	target := flow.ErrorCallbackURL
	if target == "" {
		target = flow.CallbackURL
	}
	u, e := url.Parse(target)
	if e != nil {
		return nil, e
	}
	v := u.Query()
	v.Set("error", code)
	u.RawQuery = v.Encode()
	return c.Redirect(u.String())
}
