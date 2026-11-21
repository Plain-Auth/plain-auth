// Package sso administers persisted enterprise OpenID Connect providers.
package sso

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	auth "github.com/Stonewrit/stonewrit-auth"
	"golang.org/x/net/idna"
)

type Options struct {
	// GuardProviderMutation can reject a deletion after the exact provider and
	// its authorization have been checked inside the store transaction.
	GuardProviderMutation MutationGuard
	// SharedCallback registers the same /sso/callback URL for every enterprise client.
	SharedCallback bool
	// DisableImplicitSignUp requires requestSignUp before creating an account.
	DisableImplicitSignUp bool
	// DisableOrganizationProvisioning leaves membership management to the application.
	DisableOrganizationProvisioning bool
	// A nil ProvidersLimit allows ten registrations per creator. Zero disables registration.
	ProvidersLimit *int
	// HTTPClient supplies discovery transport and optional TLS settings.
	HTTPClient *http.Client
}

type Config struct {
	Issuer                      string         `json:"issuer,omitempty"`
	ClientID                    string         `json:"clientId"`
	ClientSecret                string         `json:"clientSecret"`
	AuthorizationEndpoint       string         `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint               string         `json:"tokenEndpoint,omitempty"`
	JWKSEndpoint                string         `json:"jwksEndpoint,omitempty"`
	UserInfoEndpoint            string         `json:"userInfoEndpoint,omitempty"`
	DiscoveryEndpoint           string         `json:"discoveryEndpoint,omitempty"`
	TokenEndpointAuthentication string         `json:"tokenEndpointAuthentication,omitempty"`
	PKCE                        *bool          `json:"pkce,omitempty"`
	Scopes                      []string       `json:"scopes,omitempty"`
	Mapping                     map[string]any `json:"mapping,omitempty"`
	OverrideUserInfo            bool           `json:"overrideUserInfo"`
}

type Provider struct {
	ID             string  `json:"id"`
	ProviderID     string  `json:"providerId"`
	Issuer         string  `json:"issuer"`
	Domain         string  `json:"domain"`
	UserID         string  `json:"userId"`
	OrganizationID *string `json:"organizationId,omitempty"`
	OIDC           *Config `json:"oidcConfig"`
}

type Registered struct {
	Provider
	RedirectURI string `json:"redirectURI"`
	SAMLConfig  any    `json:"samlConfig"`
}

type PublicConfig struct {
	ClientIDLastFour            string   `json:"clientIdLastFour"`
	DiscoveryEndpoint           string   `json:"discoveryEndpoint,omitempty"`
	AuthorizationEndpoint       string   `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint               string   `json:"tokenEndpoint,omitempty"`
	JWKSEndpoint                string   `json:"jwksEndpoint,omitempty"`
	UserInfoEndpoint            string   `json:"userInfoEndpoint,omitempty"`
	TokenEndpointAuthentication string   `json:"tokenEndpointAuthentication,omitempty"`
	PKCE                        *bool    `json:"pkce,omitempty"`
	Scopes                      []string `json:"scopes,omitempty"`
}
type PublicProvider struct {
	ProviderID     string        `json:"providerId"`
	Type           string        `json:"type"`
	Issuer         string        `json:"issuer"`
	Domain         string        `json:"domain"`
	OrganizationID *string       `json:"organizationId"`
	DomainVerified bool          `json:"domainVerified"`
	OIDC           *PublicConfig `json:"oidcConfig,omitempty"`
	SPMetadataURL  string        `json:"spMetadataUrl"`
}

type Actor struct {
	UserID, SessionID string
	SessionToken      string `json:"-"`
}
type Store interface {
	CheckSSORegistration(context.Context, Actor, Provider, int) error
	CreateSSOProvider(context.Context, Actor, Provider, int) error
	ReadSSOProviders(context.Context, Actor, string) ([]Provider, error)
}

var (
	ErrUnauthenticated = apiError(401, "Unauthorized")
	ErrLimit           = apiError(403, "You have reached the maximum number of SSO providers")
	ErrDisabled        = apiError(403, "SSO provider registration is disabled")
	ErrDuplicate       = apiError(422, "SSO provider with this providerId already exists")
	ErrForbidden       = apiError(403, "You don't have access to this provider")
	ErrNotMember       = apiError(400, "You are not a member of the organization")
	ErrOrgRole         = apiError(403, "You must be an organization owner or admin to register SSO providers")
	ErrMissing         = apiError(404, "Provider not found")
)

func apiError(status int, text string) *auth.APIError {
	return &auth.APIError{Status: status, Message: text}
}

var slug = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var label = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var reserved = []string{"credential", "email-otp", "magic-link", "phone-number", "anonymous", "siwe"}

func domains(value string) (string, error) {
	var list []string
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, err := idna.Lookup.ToASCII(strings.ToLower(entry))
		if err != nil || len(name) > 253 || !strings.Contains(name, ".") {
			return "", apiError(400, "Invalid provider domain")
		}
		for _, part := range strings.Split(name, ".") {
			if !label.MatchString(part) {
				return "", apiError(400, "Invalid provider domain")
			}
		}
		if !slices.Contains(list, name) {
			list = append(list, name)
		}
	}
	out := strings.Join(list, ",")
	if out == "" || len(out) > 255 {
		return "", apiError(400, "Invalid provider domain")
	}
	return out, nil
}

// New registers the provider management routes under the auth mount.
func New(o Options) (auth.Plugin, error) {
	limit := 10
	if o.ProvidersLimit != nil {
		limit = *o.ProvidersLimit
	}
	if limit < 0 {
		return auth.Plugin{}, errors.New("sso: provider limit must be nonnegative")
	}
	type operation func(auth.EndpointContext, Store, Actor) (any, error)
	endpoint := func(path, method string, fn operation) auth.Endpoint {
		return auth.Endpoint{Path: path, Method: method, Handler: func(c auth.EndpointContext) (any, error) {
			session, err := c.Auth.GetSession(c.Request.Context(), c.Request.Header)
			if err != nil {
				return nil, err
			}
			if session == nil {
				return nil, ErrUnauthenticated
			}
			actor := Actor{UserID: session.User.ID, SessionID: session.Session.ID}
			if method == http.MethodPost {
				if err := session.Session.RequireOwner(); err != nil {
					return nil, err
				}
				actor.SessionToken = session.Session.Token
			} else if session.Session.IsApplicationCredential() {
				return nil, ErrUnauthenticated
			}
			return fn(c, c.Store().(Store), actor)
		}}
	}
	register := func(c auth.EndpointContext, store Store, actor Actor) (any, error) {
		if limit == 0 {
			return nil, ErrDisabled
		}
		oidc, ok := c.Body["oidcConfig"].(map[string]any)
		if !ok || c.Body["samlConfig"] != nil {
			return nil, apiError(400, "Supply an OpenID Connect configuration")
		}
		id, _ := c.Body["providerId"].(string)
		if !slug.MatchString(id) || strings.Contains(id, "..") {
			return nil, apiError(400, "Invalid providerId")
		}
		if slices.Contains(reserved, strings.ToLower(id)) || c.Auth.HasOAuthProvider(id) {
			return nil, apiError(422, "This providerId is reserved and cannot be used for an SSO provider")
		}
		domain, _ := c.Body["domain"].(string)
		domain, err := domains(domain)
		if err != nil {
			return nil, err
		}
		issuer, _ := c.Body["issuer"].(string)
		if _, err = endpointURL(issuer); err != nil {
			return nil, err
		}
		p := Provider{ID: rand.Text(), ProviderID: id, Issuer: issuer, Domain: domain, UserID: actor.UserID}
		if org, ok := c.Body["organizationId"]; ok {
			id, ok := org.(string)
			if !ok || id == "" || len(id) > 255 {
				return nil, ErrNotMember
			}
			p.OrganizationID = &id
		}
		ctx := c.Request.Context()
		if err = store.CheckSSORegistration(ctx, actor, p, limit); err != nil {
			return nil, err
		}
		raw, err := json.Marshal(oidc)
		if err != nil {
			return nil, apiError(400, "Invalid OpenID Connect configuration")
		}
		var cfg Config
		if err = json.Unmarshal(raw, &cfg); err != nil || cfg.ClientID == "" || cfg.ClientSecret == "" {
			return nil, apiError(400, "OpenID Connect client credentials are required")
		}
		cfg.Issuer = issuer
		if cfg.PKCE == nil {
			enabled := true
			cfg.PKCE = &enabled
		}
		if override, ok := c.Body["overrideUserInfo"]; ok {
			v, ok := override.(bool)
			if !ok {
				return nil, apiError(400, "Invalid overrideUserInfo")
			}
			cfg.OverrideUserInfo = v
		}
		skip := false
		if v, ok := oidc["skipDiscovery"]; ok {
			var valid bool
			skip, valid = v.(bool)
			if !valid {
				return nil, apiError(400, "Invalid skipDiscovery")
			}
		}
		if err = hydrate(ctx, c.Auth, o.HTTPClient, &cfg, skip); err != nil {
			return nil, err
		}
		p.OIDC = &cfg
		if err = store.CreateSSOProvider(ctx, actor, p, limit); err != nil {
			return nil, err
		}
		callback, err := callbackURI(c, id, o.SharedCallback)
		if err != nil {
			return nil, err
		}
		return Registered{Provider: p, RedirectURI: callback}, nil
	}
	read := func(c auth.EndpointContext, store Store, actor Actor) (any, error) {
		id := ""
		single := strings.HasSuffix(c.Request.URL.Path, "/get-provider")
		if single {
			id = c.Request.URL.Query().Get("providerId")
			if id == "" {
				return nil, apiError(400, "providerId is required")
			}
		}
		list, err := store.ReadSSOProviders(c.Request.Context(), actor, id)
		if err != nil {
			return nil, err
		}
		out := make([]PublicProvider, 0, len(list))
		for _, p := range list {
			out = append(out, sanitized(c, p))
		}
		if single {
			if len(out) != 1 {
				return nil, ErrMissing
			}
			return out[0], nil
		}
		return map[string]any{"providers": out}, nil
	}
	return auth.Plugin{ID: "sso", ValidateStore: func(s auth.Store) error {
		if _, ok := s.(Store); !ok {
			return errors.New("sso: provider management requires a directory store")
		}
		return nil
	}, Endpoints: []auth.Endpoint{endpoint("/sso/register", "POST", register), endpoint("/sso/providers", "GET", read), endpoint("/sso/get-provider", "GET", read), endpoint("/sso/delete-provider", "POST", o.deleteProvider),
		{Method: "POST", Path: "/sign-in/sso", Handler: o.start},
		{Method: "GET", Path: "/sso/callback", Handler: o.finish},
		{Method: "GET", Path: "/sso/callback/:providerId", Handler: o.finish}}}, nil
}

func sanitized(c auth.EndpointContext, p Provider) PublicProvider {
	metadata, _ := c.Auth.CallbackURL(strings.TrimRight(c.Auth.BasePath(), "/") + "/sso/saml2/sp/metadata?providerId=" + url.QueryEscape(p.ProviderID))
	out := PublicProvider{ProviderID: p.ProviderID, Issuer: p.Issuer, Domain: p.Domain, OrganizationID: p.OrganizationID, Type: "oidc", SPMetadataURL: metadata}
	if cfg := p.OIDC; cfg != nil {
		masked := "****"
		if utf8.RuneCountInString(cfg.ClientID) > 4 {
			r := []rune(cfg.ClientID)
			masked += string(r[len(r)-4:])
		}
		out.OIDC = &PublicConfig{ClientIDLastFour: masked, DiscoveryEndpoint: cfg.DiscoveryEndpoint, AuthorizationEndpoint: cfg.AuthorizationEndpoint, TokenEndpoint: cfg.TokenEndpoint, JWKSEndpoint: cfg.JWKSEndpoint, UserInfoEndpoint: cfg.UserInfoEndpoint, TokenEndpointAuthentication: cfg.TokenEndpointAuthentication, PKCE: cfg.PKCE, Scopes: cfg.Scopes}
	}
	return out
}
