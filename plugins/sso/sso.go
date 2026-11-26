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

	auth "github.com/Plain-Org/plain-auth"
	"golang.org/x/net/idna"
)

type Options struct {
	// SAML enables service-provider initiated sign-in with signed assertions.
	SAML *SAMLOptions
	// DomainVerification enables DNS ownership checks for managed OIDC domains.
	DomainVerification *DomainVerificationOptions
	// GuardProviderMutation reviews a provider deletion, SAML metadata
	// replacement or general update after the exact provider and its
	// authorization are checked. It runs outside the store's transaction on a
	// snapshot of the locked provider and its linked accounts, and the store
	// commits only if it locks the same snapshot again, asking again up to
	// three times. Keep it free of side effects; an error denies the
	// operation and nothing is written.
	GuardProviderMutation MutationGuard
	// SharedCallback registers the same /sso/callback URL for every enterprise client.
	// The shared callback is always {basePath}/sso/callback; another runtime
	// also accepts another path or a full URL.
	SharedCallback bool
	// DisableImplicitSignUp requires requestSignUp before creating an account.
	DisableImplicitSignUp bool
	// DefaultOverrideUserInfo stores overrideUserInfo on every new OIDC
	// registration, whatever the request says.
	DefaultOverrideUserInfo bool
	// DisableOrganizationProvisioning leaves membership management to the application.
	DisableOrganizationProvisioning bool
	// A nil ProvidersLimit allows ten registrations per creator. Zero disables registration.
	ProvidersLimit *int
	// ResolveProvidersLimit returns how many providers the signed-in user may
	// register, in place of ProvidersLimit. Zero refuses that user's
	// registrations with 403 and a negative number counts as reached. It runs
	// before the store's transaction; an error fails the registration.
	ResolveProvidersLimit func(context.Context, auth.User) (int, error)
	// ResolvePrivateKey supplies the signing key for a provider whose
	// tokenEndpointAuthentication is private_key_jwt. It runs before each
	// token request, outside any store transaction. Without it,
	// registration refuses private_key_jwt.
	ResolvePrivateKey func(context.Context, PrivateKeyRequest) (PrivateKey, error)
	// AllowIDPInitiatedOIDC restarts a callback that reaches
	// /sso/callback/{providerId} with a code and no state, for providers it
	// approves. The code is discarded and a new authorization with a fresh
	// state, nonce and PKCE verifier starts, returning to the host root. It
	// runs outside any store transaction and cannot request sign-up.
	// Another runtime enables this on providers defined in code; without
	// them the host approves stored registrations.
	AllowIDPInitiatedOIDC OIDCDirectoryPolicy
	// ResolveUser maps every verified enterprise identity to a user:
	// continue by the built-in rules, link it to a chosen user or reject the
	// sign-in. It runs after the protocol identity is verified and before the
	// sign-in transaction, never inside it, so it may read through the store
	// or the application's database; the store then locks the chosen user
	// and the identity and refuses a decision they no longer allow. With it,
	// every OIDC sign-in needs an ID token. It needs a store implementing
	// UserResolutionStore.
	ResolveUser func(context.Context, UserResolutionInput) (UserResolution, error)
	// ProvisionUser runs after an enterprise sign-in creates a user and its
	// account, outside any transaction and before the session cookie is set.
	// An *auth.APIError is the response and any other error, or a panic,
	// answers 500;
	// either way the session is removed, the user stays and, without
	// ProvisionUserOnEveryLogin, the callback does not run for that user
	// again.
	ProvisionUser func(context.Context, Provisioning) error
	// ProvisionUserOnEveryLogin runs ProvisionUser on every enterprise
	// sign-in, not only the one that creates the user. Keep the callback
	// idempotent.
	ProvisionUserOnEveryLogin bool
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
	// PrivateKeyID names the private_key_jwt key: ResolvePrivateKey
	// receives it as KeyID and the assertion carries it as kid.
	PrivateKeyID string `json:"privateKeyId,omitempty"`
	// PrivateKeyAlgorithm signs the private_key_jwt assertion; it defaults
	// to the resolved key's algorithm, then RS256.
	PrivateKeyAlgorithm string `json:"privateKeyAlgorithm,omitempty"`
}

type Provider struct {
	ID             string      `json:"id"`
	ProviderID     string      `json:"providerId"`
	Issuer         string      `json:"issuer"`
	Domain         string      `json:"domain"`
	UserID         string      `json:"userId"`
	OrganizationID *string     `json:"organizationId,omitempty"`
	OIDC           *Config     `json:"oidcConfig"`
	SAML           *SAMLConfig `json:"samlConfig,omitempty"`
}

type Registered struct {
	Provider
	RedirectURI             string `json:"redirectURI"`
	SAMLConfig              any    `json:"samlConfig"`
	DomainVerified          *bool  `json:"domainVerified,omitempty"`
	DomainVerificationToken string `json:"domainVerificationToken,omitempty"`
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
type PublicSAMLConfig struct {
	EntryPoint           string `json:"entryPoint"`
	Audience             string `json:"audience,omitempty"`
	WantAssertionsSigned *bool  `json:"wantAssertionsSigned,omitempty"`
	AuthnRequestsSigned  bool   `json:"authnRequestsSigned,omitempty"`
	IdentifierFormat     string `json:"identifierFormat,omitempty"`
	SignatureAlgorithm   string `json:"signatureAlgorithm,omitempty"`
	DigestAlgorithm      string `json:"digestAlgorithm,omitempty"`
}

type PublicProvider struct {
	SAML           *PublicSAMLConfig `json:"samlConfig,omitempty"`
	ProviderID     string            `json:"providerId"`
	Type           string            `json:"type"`
	Issuer         string            `json:"issuer"`
	Domain         string            `json:"domain"`
	OrganizationID *string           `json:"organizationId"`
	DomainVerified bool              `json:"domainVerified"`
	OIDC           *PublicConfig     `json:"oidcConfig,omitempty"`
	SPMetadataURL  string            `json:"spMetadataUrl"`
}

type Actor struct {
	UserID, SessionID string
	SessionToken      string `json:"-"`
	user              auth.User
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
	if o.SAML != nil {
		v := *o.SAML
		v.Algorithms.AllowedSignatureAlgorithms = slices.Clone(v.Algorithms.AllowedSignatureAlgorithms)
		v.Algorithms.AllowedDigestAlgorithms = slices.Clone(v.Algorithms.AllowedDigestAlgorithms)
		if v.Encryption != nil {
			keys := *v.Encryption
			v.Encryption = &keys
		}
		if err := v.validate(); err != nil {
			return auth.Plugin{}, err
		}
		o.SAML = &v
	}
	if o.DomainVerification != nil {
		cfg, err := o.DomainVerification.normalized()
		if err != nil {
			return auth.Plugin{}, err
		}
		o.DomainVerification = &cfg
	}
	limit := 10
	if o.ProvidersLimit != nil {
		limit = *o.ProvidersLimit
	}
	if limit < 0 {
		return auth.Plugin{}, errors.New("sso: provider limit must be nonnegative")
	}
	if o.ProvidersLimit != nil && o.ResolveProvidersLimit != nil {
		return auth.Plugin{}, errors.New("sso: choose ProvidersLimit or ResolveProvidersLimit")
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
			actor := Actor{UserID: session.User.ID, SessionID: session.Session.ID, user: session.User}
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
		limit, err := o.providerLimit(c.Request.Context(), actor.user, limit)
		if err != nil {
			return nil, err
		}
		if limit == 0 {
			return nil, ErrDisabled
		}
		oidc, ok := c.Body["oidcConfig"].(map[string]any)
		samlInput, usesSAML := c.Body["samlConfig"].(map[string]any)
		if (usesSAML && (ok || o.SAML == nil)) || (!usesSAML && (!ok || c.Body["samlConfig"] != nil)) {
			return nil, apiError(400, "Supply an OpenID Connect configuration")
		}
		id, _ := c.Body["providerId"].(string)
		if !slug.MatchString(id) || strings.Contains(id, "..") {
			return nil, apiError(400, "Invalid providerId")
		}
		// A trusted provider ID would let this tenant's identities link by name.
		trusted, trustErr := c.Auth.TrustedProviderIDs(c.Request)
		if trustErr != nil {
			return nil, trustErr
		}
		if slices.Contains(reserved, strings.ToLower(id)) || c.Auth.HasOAuthProvider(id) || slices.ContainsFunc(trusted, func(t string) bool { return strings.EqualFold(t, id) }) {
			return nil, apiError(422, "This providerId is reserved and cannot be used for an SSO provider")
		}
		domain, _ := c.Body["domain"].(string)
		domain, err = domains(domain)
		if err != nil {
			return nil, err
		}
		if opt := o.DomainVerification; opt != nil {
			if _, err := DomainTargets(id, opt.identifier(id), domain); err != nil {
				return nil, err
			}
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
		if usesSAML {
			if input, ok := samlInput["idpMetadata"].(map[string]any); ok {
				if doc, ok := input["metadata"].(string); ok && len(doc) > o.SAML.metadataLimit() {
					return nil, ErrInvalidSAML
				}
			}
			raw, e := json.Marshal(samlInput)
			if e != nil {
				return nil, ErrInvalidSAML
			}
			p.SAML, e = DecodeSAMLConfig(raw)
			if e != nil {
				return nil, ErrInvalidSAML
			}
			if e = o.SAML.Algorithms.checkConfig(*p.SAML); e != nil {
				return nil, e
			}
			p.SAML.Issuer = issuer
			if _, e = o.samlSP(c, p); e != nil {
				return nil, e
			}
		} else {
			raw, err := json.Marshal(oidc)
			if err != nil {
				return nil, apiError(400, "Invalid OpenID Connect configuration")
			}
			var cfg Config
			if err = json.Unmarshal(raw, &cfg); err != nil || cfg.ClientID == "" {
				return nil, apiError(400, "OpenID Connect client credentials are required")
			}
			if !validMapping(cfg.Mapping) {
				return nil, apiError(400, "Invalid OpenID Connect mapping")
			}
			// Only the top-level overrideUserInfo counts, as in another runtime.
			cfg.OverrideUserInfo = o.DefaultOverrideUserInfo
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
				cfg.OverrideUserInfo = v || o.DefaultOverrideUserInfo
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
			if err = o.checkClientAuth(&cfg); err != nil {
				return nil, err
			}
			p.OIDC = &cfg
		}
		var result Registered
		if opt := o.DomainVerification; opt != nil {
			// The store asks the request's gate before storing the token, so its
			// verification hooks run outside the store's transaction.
			err = c.GateVerifications(func(ctx context.Context) (err error) {
				result.DomainVerificationToken, err = store.(DomainStore).CreateSSODomainProvider(ctx, actor, p, limit, opt.identifier(id))
				return err
			})
			verified := false
			result.DomainVerified = &verified
		} else {
			err = store.CreateSSOProvider(ctx, actor, p, limit)
		}
		if err != nil {
			return nil, err
		}
		callback, err := callbackURI(c, id, o.SharedCallback)
		if err != nil {
			return nil, err
		}
		if p.SAML != nil {
			result.SAMLConfig = p.SAML
		}
		result.Provider = p
		result.RedirectURI = callback
		return result, nil
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
			public := sanitized(c, p)
			_, public.DomainVerified, err = o.domainStatus(c.Request.Context(), store, p, "")
			if err != nil {
				return nil, err
			}
			out = append(out, public)
		}
		if single {
			if len(out) != 1 {
				return nil, ErrMissing
			}
			return out[0], nil
		}
		return map[string]any{"providers": out}, nil
	}
	callback := auth.Endpoint{Method: "GET", Path: "/sso/callback/:providerId", Handler: o.finish}
	if o.AllowIDPInitiatedOIDC != nil {
		callback.OpenAPI = json.RawMessage(`{"x-plainauth-idp-initiated":true}`)
	}
	plugin := auth.Plugin{ID: "sso", ValidateStore: func(s auth.Store) error {
		if _, ok := s.(Store); !ok {
			return errors.New("sso: provider management requires a directory store")
		}
		if _, ok := s.(UserResolutionStore); o.ResolveUser != nil && !ok {
			return errors.New("sso: ResolveUser requires a store implementing UserResolutionStore")
		}
		if o.SAML != nil {
			if o.SAML.EnableIDPInitiatedLogout {
				if _, ok := s.(SAMLIDPLogoutStore); !ok {
					return errors.New("sso: IdP-initiated logout requires a directory session revocation store")
				}
			}
			if o.SAML.EnableSingleLogout {
				if _, ok := s.(SAMLLogoutStore); !ok {
					return errors.New("sso: SAML single logout requires a logout session store")
				}
			}
			if _, ok := s.(SAMLStore); !ok {
				return errors.New("sso: SAML requires a browser and assertion receipt store")
			}
		}
		if o.DomainVerification != nil {
			ds, ok := s.(DomainStore)
			if !ok {
				return errors.New("sso: DNS verification requires a domain verification store")
			}
			return ds.CheckSSODomainSchema(context.Background())
		}
		return nil
	}, Endpoints: []auth.Endpoint{endpoint("/sso/register", "POST", register), endpoint("/sso/providers", "GET", read), endpoint("/sso/get-provider", "GET", read), endpoint("/sso/delete-provider", "POST", o.deleteProvider), endpoint("/sso/update-provider", "POST", o.updateProvider),
		{Method: "POST", Path: "/sign-in/sso", Handler: o.start},
		{Method: "GET", Path: "/sso/callback", Handler: o.finish},
		callback}}
	if opt := o.DomainVerification; opt != nil {
		request := endpoint("/sso/request-domain-verification", "POST", opt.request)
		request.SuccessStatus = 201
		verify := endpoint("/sso/verify-domain", "POST", opt.verify)
		verify.SuccessStatus = 204
		plugin.Endpoints = append(plugin.Endpoints, request, verify)
	}
	if o.SAML != nil {
		if o.SAML.EnableSingleLogout {
			slo := auth.Endpoint{Path: "/sso/saml2/sp/slo/:providerId", Method: "GET", Handler: o.finishLogout}
			if o.SAML.EnableIDPInitiatedLogout {
				slo.OpenAPI = json.RawMessage(`{"x-plainauth-idp-logout":true}`)
			}
			plugin.Endpoints = append(plugin.Endpoints, endpoint("/sso/saml2/logout/:providerId", "POST", o.startLogout), slo)
		}
		acs := auth.Endpoint{Method: "POST", Path: "/sso/saml2/sp/acs/:providerId", RawBody: true, Handler: o.samlFinish}
		if o.SAML.AllowIDPInitiated != nil {
			acs.OpenAPI = json.RawMessage(`{"x-plainauth-idp-initiated":true}`)
		}
		plugin.Endpoints = append(plugin.Endpoints, auth.Endpoint{Method: "GET", Path: "/sso/saml2/sp/metadata", Handler: o.samlMetadata}, acs)
	}
	plugin.ValidateVerificationStore = func(s auth.Store, hooks auth.VerificationHookSet) error {
		// A logout binding or request and a domain token are written inside the
		// store's transactions, which must ask the request's gate. A store
		// without the base interface gets ValidateStore's error instead.
		_, slo := s.(SAMLLogoutStore)
		_, dns := s.(DomainStore)
		logout := o.SAML != nil && o.SAML.EnableSingleLogout && slo
		domain := o.DomainVerification != nil && dns
		if o.SAML != nil && o.SAML.EnableSingleLogout && hooks.UpdateBefore {
			return errors.New("auth: verification update before hooks cannot run with SAML single logout, whose session renewal extends a logout binding inside the store; use the update after hooks")
		}
		if _, ok := s.(VerificationGater); (logout || domain) && !ok {
			return errors.New("auth: verification hooks with SAML single logout or SSO domain verification require a store implementing GatesSSOVerifications")
		}
		return nil
	}
	return plugin, nil
}

func sanitized(c auth.EndpointContext, p Provider) PublicProvider {
	metadata, _ := c.CallbackURL(strings.TrimRight(c.Auth.BasePath(), "/") + "/sso/saml2/sp/metadata?providerId=" + url.QueryEscape(p.ProviderID))
	out := PublicProvider{ProviderID: p.ProviderID, Issuer: p.Issuer, Domain: p.Domain, OrganizationID: p.OrganizationID, Type: "oidc", SPMetadataURL: metadata}
	if p.SAML != nil {
		out.Type = "saml"
		out.SAML = &PublicSAMLConfig{EntryPoint: p.SAML.EntryPoint, Audience: p.SAML.Audience, WantAssertionsSigned: p.SAML.WantAssertionsSigned, AuthnRequestsSigned: p.SAML.AuthnRequestsSigned, IdentifierFormat: p.SAML.IdentifierFormat, SignatureAlgorithm: p.SAML.SignatureAlgorithm, DigestAlgorithm: p.SAML.DigestAlgorithm}
	}
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

// providerLimit resolves the signed-in user's registration quota before the
// store's transaction, so the host's resolver never runs inside it.
func (o Options) providerLimit(ctx context.Context, user auth.User, fixed int) (int, error) {
	if o.ResolveProvidersLimit == nil {
		return fixed, nil
	}
	n, err := o.ResolveProvidersLimit(ctx, user)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, ErrLimit
	}
	return n, nil
}

// validMapping reports whether an OIDC claim mapping has only the email,
// emailVerified, name and image claim names and extraFields from user field
// names to claim names.
func validMapping(m map[string]any) bool {
	for key, value := range m {
		switch key {
		case "email", "emailVerified", "name", "image":
			if _, ok := value.(string); !ok {
				return false
			}
		case "extraFields":
			// Require claim names; another runtime accepts any value and
			// indexes the claims with it.
			fields, ok := value.(map[string]any)
			if !ok {
				return false
			}
			for _, claim := range fields {
				if _, ok := claim.(string); !ok {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}
