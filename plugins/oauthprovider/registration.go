package oauthprovider

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/jsjson"
)

// RegistrationMetadata is the client-supplied portion of an RFC 7591 registration.
// Server-assigned identifiers, owner, credentials, and administrative permissions are separate.
type RegistrationMetadata struct {
	RedirectURIs                     []string        `json:"redirect_uris,omitzero"`
	Scope                            string          `json:"scope,omitempty"`
	Name                             *string         `json:"client_name,omitempty"`
	URI                              *string         `json:"client_uri,omitempty"`
	LogoURI                          *string         `json:"logo_uri,omitempty"`
	Contacts                         []string        `json:"contacts,omitzero"`
	TermsURI                         *string         `json:"tos_uri,omitempty"`
	PolicyURI                        *string         `json:"policy_uri,omitempty"`
	SoftwareID                       *string         `json:"software_id,omitempty"`
	SoftwareVersion                  *string         `json:"software_version,omitempty"`
	SoftwareStatement                *string         `json:"software_statement,omitempty"`
	PostLogoutRedirectURIs           []string        `json:"post_logout_redirect_uris,omitzero"`
	BackchannelLogoutURI             *string         `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired *bool           `json:"backchannel_logout_session_required,omitempty"`
	TokenEndpointAuthMethod          string          `json:"token_endpoint_auth_method,omitempty"`
	JWKS                             json.RawMessage `json:"jwks,omitempty"`
	JWKSURI                          *string         `json:"jwks_uri,omitempty"`
	GrantTypes                       []string        `json:"grant_types,omitzero"`
	ResponseTypes                    []string        `json:"response_types,omitzero"`
	ApplicationType                  string          `json:"application_type,omitempty"`
	SubjectType                      string          `json:"subject_type,omitempty"`
	DPoPBoundAccessTokens            *bool           `json:"dpop_bound_access_tokens,omitempty"`
	Resources                        []string        `json:"resources,omitempty"`
}

// RegisteredClient is returned once to the registering application. ClientSecret
// contains the issued secret only for clients using shared-secret authentication.
type RegisteredClient struct {
	RegistrationMetadata
	ClientID        string `json:"client_id"`
	ClientSecret    string `json:"client_secret,omitempty"`
	SecretExpiresAt *int64 `json:"client_secret_expires_at,omitempty"`
	IssuedAt        int64  `json:"client_id_issued_at"`
	UserID          string `json:"user_id,omitempty"`
	ReferenceID     string `json:"reference_id,omitempty"`
	RequirePKCE     *bool  `json:"require_pkce,omitempty"`
	Disabled        bool   `json:"disabled"`
	// managed marks a client created without dynamic registration.
	managed bool
}

func (c RegisteredClient) MarshalJSON() ([]byte, error) {
	type record RegisteredClient
	// A client created without a scope leaves it out, as another runtime
	// does; a registration always names its scope.
	if c.managed && c.Scope == "" {
		return json.Marshal(record(c))
	}
	return json.Marshal(struct {
		record
		Scope string `json:"scope"`
	}{record(c), c.Scope})
}

// ClientRegistrationRecord is the trusted storage representation. StoredSecret
// is a digest or the result of the application's secret-storage hook.
type ClientRegistrationRecord struct {
	Metadata                                        RegistrationMetadata
	ID, ClientID, StoredSecret, UserID, ReferenceID string
	Scopes                                          []string
	RequirePKCE                                     *bool
	CreatedAt                                       time.Time
	// The settings below are set only by ClientManager.CreateClient.
	SkipConsent, EnableEndSession *bool
	ClientCredentialsScopes       []string
	// Extensions is the client's metadata object.
	Extensions map[string]json.RawMessage
}

type RegistrationStore interface {
	// CreateRegisteredClient must verify all resource IDs exist and are enabled,
	// and insert the client and every resource link in one transaction.
	CreateRegisteredClient(context.Context, ClientRegistrationRecord) error
}

type RegistrationAccess struct {
	auth.SessionResult
	Headers http.Header
}

// InitialAuthorization attributes a registration to a trusted external owner.
// Return a nil authorization from ValidateInitialToken to reject a token.
type InitialAuthorization struct{ ReferenceID string }

type RegistrationOptions struct {
	Enabled                                bool
	AllowUnauthenticated                   bool
	DefaultScopes, AllowedScopes           []string
	DefaultResources, AllowedResources     []string
	DefaultApplicationType                 string // web (default), native or infer
	RequirePKCE                            *bool
	SecretPrefix                           string
	GenerateClientID, GenerateClientSecret func() (string, error)
	StoreSecret                            func(context.Context, string) (string, error)
	// VerifySecret compares an unprefixed issued secret with its stored representation.
	// Supply this when StoreSecret uses a random salt.
	VerifySecret func(ctx context.Context, raw, stored string) (bool, error)
	// DecryptSecret pairs with a StoreSecret that encrypts: it returns the
	// unprefixed secret for a stored value, which is then compared in
	// constant time.
	DecryptSecret func(ctx context.Context, stored string) (string, error)
	// SecretStorage is "hashed", the default, which stores a digest, or
	// "encrypted", which seals the secret with the auth secret, bound to the
	// client ID, so the issuer can read it back. StoreSecret replaces both.
	SecretStorage        string
	ValidateInitialToken func(context.Context, string, http.Header, RegistrationMetadata) (*InitialAuthorization, error)
	MayCreate            func(context.Context, RegistrationAccess) (bool, error)
	ClientReference      func(context.Context, RegistrationAccess) (string, error)
	AllowHTTPRedirect    func(*url.URL) bool
	// RateLimit applies to registration and defaults to 5 per minute. An
	// empty rule uses the host's global limit.
	RateLimit *auth.RateLimitRule
	// SecretLifetime sets client_secret_expires_at in a registration response
	// that issues a secret, counted from client_id_issued_at in whole
	// seconds. Zero reports a secret that never expires. The value is
	// informational: it is not stored and the secret keeps authenticating.
	SecretLifetime time.Duration
}

type Options struct {
	// ClientPrivileges checks authenticated client management actions. Assigning machine
	// scopes requires an explicit configure-client-credentials-scopes decision.
	ClientPrivileges func(context.Context, ClientAccess) (bool, error)
	// ClientReference resolves the active tenant. It defaults to Registration.ClientReference.
	ClientReference func(context.Context, RegistrationAccess) (string, error)
	// ImmutableClientIDs are operator-managed registrations protected against owner mutations.
	ImmutableClientIDs []string
	Scopes, GrantTypes []string
	PairwiseSecret     string
	Registration       RegistrationOptions
	Tokens             TokenOptions
	Authorization      BrowserAuthorizationOptions
	Assertions         AssertionOptions
	UserInfo           UserInfoOptions
	Metadata           IssuerMetadataOptions
	// DPoP controls sender proofs at the token endpoint. The host SQL store
	// shares reservations automatically when ReplayStore is omitted.
	DPoP DPoPOptions
	// BackchannelTransport sends back-channel logout tokens. The default
	// dials only public addresses, checking every address a logout host
	// resolves to.
	BackchannelTransport http.RoundTripper
	// Extensions add capabilities to the provider, such as discovery fields.
	Extensions []Extension
	// DisableJWTPlugin signs ID tokens with HS256 keyed by the client secret
	// instead of the jwt plugin, which must not be installed. Access tokens
	// stay opaque, clients without a secret get no ID token, and client
	// secrets must be stored encrypted, the default in this mode.
	DisableJWTPlugin bool
	// Resources declares the protected resources this issuer serves. They are
	// seeded into the store on the first request and again before a lookup
	// while a seed has not finished, and registration default and allowed
	// resources must be among them.
	Resources []ResourceDefinition
	// ResourceSeedMode chooses how a declared resource meets an existing row:
	// insert only (the default), merge or overwrite.
	ResourceSeedMode ResourceSeedMode
	// SharedResourceSeeds shares completed seeds with a ResourceManager or
	// another provider using the same database.
	SharedResourceSeeds *ResourceSeedCache
	proofVerifier       *DPoPVerifier
	assertionKeys       *clientKeyCache
	resourceSeeds       *resourceSeeds
	// discoveries are the extensions' client discoveries in order.
	discoveries []*ClientDiscovery
}

// seedResources applies the declared resources once through the request's
// store, retrying a seed that has not finished. Declared identifiers follow
// the standard rule: the provider takes no identifier validator, where
// another runtime's provider does; a ResourceManager takes one.
func (opts Options) seedResources(c auth.EndpointContext) error {
	if opts.resourceSeeds == nil {
		return nil
	}
	store, ok := c.Store().(ResourceStore)
	if !ok {
		return errors.New("oauthprovider: declared resources require a ResourceStore")
	}
	return opts.resourceSeeds.seed(c.Request.Context(), c.Auth, store, opts.SharedResourceSeeds, func(_ context.Context, id string) (bool, error) {
		return ValidResourceIdentifier(id), nil
	})
}

func (opts Options) clientManagementOptions() Options {
	if opts.Scopes == nil {
		opts.Scopes = []string{"openid", "profile", "email", "offline_access"}
	}
	opts.Scopes = distinct(opts.Scopes)
	opts.ImmutableClientIDs = distinct(opts.ImmutableClientIDs)
	if opts.ClientReference == nil {
		opts.ClientReference = opts.Registration.ClientReference
	}
	// Defaults a ClientManager shares with the mounted plugin.
	if opts.GrantTypes == nil {
		opts.GrantTypes = []string{"authorization_code", "client_credentials", "refresh_token"}
	}
	if opts.Registration.GenerateClientID == nil {
		opts.Registration.GenerateClientID = randomClientCredential
	}
	if opts.Registration.GenerateClientSecret == nil {
		opts.Registration.GenerateClientSecret = randomClientCredential
	}
	// As in another runtime, secrets are hashed when the jwt plugin signs ID
	// tokens and encrypted when they are signed with the client secret.
	r := &opts.Registration
	if opts.DisableJWTPlugin && r.SecretStorage == "" && r.StoreSecret == nil {
		r.SecretStorage = "encrypted"
	}
	return opts
}

// checkSecretStorage refuses secret storage settings the token endpoint
// could not verify.
func (opts Options) checkSecretStorage() error {
	r := opts.Registration
	switch {
	case opts.DisableJWTPlugin && (r.SecretStorage == "hashed" || r.StoreSecret != nil && r.DecryptSecret == nil):
		return errors.New("oauthprovider: DisableJWTPlugin signs ID tokens with client secrets, which must be stored encrypted")
	case !opts.DisableJWTPlugin && (r.SecretStorage == "encrypted" || r.DecryptSecret != nil):
		return errors.New("oauthprovider: encrypted client secrets require DisableJWTPlugin")
	case r.SecretStorage != "" && r.SecretStorage != "hashed" && r.SecretStorage != "encrypted":
		return fmt.Errorf("oauthprovider: unknown client secret storage %q", r.SecretStorage)
	case r.StoreSecret != nil && r.SecretStorage == "encrypted":
		return errors.New("oauthprovider: StoreSecret replaces the encrypted secret storage")
	case r.DecryptSecret != nil && r.StoreSecret == nil:
		return errors.New("oauthprovider: DecryptSecret requires StoreSecret")
	case r.DecryptSecret != nil && r.VerifySecret != nil:
		return errors.New("oauthprovider: use DecryptSecret or VerifySecret, not both")
	}
	return nil
}

// New installs the OAuth consent, client management and dynamic registration endpoints.
// Dynamic registration is disabled until the host explicitly enables it.
func New(opts Options) (auth.Plugin, error) {
	opts = opts.clientManagementOptions()
	opts.Extensions = slices.Clone(opts.Extensions)
	opts.UserInfo.Extensions = slices.Clone(opts.UserInfo.Extensions)
	for _, extension := range opts.Extensions {
		if extension.UserInfoClaims != nil {
			opts.UserInfo.Extensions = append(opts.UserInfo.Extensions, extension.UserInfoClaims)
		}
	}
	if err := opts.Authorization.defaults(); err != nil {
		return auth.Plugin{}, err
	}
	if opts.Authorization.RequireOpenID && !slices.Contains(opts.Scopes, "openid") {
		return auth.Plugin{}, errors.New("oauthprovider: RequireOpenID requires openid in Scopes")
	}
	if err := opts.checkClientAuthentication(); err != nil {
		return auth.Plugin{}, err
	}
	if err := opts.checkGrants(); err != nil {
		return auth.Plugin{}, err
	}
	if err := opts.collectDiscoveries(); err != nil {
		return auth.Plugin{}, err
	}
	if err := opts.Metadata.prepare(opts.Scopes, opts.extensionAuthMethods()); err != nil {
		return auth.Plugin{}, err
	}
	if err := opts.Assertions.defaults(); err != nil {
		return auth.Plugin{}, err
	}
	opts.assertionKeys = newClientKeyCache(opts.Assertions.JWKSTransport)
	proofs, err := NewDPoPVerifier(opts.DPoP)
	if err != nil {
		return auth.Plugin{}, err
	}
	opts.proofVerifier = proofs
	opts.DPoP.SigningAlgorithms = slices.Clone(opts.DPoP.SigningAlgorithms)
	opts.UserInfo.SupportedClaims = slices.Clone(opts.UserInfo.SupportedClaims)
	for _, extension := range opts.UserInfo.Extensions {
		if extension == nil {
			return auth.Plugin{}, errors.New("oauthprovider: nil UserInfo claim extension")
		}
	}
	if opts.GrantTypes == nil {
		opts.GrantTypes = []string{"authorization_code", "client_credentials", "refresh_token"}
	}
	opts.GrantTypes = distinct(opts.GrantTypes)
	if slices.Contains(opts.Metadata.TokenAuthMethods, "none") && !slices.Contains(opts.GrantTypes, "authorization_code") {
		return auth.Plugin{}, errors.New("oauthprovider: public client authentication requires a delegated grant")
	}
	if slices.Contains(opts.GrantTypes, "refresh_token") && !slices.Contains(opts.GrantTypes, "authorization_code") {
		return auth.Plugin{}, errors.New("oauthprovider: refresh_token requires authorization_code")
	}
	if opts.PairwiseSecret != "" && len(opts.PairwiseSecret) < 32 {
		return auth.Plugin{}, errors.New("oauthprovider: pairwise secret must contain at least 32 bytes")
	}
	r := &opts.Registration
	if err := opts.Tokens.defaults(); err != nil {
		return auth.Plugin{}, err
	}
	switch r.DefaultApplicationType {
	case "":
		r.DefaultApplicationType = "web"
	case "web", "native", "infer":
	default:
		return auth.Plugin{}, errors.New("oauthprovider: invalid default application type")
	}
	if r.DefaultScopes == nil {
		r.DefaultScopes = opts.Scopes
	}
	r.DefaultScopes = distinct(r.DefaultScopes)
	r.AllowedScopes = distinct(slices.Concat(r.DefaultScopes, r.AllowedScopes))
	for _, sc := range r.AllowedScopes {
		if !slices.Contains(opts.Scopes, sc) {
			return auth.Plugin{}, fmt.Errorf("oauthprovider: registration scope %q is outside the configured scopes", sc)
		}
	}
	// As in another runtime, registration resources must be declared.
	declared := map[string]bool{}
	for _, d := range opts.Resources {
		declared[d.Identifier] = true
	}
	for _, list := range []struct {
		name string
		ids  []string
	}{{"default", r.DefaultResources}, {"allowed", r.AllowedResources}} {
		for _, id := range list.ids {
			if !declared[id] {
				return auth.Plugin{}, fmt.Errorf("oauthprovider: registration %s resource %q is not declared in Resources", list.name, id)
			}
		}
	}
	seeds, err := prepareResourceSeeds(opts.Resources, opts.ResourceSeedMode)
	if err != nil {
		return auth.Plugin{}, err
	}
	opts.resourceSeeds, opts.Resources = seeds, nil
	r.DefaultResources = distinct(r.DefaultResources)
	r.AllowedResources = distinct(slices.Concat(r.DefaultResources, r.AllowedResources))
	if r.RequirePKCE != nil {
		v := *r.RequirePKCE
		r.RequirePKCE = &v
	}
	if err := opts.checkSecretStorage(); err != nil {
		return auth.Plugin{}, err
	}
	if r.SecretLifetime < 0 || r.SecretLifetime%time.Second != 0 {
		return auth.Plugin{}, errors.New("oauthprovider: registration secret lifetime must be zero or a positive whole number of seconds")
	}
	if r.GenerateClientID == nil {
		r.GenerateClientID = randomClientCredential
	}
	if r.GenerateClientSecret == nil {
		r.GenerateClientSecret = randomClientCredential
	}
	limit := tokenRouteLimit(r.RateLimit, 5)
	p := ConsentManagement(ConsentOptions{Scopes: opts.Scopes, resolve: opts.retryResolved})
	p.WellKnown = opts.issuerDocuments
	p.OnSessionsEnded = opts.sessionsEnded
	validateConsent := p.ValidateStore
	p.ValidateStore = func(s auth.Store) error {
		if _, ok := s.(ClientKeyRotationStore); opts.Assertions.AllowKeyRotation && !ok {
			return errors.New("oauthprovider: client key rotation requires a store with atomic single-use assertions and key replacement")
		}
		if _, ok := s.(BrowserConsentStore); opts.Authorization.ConsentPage != "" && !ok {
			return errors.New("oauthprovider: interactive consent requires a BrowserConsentStore")
		}
		if _, ok := s.(DeferredConsentStore); (opts.Authorization.CheckSignup != nil || opts.Authorization.PostLogin != nil) && opts.Authorization.ConsentPage != "" && !ok {
			return errors.New("oauthprovider: interactive consent with host account checks requires a DeferredConsentStore")
		}
		if err := validateConsent(s); err != nil {
			return err
		}
		if _, ok := s.(RegistrationStore); r.Enabled && !ok {
			return errors.New("oauthprovider: registration requires a RegistrationStore")
		}
		if _, ok := s.(DiscoveredClientStore); len(opts.discoveries) > 0 && !ok {
			return errors.New("oauthprovider: client discoveries require a DiscoveredClientStore")
		}
		if _, ok := s.(OpenIDGrantStore); opts.Tokens.CustomTokenResponseFields != nil && slices.Contains(opts.GrantTypes, "authorization_code") && !ok {
			return errors.New("oauthprovider: token response fields require an OpenIDGrantStore")
		}
		if seeds := opts.resourceSeeds; seeds != nil {
			if _, ok := s.(ResourceStore); !ok {
				return errors.New("oauthprovider: declared resources require a ResourceStore")
			}
			if _, ok := s.(ResourcePolicyReplacer); seeds.mode == SeedOverwrite && !ok {
				return errors.New("oauthprovider: overwrite seeding requires a ResourcePolicyReplacer")
			}
		}
		return nil
	}
	// The declared resources are seeded on the first request to any
	// endpoint, as another runtime seeds them at startup; a failure is
	// logged and retried by the next lookup that needs them.
	if opts.resourceSeeds != nil {
		p.Hooks.Before = append(p.Hooks.Before, auth.EndpointHook{Run: func(h *auth.HookContext) error {
			if err := opts.seedResources(h.EndpointContext); err != nil {
				h.Auth.Logger().ErrorContext(h.Request.Context(), "Seeding OAuth resources failed", "error", err)
			}
			return nil
		}})
	}
	if slices.Contains(opts.GrantTypes, "authorization_code") {
		p.ValidateVerificationStore = func(s auth.Store, _ auth.VerificationHookSet) error {
			// Codes are stored and spent inside the store's transactions, which
			// must ask the request's gate. A store with neither method gets
			// ValidateStore's error instead.
			_, issues := s.(BrowserAuthorizationStore)
			_, redeems := s.(AuthorizationCodeStore)
			if _, ok := s.(AuthorizationCodeGater); (issues || redeems) && !ok {
				return errors.New("auth: verification hooks with the oauth-provider plugin's authorization codes require a store implementing GatesAuthorizationCodes")
			}
			return nil
		}
	}
	p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: http.MethodPost, Path: "/oauth2/register", SuccessStatus: 201, RateLimit: limit, Handler: opts.register})
	for _, action := range []string{"get-client", "get-clients", "public-client"} {
		p.Endpoints = append(p.Endpoints, opts.clientEndpoint(action))
	}
	p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: http.MethodPost, Path: "/oauth2/public-client-prelogin", Handler: opts.publicClientPrelogin})
	p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: http.MethodPost, Path: "/oauth2/create-client", SuccessStatus: 201, Handler: opts.createClient})
	p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: http.MethodPost, Path: "/oauth2/update-client", Handler: opts.updateClient})
	p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: http.MethodPost, Path: "/oauth2/client/rotate-secret", Handler: opts.rotateClientSecret})
	p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: http.MethodPost, Path: keyRotationPath, Handler: opts.rotateClientKeys,
		RateLimit: tokenRouteLimit(opts.Assertions.KeyRotationRateLimit, 5), OpenAPI: json.RawMessage(keyRotationOperation)})
	p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: http.MethodPost, Path: "/oauth2/delete-client", Handler: opts.deleteClient})
	p.Endpoints = append(p.Endpoints,
		auth.Endpoint{Method: http.MethodGet, Path: endSessionPath, Handler: opts.endSession, OpenAPI: json.RawMessage(endSessionOperation(http.MethodGet))},
		auth.Endpoint{Method: http.MethodPost, Path: endSessionPath, RawBody: true, Handler: opts.endSession, OpenAPI: json.RawMessage(endSessionOperation(http.MethodPost))},
		auth.Endpoint{Method: http.MethodPost, Path: endSessionConfirmPath, RawBody: true, Handler: opts.confirmEndSession, OpenAPI: json.RawMessage(endSessionConfirmOperation)})
	p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: http.MethodPost, Path: "/oauth2/token", RawBody: true, OpenAPI: opts.tokenOperation(), RateLimit: opts.Tokens.RateLimit, Handler: opts.token})
	if slices.Contains(opts.GrantTypes, "authorization_code") {
		if opts.Authorization.LoginPage != "" || opts.Authorization.SignupPage != "" {
			p.PrepareOAuthLogin = opts.prepareLogin
		}
		if opts.Authorization.PostLogin != nil {
			p.PrepareOAuthSelection = opts.prepareSelection
		}
		if p.PrepareOAuthLogin != nil || opts.Authorization.SelectAccount.Page != "" || opts.Authorization.CheckSignup != nil || opts.Authorization.PostLogin != nil {
			p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: http.MethodPost, Path: "/oauth2/continue", Handler: opts.continueAccount, OpenAPI: json.RawMessage(continueAccountOperation)})
		}
		if opts.Authorization.ConsentPage != "" {
			p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: http.MethodPost, Path: "/oauth2/consent", Handler: opts.browserConsent, OpenAPI: json.RawMessage(browserConsentOperation)})
		}
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: method, Path: "/oauth2/authorize", RawBody: method == http.MethodPost, RateLimit: opts.Authorization.RateLimit, Handler: opts.browserAuthorize, OpenAPI: browserAuthorizationOperation(method)})
		}
	}

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: method, Path: "/oauth2/userinfo", RawBody: method == http.MethodPost, RateLimit: tokenRouteLimit(opts.UserInfo.RateLimit, 60), Handler: opts.userInfo, OpenAPI: userInfoOperation(method)})
	}
	p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: http.MethodPost, Path: "/oauth2/introspect", RawBody: true, OpenAPI: json.RawMessage(introspectionOperation), RateLimit: opts.Tokens.IntrospectionRateLimit, Handler: opts.introspect})
	p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: http.MethodPost, Path: "/oauth2/revoke", RawBody: true, OpenAPI: json.RawMessage(revocationOperation), RateLimit: opts.Tokens.RevocationRateLimit, Handler: opts.revoke})
	return p, nil
}

func distinct(xs []string) []string {
	result := make([]string, 0, len(xs))
	seen := make(map[string]bool, len(xs))
	for _, x := range xs {
		if x != "" && !seen[x] {
			result = append(result, x)
			seen[x] = true
		}
	}
	return result
}

// promptValues splits a prompt parameter on single spaces, trims each value
// as JavaScript does and drops empty ones, so "login\tconsent" stays one
// unsupported value.
func promptValues(raw string) []string {
	var values []string
	for _, v := range strings.Split(raw, " ") {
		if v = jsjson.TrimSpace(v); v != "" {
			values = append(values, v)
		}
	}
	return values
}

func randomClientCredential() (string, error) {
	return randomCredential("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

func randomCredential(alphabet string) (string, error) {
	var b [32]byte
	n := big.NewInt(int64(len(alphabet)))
	for i := range b {
		v, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", err
		}
		b[i] = alphabet[v.Int64()]
	}
	return string(b[:]), nil
}

func registrationProblem(status int, code, msg string) error {
	return &auth.OAuthError{Status: status, Code: code, Description: msg}
}
func metadataProblem(msg string) error {
	return registrationProblem(400, "invalid_client_metadata", msg)
}

func (opts Options) register(c auth.EndpointContext) (any, error) {
	c.ResponseHeader.Set("Cache-Control", "no-store")
	c.ResponseHeader.Set("Pragma", "no-cache")
	m, err := readRegistration(c.Body)
	if err != nil {
		return nil, err
	}
	r := opts.Registration
	if !r.Enabled {
		return nil, registrationProblem(403, "access_denied", "Client registration is disabled")
	}
	owner, reference, authenticated, err := opts.authorize(c)
	if err != nil {
		return nil, err
	}
	kind := openRegistration
	if authenticated {
		kind = authenticatedRegistration
	}
	if err = opts.prepareMetadata(c.Auth, &m, kind); err != nil {
		return nil, err
	}
	return opts.persistClient(c, m, owner, reference, r.AllowedScopes, true)
}

// persistClient issues a client's ID and secret and stores it. A dynamic
// registration applies the registration PKCE setting and secret lifetime.
func (opts Options) persistClient(c auth.EndpointContext, m RegistrationMetadata, owner, reference string, scopes []string, dynamic bool) (RegisteredClient, error) {
	// The resources a client links to must exist, so an unfinished seed of
	// the declared ones is retried first.
	if len(m.Resources) > 0 {
		if err := opts.seedResources(c); err != nil {
			return RegisteredClient{}, err
		}
	}
	store, ok := c.Store().(RegistrationStore)
	if !ok {
		return RegisteredClient{}, &auth.APIError{Status: 501, Code: "OAUTH_CLIENT_CREATION_UNAVAILABLE", Message: "The configured store does not support OAuth client creation"}
	}
	row := ClientRegistrationRecord{UserID: owner, ReferenceID: reference, Scopes: scopes, Metadata: m}
	return opts.storeClient(c.Request.Context(), c.Auth, store, row, dynamic)
}

// storeClient issues the client ID and secret for row and stores it.
func (opts Options) storeClient(ctx context.Context, a *auth.Auth, store RegistrationStore, row ClientRegistrationRecord, dynamic bool) (RegisteredClient, error) {
	r := opts.Registration
	m, owner, reference := row.Metadata, row.UserID, row.ReferenceID
	id, err := r.GenerateClientID()
	if err != nil {
		return RegisteredClient{}, err
	}
	if id == "" {
		return RegisteredClient{}, errors.New("oauthprovider: empty generated client ID")
	}
	row.ID, row.ClientID, row.CreatedAt = rand.Text(), id, time.Now().UTC().Truncate(time.Second)
	result := RegisteredClient{RegistrationMetadata: m, ClientID: id, UserID: owner, ReferenceID: reference, IssuedAt: row.CreatedAt.Unix(), managed: !dynamic}
	if row.RequirePKCE != nil {
		result.RequirePKCE = row.RequirePKCE
	}
	if dynamic && r.RequirePKCE != nil && !*r.RequirePKCE && m.TokenEndpointAuthMethod != "none" {
		row.RequirePKCE = r.RequirePKCE
		result.RequirePKCE = r.RequirePKCE
	}
	if m.TokenEndpointAuthMethod == "client_secret_basic" || m.TokenEndpointAuthMethod == "client_secret_post" {
		result.ClientSecret, row.StoredSecret, err = r.issueSecret(ctx, a, id)
		if err != nil {
			return RegisteredClient{}, err
		}
		// Another runtime also accepts a fixed instant; a duration from
		// registration is enough here, as one instant would expire every
		// later registration at once.
		expires := int64(0)
		if dynamic && r.SecretLifetime > 0 {
			expires = result.IssuedAt + int64(r.SecretLifetime/time.Second)
		}
		result.SecretExpiresAt = &expires
	}
	if err = store.CreateRegisteredClient(ctx, row); err != nil {
		return RegisteredClient{}, err
	}
	return result, nil
}

// clientSecretPurpose binds an encrypted secret to its client, so a stored
// value copied to another client does not open.
const clientSecretPurpose = "oauth-client-secret/"

func (r RegistrationOptions) issueSecret(ctx context.Context, a *auth.Auth, clientID string) (issued, stored string, err error) {
	secret, err := r.GenerateClientSecret()
	if err != nil {
		return "", "", err
	}
	if secret == "" {
		return "", "", errors.New("oauthprovider: empty generated client secret")
	}
	switch {
	case r.StoreSecret != nil:
		stored, err = r.StoreSecret(ctx, secret)
		if err != nil {
			return "", "", err
		}
		if stored == "" {
			return "", "", errors.New("oauthprovider: empty stored client secret")
		}
	case r.SecretStorage == "encrypted":
		stored, err = a.EncryptRecord(clientSecretPurpose+clientID, []byte(secret))
		if err != nil {
			return "", "", err
		}
	default:
		stored = tokenDigest(secret)
	}
	return r.SecretPrefix + secret, stored, nil
}

func (opts Options) authorize(c auth.EndpointContext) (owner, reference string, authenticated bool, err error) {
	r := opts.Registration
	ctx, h := c.Request.Context(), c.Request.Header
	session, err := c.Auth.GetSession(ctx, h)
	if err != nil {
		return "", "", false, err
	}
	if session != nil {
		if err := session.Session.RequireOwner(); err != nil {
			return "", "", false, err
		}
		access := RegistrationAccess{SessionResult: *session, Headers: h.Clone()}
		if err := opts.allowClient(ctx, access, "create", ""); err != nil {
			return "", "", false, err
		}
		if r.MayCreate != nil {
			ok, err := r.MayCreate(ctx, access)
			if err != nil {
				return "", "", false, err
			}
			if !ok {
				return "", "", false, auth.StatusOnlyError(401)
			}
		}
		reference, err = opts.activeClientReference(ctx, access)
		if err != nil {
			return "", "", false, err
		}
		if reference == "" {
			owner = session.User.ID
		}
		return owner, reference, true, nil
	}
	if len(h.Values("Authorization")) > 1 {
		return "", "", false, registrationChallenge(c, 400, "invalid_request", "Malformed initial access token Authorization header")
	}
	parts := strings.Fields(h.Get("Authorization"))
	if len(parts) > 0 && strings.EqualFold(parts[0], "Bearer") {
		if len(parts) != 2 {
			return "", "", false, registrationChallenge(c, 400, "invalid_request", "Malformed initial access token Authorization header")
		}
		if r.ValidateInitialToken != nil {
			// A callback may retain the metadata. Give it a separate snapshot from the row we validate and persist.
			snapshot, err := readRegistration(c.Body)
			if err != nil {
				return "", "", false, err
			}
			authorized, err := r.ValidateInitialToken(ctx, parts[1], h.Clone(), snapshot)
			if err != nil {
				var api *auth.APIError
				var oauth *auth.OAuthError
				if errors.As(err, &api) || errors.As(err, &oauth) {
					return "", "", false, err
				}
				return "", "", false, registrationProblem(500, "server_error", "Initial access token validation failed")
			}
			if authorized != nil {
				return "", authorized.ReferenceID, true, nil
			}
		}
		return "", "", false, registrationChallenge(c, 401, "invalid_token", "Invalid initial access token")
	}
	if !r.AllowUnauthenticated {
		return "", "", false, registrationChallenge(c, 401, "", "Authentication required for client registration")
	}
	return "", "", false, nil
}

func registrationChallenge(c auth.EndpointContext, status int, code, msg string) error {
	challenge := "Bearer"
	if code != "" {
		challenge += " error=\"" + code + "\""
	}
	c.ResponseHeader.Set("WWW-Authenticate", challenge)
	c.ResponseHeader.Add("Access-Control-Expose-Headers", "WWW-Authenticate")
	return registrationProblem(status, code, msg)
}
