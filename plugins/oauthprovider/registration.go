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

	auth "github.com/Plain-Auth/plain-auth"
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
}

func (c RegisteredClient) MarshalJSON() ([]byte, error) {
	type record RegisteredClient
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
	// Supply this when StoreSecret uses a random salt or encryption.
	VerifySecret         func(ctx context.Context, raw, stored string) (bool, error)
	ValidateInitialToken func(context.Context, string, http.Header, RegistrationMetadata) (*InitialAuthorization, error)
	MayCreate            func(context.Context, RegistrationAccess) (bool, error)
	ClientReference      func(context.Context, RegistrationAccess) (string, error)
	AllowHTTPRedirect    func(*url.URL) bool
	RateLimit            *auth.RateLimitRule
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
	return opts
}

// New installs the OAuth consent, client management and dynamic registration endpoints.
// Dynamic registration is disabled until the host explicitly enables it.
func New(opts Options) (auth.Plugin, error) {
	opts = opts.clientManagementOptions()
	if opts.GrantTypes == nil {
		opts.GrantTypes = []string{"authorization_code", "client_credentials", "refresh_token"}
	}
	opts.GrantTypes = distinct(opts.GrantTypes)
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
	r.DefaultResources = distinct(r.DefaultResources)
	r.AllowedResources = distinct(slices.Concat(r.DefaultResources, r.AllowedResources))
	if r.RequirePKCE != nil {
		v := *r.RequirePKCE
		r.RequirePKCE = &v
	}
	if r.GenerateClientID == nil {
		r.GenerateClientID = randomClientCredential
	}
	if r.GenerateClientSecret == nil {
		r.GenerateClientSecret = randomClientCredential
	}
	limit := auth.RateLimitRule{Window: time.Minute, Max: 5}
	if r.RateLimit != nil {
		limit = *r.RateLimit
	}
	p := ConsentManagement(ConsentOptions{Scopes: opts.Scopes})
	validateConsent := p.ValidateStore
	p.ValidateStore = func(s auth.Store) error {
		if err := validateConsent(s); err != nil {
			return err
		}
		if _, ok := s.(RegistrationStore); r.Enabled && !ok {
			return errors.New("oauthprovider: registration requires a RegistrationStore")
		}
		return nil
	}
	p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: http.MethodPost, Path: "/oauth2/register", SuccessStatus: 201, RateLimit: &limit, Handler: opts.register})
	for _, action := range []string{"get-client", "get-clients", "public-client"} {
		p.Endpoints = append(p.Endpoints, opts.clientEndpoint(action))
	}
	p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: http.MethodPost, Path: "/oauth2/client/rotate-secret", Handler: opts.rotateClientSecret})
	p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: http.MethodPost, Path: "/oauth2/delete-client", Handler: opts.deleteClient})
	p.Endpoints = append(p.Endpoints, auth.Endpoint{Method: http.MethodPost, Path: "/oauth2/token", RawBody: true, OpenAPI: json.RawMessage(machineTokenOperation), RateLimit: opts.Tokens.RateLimit, Handler: opts.token})
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

func randomClientCredential() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
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
	if err = opts.prepareMetadata(c.Auth, &m, authenticated); err != nil {
		return nil, err
	}
	ctx := c.Request.Context()
	id, err := r.GenerateClientID()
	if err != nil {
		return nil, err
	}
	if id == "" {
		return nil, errors.New("oauthprovider: empty generated client ID")
	}
	row := ClientRegistrationRecord{ID: rand.Text(), ClientID: id, UserID: owner, ReferenceID: reference, Scopes: r.AllowedScopes, Metadata: m, CreatedAt: time.Now().UTC().Truncate(time.Second)}
	result := RegisteredClient{RegistrationMetadata: m, ClientID: id, UserID: owner, ReferenceID: reference, IssuedAt: row.CreatedAt.Unix()}
	if r.RequirePKCE != nil && !*r.RequirePKCE && m.TokenEndpointAuthMethod != "none" {
		row.RequirePKCE = r.RequirePKCE
		result.RequirePKCE = r.RequirePKCE
	}
	if m.TokenEndpointAuthMethod == "client_secret_basic" || m.TokenEndpointAuthMethod == "client_secret_post" {
		result.ClientSecret, row.StoredSecret, err = r.issueSecret(ctx)
		if err != nil {
			return nil, err
		}
		result.SecretExpiresAt = new(int64)
	}
	if err = c.Store().(RegistrationStore).CreateRegisteredClient(ctx, row); err != nil {
		return nil, err
	}
	return result, nil
}

func (r RegistrationOptions) issueSecret(ctx context.Context) (issued, stored string, err error) {
	secret, err := r.GenerateClientSecret()
	if err != nil {
		return "", "", err
	}
	if secret == "" {
		return "", "", errors.New("oauthprovider: empty generated client secret")
	}
	if r.StoreSecret != nil {
		stored, err = r.StoreSecret(ctx, secret)
		if err != nil {
			return "", "", err
		}
		if stored == "" {
			return "", "", errors.New("oauthprovider: empty stored client secret")
		}
	} else {
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
