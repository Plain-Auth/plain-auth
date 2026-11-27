package oauthprovider

import (
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
)

// GrantHandler answers a token request for an extension grant type. It
// runs in the token endpoint, outside any store transaction. An
// *auth.OAuthError it returns is the answer.
type GrantHandler func(GrantInput) (TokenResponse, error)

// GrantInput is one token request for an extension grant.
type GrantInput struct {
	Endpoint auth.EndpointContext
	// Form is the parsed token request.
	Form      url.Values
	GrantType string
	// Provider is the provider's API for this request, bound to GrantType.
	Provider *ProviderAPI
}

// ProviderAPI is what an extension grant handler may ask of the provider,
// as another runtime's provider API. It exists only inside a dispatched
// grant, bound to its request and grant type.
type ProviderAPI struct {
	opts  Options
	c     auth.EndpointContext
	form  url.Values
	grant string
	// challenge is the WWW-Authenticate scheme for a refused client.
	challenge string
	// authenticated is the registration AuthenticateClient accepted.
	authenticated *MachineClient
}

// ClientAuthenticationRequest says what AuthenticateClient checks besides
// the client's credentials.
type ClientAuthenticationRequest struct {
	// Scopes are checked against the client's registered scopes.
	Scopes []string
	// AllowPublic accepts a request without credentials from a client
	// registered for token_endpoint_auth_method none.
	AllowPublic bool
}

// AuthenticatedClient is the client AuthenticateClient proved.
type AuthenticatedClient struct {
	ClientID string
	Client   ClientDetails
	// Method is the token endpoint authentication method the request used.
	Method string
	// Confirmation is what an extension authentication strategy proved.
	Confirmation *Confirmation
}

// TokenResponse is a token endpoint success body. Fields adds members; it
// never replaces a standard one. An empty refresh or ID token is left out.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	ExpiresAt    int64  `json:"expires_at"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`

	Fields map[string]any `json:"-"`
}

// MarshalJSON writes the standard members and the Fields that do not
// name one.
func (r TokenResponse) MarshalJSON() ([]byte, error) {
	type plain TokenResponse
	body, err := tokenBody(plain(r), r.Fields)
	if err != nil {
		return nil, err
	}
	return json.Marshal(body)
}

// Client returns a registered client, or nil when there is none.
func (p *ProviderAPI) Client(clientID string) (*ClientDetails, error) {
	store, ok := p.c.Store().(ClientDirectoryStore)
	if !ok {
		return nil, &auth.APIError{Status: 501, Code: "OAUTH_CLIENT_STORE_UNAVAILABLE", Message: "The configured store does not support OAuth client lookups"}
	}
	client, err := store.LookupOAuthClient(p.c.Request.Context(), clientID)
	if errors.Is(err, ErrClientNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// AuthenticateClient authenticates the token request's client with its
// registered method, as the built-in grants do, with the token endpoint as
// an assertion's audience. It then checks req.Scopes against the client's
// registered scopes and requires the grant in its grant types, where an
// empty list means authorization_code only.
func (p *ProviderAPI) AuthenticateClient(req ClientAuthenticationRequest) (AuthenticatedClient, error) {
	client, err := p.authenticateClient(req)
	if err != nil {
		return AuthenticatedClient{}, tokenEndpointError(p.c.ResponseHeader, p.challenge, err)
	}
	return client, nil
}

func (p *ProviderAPI) authenticateClient(req ClientAuthenticationRequest) (AuthenticatedClient, error) {
	in, challenge, err := p.opts.readCredentials(p.c, p.form, "/oauth2/token")
	p.challenge = challenge
	if err != nil {
		return AuthenticatedClient{}, err
	}
	if in.id == "" {
		return AuthenticatedClient{}, registrationProblem(400, "invalid_request", "Missing required client_id")
	}
	if !req.AllowPublic && in.secret == "" && in.assertion == nil && !in.proven {
		return AuthenticatedClient{}, invalidClient("Missing required client credentials")
	}
	reader, ok := p.c.Store().(MachineClientReader)
	directory, isDirectory := p.c.Store().(ClientDirectoryStore)
	if !ok || !isDirectory {
		return AuthenticatedClient{}, &auth.APIError{Status: 501, Code: "OAUTH_CLIENT_STORE_UNAVAILABLE", Message: "The configured store does not support OAuth client lookups"}
	}
	first, err := p.opts.authenticateClient(p.c, reader, in, "/oauth2/token")
	if err != nil {
		return AuthenticatedClient{}, err
	}
	details, err := directory.LookupOAuthClient(p.c.Request.Context(), in.id)
	if err != nil {
		return AuthenticatedClient{}, err
	}
	if details.Scope != nil {
		registered := strings.Fields(*details.Scope)
		for _, scope := range req.Scopes {
			if !slices.Contains(registered, scope) {
				return AuthenticatedClient{}, registrationProblem(400, "invalid_scope", "client does not allow scope "+scope)
			}
		}
	}
	if !clientAllowsGrant(first.GrantTypes, p.grant) {
		return AuthenticatedClient{}, registrationProblem(400, "unauthorized_client", "client is not authorized to use grant type "+p.grant)
	}
	p.authenticated = &first
	return AuthenticatedClient{ClientID: in.id, Client: details, Method: in.method, Confirmation: in.confirmation}, nil
}

// clientAllowsGrant reports whether registered grant types allow grant:
// none registered means authorization_code, which also allows refresh_token.
func clientAllowsGrant(registered []string, grant string) bool {
	if len(registered) == 0 {
		registered = []string{"authorization_code"}
	}
	return slices.Contains(registered, grant) || grant == "refresh_token" && slices.Contains(registered, "authorization_code")
}

// HashToken returns the stored form of a token the provider issued, so a
// handler can find or revoke one by its value. An access token without
// the configured prefix has none, and HashToken returns "".
func (p *ProviderAPI) HashToken(token string, kind StoredTokenKind) (string, error) {
	return p.opts.Tokens.storedTokenDigest(p.c.Request.Context(), token, kind)
}

// grantHandler finds the extension handler for a grant type.
func (opts Options) grantHandler(grant string) GrantHandler {
	for _, extension := range opts.Extensions {
		if handler, ok := extension.Grants[grant]; ok {
			return handler
		}
	}
	return nil
}

// supportedGrants lists the configured grant types, then the extensions'.
func (opts Options) supportedGrants() []string {
	grants := slices.Clone(opts.GrantTypes)
	for _, extension := range opts.Extensions {
		keys := make([]string, 0, len(extension.Grants))
		for grant := range extension.Grants {
			keys = append(keys, grant)
		}
		slices.Sort(keys)
		grants = append(grants, keys...)
	}
	return distinct(grants)
}

// checkGrants refuses an extension grant type that is not an absolute
// URI, has no handler, or is defined twice, as another runtime does.
func (opts Options) checkGrants() error {
	seen := map[string]bool{}
	for _, extension := range opts.Extensions {
		for grant, handler := range extension.Grants {
			u, err := url.Parse(grant)
			switch {
			case err != nil || !u.IsAbs():
				return errors.New("oauthprovider: extension grant type must be an absolute URI: " + grant)
			case handler == nil:
				return errors.New("oauthprovider: extension grant type has no handler: " + grant)
			case seen[grant]:
				return errors.New("oauthprovider: extension grant type is defined twice: " + grant)
			}
			seen[grant] = true
		}
	}
	return nil
}

// tokenOperation documents the token endpoint, with the extensions' grant
// types in the grant_type enum.
func (opts Options) tokenOperation() json.RawMessage {
	const builtIn = `"enum":["client_credentials","authorization_code","refresh_token"]`
	grants := []string{"client_credentials", "authorization_code", "refresh_token"}
	for _, grant := range opts.supportedGrants() {
		if opts.grantHandler(grant) != nil {
			grants = append(grants, grant)
		}
	}
	enum, _ := json.Marshal(grants)
	return json.RawMessage(strings.Replace(machineTokenOperation, builtIn, `"enum":`+string(enum), 1))
}
