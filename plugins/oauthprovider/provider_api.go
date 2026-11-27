package oauthprovider

import (
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

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
	// authenticated is the registration AuthenticateClient accepted, for
	// the request it read.
	authenticated *MachineClient
	request       tokenRequest
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
	p.authenticated, p.request = &first, in
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

// TokenIssueParams describes tokens an extension grant issues for a client.
// IssueTokens applies the resources' policy and checks the registration
// again, but does not check that the scopes were approved: the handler
// authorizes them, for example with AuthenticateClient's Scopes.
type TokenIssueParams struct {
	ClientID string
	Scopes   []string
	// Resources are the token's audiences, as resource parameters name them.
	Resources []string
	// AccessTokenClaims are added to a signed access token, above the
	// extensions' claims and below the host's and the resources'.
	AccessTokenClaims map[string]any
	// TokenResponse adds response members above CustomTokenResponseFields.
	TokenResponse map[string]any
	// Confirmation binds the tokens, naming exactly one key; without one,
	// a DPoP proof on the request does.
	Confirmation *Confirmation
}

// IssueTokens issues an access token for a client, with the client
// credentials lifetime, as another runtime's issueTokens does without a
// user. With resources and the jwt plugin the token is a signed at+jwt;
// otherwise it is opaque and stored. A client or resource that requires
// DPoP needs a DPoP key, from the confirmation or a proof, where another
// runtime accepts any confirmation (safety).
func (p *ProviderAPI) IssueTokens(params TokenIssueParams) (TokenResponse, error) {
	token, err := p.issueTokens(params)
	if err != nil {
		return TokenResponse{}, tokenEndpointError(p.c.ResponseHeader, p.challenge, err)
	}
	return token, nil
}

func (p *ProviderAPI) issueTokens(params TokenIssueParams) (TokenResponse, error) {
	c, opts := p.c, p.opts
	ctx := c.Request.Context()
	if params.ClientID == "" {
		return TokenResponse{}, errors.New("oauthprovider: IssueTokens needs a client ID")
	}
	if cnf := params.Confirmation; cnf != nil && (cnf.JKT == "") == (cnf.X5TS256 == "") {
		return TokenResponse{}, errors.New("oauthprovider: a token confirmation names exactly one key")
	}
	if len(params.Resources) > 64 {
		return TokenResponse{}, registrationProblem(400, "invalid_target", "at most 64 resource parameters are supported")
	}
	for _, id := range params.Resources {
		if !ValidResourceIdentifier(id) {
			return TokenResponse{}, registrationProblem(400, "invalid_request", "resource must be an absolute URI without a fragment")
		}
	}
	store, ok := c.Store().(ResourceMachineTokenStore)
	if !ok {
		return TokenResponse{}, &auth.APIError{Status: 501, Code: "OAUTH_RESOURCE_TOKEN_STORE_UNAVAILABLE", Message: "The configured store cannot issue resource-targeted tokens"}
	}
	if err := opts.seedResources(c); err != nil {
		return TokenResponse{}, err
	}
	audiences := distinct(params.Resources)
	userInfo := c.Auth.PublicURL() + "/oauth2/userinfo"
	identifiers := slices.DeleteFunc(slices.Clone(audiences), func(id string) bool { return id == userInfo })
	// One issuance instant serves both passes.
	now := time.Now().UTC().Truncate(time.Second)
	resolve := func(client MachineClient, rows map[string]MachineResource) (machineResourcePolicy, error) {
		if client.Disabled {
			return machineResourcePolicy{}, invalidClient("client is disabled")
		}
		if !clientAllowsGrant(client.GrantTypes, p.grant) {
			return machineResourcePolicy{}, registrationProblem(400, "unauthorized_client", "client is not authorized to use grant type "+p.grant)
		}
		if p.authenticated != nil && p.authenticated.ClientID == client.ClientID {
			if err := p.request.recheckClient(*p.authenticated, client); err != nil {
				return machineResourcePolicy{}, err
			}
		}
		return opts.Tokens.machineResourcePolicy(client, params.Scopes, identifiers, rows, now)
	}
	var policy machineResourcePolicy
	var metadata map[string]json.RawMessage
	err := store.WithMachineResources(ctx, params.ClientID, identifiers, func(client MachineClient, rows map[string]MachineResource) (*ResourceMachineTokenRecord, error) {
		var err error
		policy, err = resolve(client, rows)
		metadata = client.Metadata
		return nil, err
	})
	if err != nil {
		return TokenResponse{}, err
	}
	// Host fields are resolved from the first read, before any token exists.
	fields, err := opts.Tokens.responseFields(ctx, TokenResponseInput{GrantType: p.grant, Scopes: policy.scopes, Metadata: metadata})
	if err != nil {
		return TokenResponse{}, err
	}
	if len(params.TokenResponse) > 0 {
		fields = maps.Clone(fields)
		if fields == nil {
			fields = map[string]any{}
		}
		maps.Copy(fields, params.TokenResponse)
	}
	cnf := params.Confirmation
	if cnf == nil {
		if len(c.Request.Header.Values("DPoP")) > 1 {
			return TokenResponse{}, proofError("DPoP proof header must not be repeated")
		}
		thumb, err := opts.machineThumbprint(c, tokenRequest{proof: c.Request.Header.Get("DPoP")}, policy.bound)
		if err != nil {
			return TokenResponse{}, err
		}
		cnf = jktConfirmation(thumb)
	}
	unbound := cnf == nil || cnf.JKT == ""
	signed := len(audiences) > 0 && opts.signsResourceTokens(c)
	var issued, stored string
	if signed {
		// Contributed claims are resolved outside the store's transactions.
		extra, err := opts.accessTokenClaims(c, TokenClaimsInput{ClientID: params.ClientID, Scopes: policy.scopes, GrantType: p.grant, Resources: params.Resources, Metadata: metadata}, params.AccessTokenClaims)
		if err != nil {
			return TokenResponse{}, err
		}
		issued, err = policy.sign(c, params.ClientID, params.ClientID, "", audiences, cnf, now, extra)
		if err != nil {
			return TokenResponse{}, err
		}
	} else if issued, stored, err = opts.Tokens.newOpaqueToken(ctx); err != nil {
		return TokenResponse{}, err
	}
	// Signing and host token generators may use this same database. Run
	// them outside the transaction, then authorize the actual response again.
	err = store.WithMachineResources(ctx, params.ClientID, identifiers, func(client MachineClient, rows map[string]MachineResource) (*ResourceMachineTokenRecord, error) {
		current, err := resolve(client, rows)
		if err != nil {
			return nil, err
		}
		if current.bound && unbound {
			return nil, proofError("DPoP proof header is required")
		}
		if signed {
			if !reflect.DeepEqual(current, policy) {
				return nil, registrationProblem(400, "invalid_request", "resource policy changed during issuance, retry the request")
			}
			if !time.Now().Before(now.Add(policy.lifetime)) {
				return nil, registrationProblem(503, "temporarily_unavailable", "token expired during issuance, retry the request")
			}
			return nil, nil
		}
		if opts.Tokens.CustomTokenResponseFields != nil && !slices.Equal(current.scopes, policy.scopes) {
			return nil, registrationProblem(400, "invalid_request", "client scopes changed during issuance, retry the request")
		}
		policy = current
		record := MachineTokenRecord{StoredToken: stored, Scopes: current.scopes, IssuedAt: now, ExpiresAt: now.Add(current.lifetime)}
		return &ResourceMachineTokenRecord{MachineTokenRecord: record, Resources: params.Resources, Confirmation: cnf}, nil
	})
	if err != nil {
		return TokenResponse{}, err
	}
	token := machineResponse(issued, "", policy.scopes, now, policy.lifetime)
	if !unbound {
		token.TokenType = "DPoP"
	}
	return TokenResponse{AccessToken: token.AccessToken, TokenType: token.TokenType, ExpiresIn: token.ExpiresIn, ExpiresAt: token.ExpiresAt, Scope: token.Scope, Fields: fields}, nil
}

// jktConfirmation names a DPoP key as a token confirmation, or none.
func jktConfirmation(thumb string) *Confirmation {
	if thumb == "" {
		return nil
	}
	return &Confirmation{JKT: thumb}
}
