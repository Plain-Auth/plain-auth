package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
)

// ClientCreation is the server-only input to ClientManager.CreateClient. The
// settings after RegistrationMetadata are only for an administrator to choose.
type ClientCreation struct {
	RegistrationMetadata
	SkipConsent             *bool
	EnableEndSession        *bool
	RequirePKCE             *bool
	ClientCredentialsScopes []string
	// Metadata is stored as the client's metadata object; names the
	// provider reserves are dropped.
	Metadata map[string]json.RawMessage
}

// AdministrativeClient is the server-only view of a created client: the
// registration response plus the settings only an administrator can choose.
type AdministrativeClient struct {
	RegisteredClient
	SkipConsent, EnableEndSession *bool
	ClientCredentialsScopes       []string
}

// MarshalJSON always writes client_credentials_scopes, as another runtime's
// administrative response does.
func (c AdministrativeClient) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal(c.RegisteredClient)
	if err != nil {
		return nil, err
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	scopes := c.ClientCredentialsScopes
	if scopes == nil {
		scopes = []string{}
	}
	for name, value := range map[string]any{"client_credentials_scopes": scopes, "skip_consent": c.SkipConsent, "enable_end_session": c.EnableEndSession} {
		if name != "client_credentials_scopes" && value.(*bool) == nil {
			continue
		}
		if body[name], err = json.Marshal(value); err != nil {
			return nil, err
		}
	}
	return json.Marshal(body)
}

// WithResources returns a copy whose CreateClient may link requested
// resources: r checks the link privilege for each one and seeds its
// configured resources first.
func (m *ClientManager) WithResources(r *ResourceManager) *ClientManager {
	copy := *m
	copy.resources = r
	return &copy
}

// CreateClient creates a client with administrator settings for the
// signed-in owner of headers, as another runtime's adminCreateOAuthClient
// does. It has no HTTP route. The create privilege decides, MayCreate is
// not asked, and assigning machine scopes or linking requested resources
// needs its own approval.
func (m *ClientManager) CreateClient(ctx context.Context, headers http.Header, in ClientCreation) (AdministrativeClient, error) {
	session, err := m.auth.GetSession(ctx, headers)
	if err != nil {
		return AdministrativeClient{}, err
	}
	if session == nil {
		return AdministrativeClient{}, auth.StatusOnlyError(http.StatusUnauthorized)
	}
	if err := session.Session.RequireOwner(); err != nil {
		return AdministrativeClient{}, err
	}
	access := RegistrationAccess{SessionResult: *session, Headers: headers.Clone()}
	if err := m.opts.allowClient(ctx, access, "create", ""); err != nil {
		return AdministrativeClient{}, err
	}
	reference, err := m.opts.activeClientReference(ctx, access)
	if err != nil {
		return AdministrativeClient{}, err
	}
	owner := ""
	if reference == "" {
		owner = session.User.ID
	}
	// The Go input passes the same shape checks as an HTTP body.
	raw, err := json.Marshal(in.RegistrationMetadata)
	if err != nil {
		return AdministrativeClient{}, err
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return AdministrativeClient{}, err
	}
	md, err := readRegistration(body)
	if err != nil {
		return AdministrativeClient{}, err
	}
	requested := distinct(md.Resources)
	if err := m.opts.prepareMetadata(m.auth, &md, managedClient); err != nil {
		return AdministrativeClient{}, err
	}
	scopes, err := normalizeScopeField("body.client_credentials_scopes", in.ClientCredentialsScopes)
	if err != nil {
		return AdministrativeClient{}, err
	}
	if len(scopes) > 0 {
		if !slices.Contains(md.GrantTypes, "client_credentials") {
			return AdministrativeClient{}, metadataProblem("client_credentials_scopes requires the client_credentials grant")
		}
		if md.TokenEndpointAuthMethod == "none" {
			return AdministrativeClient{}, metadataProblem("public clients cannot be assigned client_credentials scopes")
		}
		var invalid []string
		for _, scope := range scopes {
			if userDelegatedScope(scope) || !slices.Contains(m.opts.Scopes, scope) {
				invalid = append(invalid, scope)
			}
		}
		if len(invalid) > 0 {
			return AdministrativeClient{}, registrationProblem(400, "invalid_scope", "The following client_credentials scopes are invalid: "+strings.Join(invalid, ", "))
		}
		if err := m.opts.allowClient(ctx, access, "configure-client-credentials-scopes", ""); err != nil {
			return AdministrativeClient{}, err
		}
	}
	// Requested resources need the resource manager's link privilege;
	// default resources need none.
	if len(requested) > 0 {
		if m.resources == nil {
			return AdministrativeClient{}, errors.New("oauthprovider: linking resources at client creation requires ClientManager.WithResources")
		}
		for _, id := range requested {
			if err := m.resources.authorize(ctx, headers, "link", id); err != nil {
				return AdministrativeClient{}, err
			}
		}
	}
	extensions := map[string]json.RawMessage{}
	for name, value := range in.Metadata {
		if clientExtension(name) {
			extensions[name] = value
		}
	}
	if len(extensions) == 0 {
		extensions = nil
	}
	store, ok := m.store.(RegistrationStore)
	if !ok {
		return AdministrativeClient{}, errors.New("oauthprovider: client creation requires a RegistrationStore")
	}
	var clientScopes []string
	if md.Scope != "" {
		clientScopes = strings.Fields(md.Scope)
	}
	row := ClientRegistrationRecord{UserID: owner, ReferenceID: reference, Scopes: clientScopes, Metadata: md, RequirePKCE: in.RequirePKCE,
		SkipConsent: in.SkipConsent, EnableEndSession: in.EnableEndSession, ClientCredentialsScopes: scopes, Extensions: extensions}
	created, err := m.opts.storeClient(ctx, m.auth, store, row, false)
	if err != nil {
		return AdministrativeClient{}, err
	}
	return AdministrativeClient{RegisteredClient: created, SkipConsent: in.SkipConsent, EnableEndSession: in.EnableEndSession, ClientCredentialsScopes: scopes}, nil
}
