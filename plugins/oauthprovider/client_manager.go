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

// ClientAdminUpdate is the server-only input to ClientManager.UpdateClient.
// Fields replaces owner-editable registration fields by wire name, as
// /oauth2/update-client reads them; a nil setting below keeps the stored
// value, and an empty Metadata keeps the stored metadata object.
type ClientAdminUpdate struct {
	Fields                                                         map[string]any
	SkipConsent, EnableEndSession, Disabled, DPoPBoundAccessTokens *bool
	ClientCredentialsScopes                                        []string
	Metadata                                                       map[string]json.RawMessage
}

func (u ClientAdminUpdate) settingsOnly() bool {
	return len(u.Fields) == 0 && u.SkipConsent == nil && u.EnableEndSession == nil && u.Disabled == nil && u.DPoPBoundAccessTokens == nil && len(u.Metadata) == 0
}

// UpdateClient changes a client with administrator settings, as another
// runtime's adminUpdateOAuthClient does, as a Go method. An update that sets
// only ClientCredentialsScopes may target another owner's client, as
// SetClientCredentialsScopes does; any other update needs ownership.
func (m *ClientManager) UpdateClient(ctx context.Context, headers http.Header, id string, in ClientAdminUpdate) (AdministrativeClient, error) {
	if in.settingsOnly() && in.ClientCredentialsScopes != nil {
		scopes, err := m.SetClientCredentialsScopes(ctx, headers, id, in.ClientCredentialsScopes)
		if err != nil {
			return AdministrativeClient{}, err
		}
		current, err := m.store.LookupOAuthClient(ctx, id)
		if err != nil {
			return AdministrativeClient{}, scopeManagementError(err)
		}
		return AdministrativeClient{RegisteredClient: registeredView(current), SkipConsent: current.SkipConsent, EnableEndSession: current.EnableEndSession, ClientCredentialsScopes: scopes}, nil
	}
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
	if err := m.opts.allowClient(ctx, access, "update", id); err != nil {
		return AdministrativeClient{}, err
	}
	if slices.Contains(m.opts.ImmutableClientIDs, id) {
		return AdministrativeClient{}, registrationProblem(400, "invalid_client", "trusted clients must be updated manually")
	}
	store, ok := m.store.(ClientUpdateStore)
	if !ok {
		return AdministrativeClient{}, errors.New("oauthprovider: client updates require a ClientUpdateStore")
	}
	current, err := m.store.LookupOAuthClient(ctx, id)
	if err != nil {
		return AdministrativeClient{}, scopeManagementError(err)
	}
	owned, err := m.opts.ownsClient(ctx, access, current)
	if err != nil {
		return AdministrativeClient{}, err
	}
	if !owned {
		return AdministrativeClient{}, auth.StatusOnlyError(http.StatusUnauthorized)
	}
	patch := map[string]any{}
	for _, name := range ownerUpdateFields {
		if value, present := in.Fields[name]; present {
			patch[name] = value
		}
	}
	if _, err := readRegistration(patch); err != nil {
		return AdministrativeClient{}, err
	}
	change, err := m.opts.clientChange(m.auth, current, patch)
	if err != nil {
		return AdministrativeClient{}, err
	}
	change.SkipConsent, change.EnableEndSession, change.Disabled, change.DPoPBoundAccessTokens = in.SkipConsent, in.EnableEndSession, in.Disabled, in.DPoPBoundAccessTokens
	for name, value := range in.Metadata {
		if clientExtension(name) {
			if change.Extensions == nil {
				change.Extensions = map[string]json.RawMessage{}
			}
			change.Extensions[name] = value
		}
	}
	if in.ClientCredentialsScopes != nil && !change.ClearMachineScopes {
		scopes, err := normalizeScopeField("body.update.client_credentials_scopes", in.ClientCredentialsScopes)
		if err != nil {
			return AdministrativeClient{}, err
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
		if len(scopes) > 0 {
			if err := m.opts.allowClient(ctx, access, "configure-client-credentials-scopes", id); err != nil {
				return AdministrativeClient{}, err
			}
		}
		change.MachineScopes = scopes
	}
	updated, err := applyClientChange(ctx, store, change)
	if err != nil {
		return AdministrativeClient{}, err
	}
	return AdministrativeClient{RegisteredClient: registeredView(updated), SkipConsent: updated.SkipConsent, EnableEndSession: updated.EnableEndSession, ClientCredentialsScopes: change.MachineScopes}, nil
}

// registeredView presents stored client details in the registration
// response shape, without a secret.
func registeredView(c ClientDetails) RegisteredClient {
	raw, _ := json.Marshal(c) // ClientDetails always encodes.
	var r RegisteredClient
	_ = json.Unmarshal(raw, &r)
	return r
}
