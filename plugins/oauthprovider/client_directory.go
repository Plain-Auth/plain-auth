package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
)

// PublicClient holds the display metadata a signed-in user can see on a login or consent screen.
// The public endpoint always returns an empty redirect_uris array.
type PublicClient struct {
	ClientID     string   `json:"client_id"`
	Name         *string  `json:"client_name,omitempty"`
	URI          *string  `json:"client_uri,omitempty"`
	LogoURI      *string  `json:"logo_uri,omitempty"`
	Contacts     []string `json:"contacts,omitzero"`
	TermsURI     *string  `json:"tos_uri,omitempty"`
	PolicyURI    *string  `json:"policy_uri,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
}

// ClientDetails is the owner view of a registration. It never carries a client secret.
type ClientDetails struct {
	PublicClient
	Scope                            *string                    `json:"scope,omitempty"`
	UserID                           *string                    `json:"user_id,omitempty"`
	ReferenceID                      *string                    `json:"reference_id,omitempty"`
	IssuedAt                         *int64                     `json:"client_id_issued_at,omitempty"`
	SecretExpiresAt                  *int64                     `json:"client_secret_expires_at,omitempty"`
	SoftwareID                       *string                    `json:"software_id,omitempty"`
	SoftwareVersion                  *string                    `json:"software_version,omitempty"`
	SoftwareStatement                *string                    `json:"software_statement,omitempty"`
	JWKS                             json.RawMessage            `json:"jwks,omitempty"`
	JWKSURI                          *string                    `json:"jwks_uri,omitempty"`
	PostLogoutRedirectURIs           []string                   `json:"post_logout_redirect_uris,omitzero"`
	BackchannelLogoutURI             *string                    `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired *bool                      `json:"backchannel_logout_session_required,omitempty"`
	TokenEndpointAuthMethod          *string                    `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes                       []string                   `json:"grant_types,omitzero"`
	ResponseTypes                    []string                   `json:"response_types,omitzero"`
	ApplicationType                  *string                    `json:"application_type,omitempty"`
	SubjectType                      *string                    `json:"subject_type,omitempty"`
	Disabled                         *bool                      `json:"disabled,omitempty"`
	SkipConsent                      *bool                      `json:"skip_consent,omitempty"`
	EnableEndSession                 *bool                      `json:"enable_end_session,omitempty"`
	RequirePKCE                      *bool                      `json:"require_pkce,omitempty"`
	DPoPBoundAccessTokens            *bool                      `json:"dpop_bound_access_tokens,omitempty"`
	Extensions                       map[string]json.RawMessage `json:"-"`
}

// Split canonical and internal names from opaque extensions even when the stored
// canonical value is absent. Only exact wire names enter the typed SDK decoder.
var clientWireFields = func() map[string]bool {
	fields := make(map[string]bool)
	for _, f := range reflect.VisibleFields(reflect.TypeFor[ClientDetails]()) {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name != "" && name != "-" {
			fields[name] = true
		}
	}
	return fields
}()

func clientExtension(k string) bool {
	switch k {
	case "client_secret", "clientId", "clientSecret", "clientDiscoveryId", "scopes", "clientCredentialsScopes",
		"userId", "referenceId", "createdAt", "updatedAt", "expiresAt", "name", "uri", "icon", "tos", "policy",
		"softwareId", "softwareVersion", "softwareStatement", "redirectUris", "postLogoutRedirectUris",
		"backchannelLogoutUri", "backchannelLogoutSessionRequired", "tokenEndpointAuthMethod", "grantTypes",
		"responseTypes", "applicationType", "jwksUri", "requirePKCE", "dpopBoundAccessTokens", "skipConsent",
		"enableEndSession", "subjectType", "metadata", "public", "type", "resources", "client_credentials_scopes",
		"__proto__", "constructor", "prototype":
		return false
	}
	return !clientWireFields[k]
}

// SetMetadataExtensions loads the database metadata envelope. Reserved fields
// are discarded before a caller can observe the application-specific values.
func (c *ClientDetails) SetMetadataExtensions(raw []byte) error {
	var extra map[string]json.RawMessage
	if err := json.Unmarshal(raw, &extra); err != nil {
		return err
	}
	for k := range extra {
		if !clientExtension(k) {
			delete(extra, k)
		}
	}
	c.Extensions = extra
	return nil
}

type clientDetailsFields ClientDetails

func (c ClientDetails) MarshalJSON() ([]byte, error) {
	return c.marshalWithSecret("")
}

func (c ClientDetails) marshalWithSecret(secret string) ([]byte, error) {
	data, err := json.Marshal(struct {
		clientDetailsFields
		Secret string `json:"client_secret,omitempty"`
	}{clientDetailsFields(c), secret})
	if err != nil || len(c.Extensions) == 0 {
		return data, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	for k, v := range c.Extensions {
		if clientExtension(k) {
			fields[k] = v
		}
	}
	return json.Marshal(fields)
}

func (c *ClientDetails) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	var extra map[string]json.RawMessage
	for k, v := range fields {
		if clientWireFields[k] {
			continue
		}
		delete(fields, k)
		if clientExtension(k) {
			if extra == nil {
				extra = make(map[string]json.RawMessage)
			}
			extra[k] = v
		}
	}
	typed, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	var decoded clientDetailsFields
	if err := json.Unmarshal(typed, &decoded); err != nil {
		return err
	}
	*c = ClientDetails(decoded)
	c.Extensions = extra
	return nil
}

// ClientDirectoryStore reads current application metadata. For a single lookup,
// return ErrClientNotFound when the client is absent or requires unresolved discovery.
// PublicOAuthClient also hides disabled clients. ListOAuthClients filters by
// reference when supplied, otherwise by user. A nonempty user owner takes precedence.
type ClientDirectoryStore interface {
	LookupOAuthClient(ctx context.Context, id string) (ClientDetails, error)
	PublicOAuthClient(ctx context.Context, id string) (PublicClient, error)
	ListOAuthClients(ctx context.Context, userID, referenceID string) ([]ClientDetails, error)
}

// ClientAccess describes an authenticated management action. The ID is empty for list and create.
type ClientAccess struct {
	RegistrationAccess
	Action   string
	ClientID string
}

func (opts Options) allowClient(ctx context.Context, a RegistrationAccess, action, id string) error {
	if opts.ClientPrivileges == nil {
		return nil
	}
	ok, err := opts.ClientPrivileges(ctx, ClientAccess{RegistrationAccess: a, Action: action, ClientID: id})
	if err != nil {
		return err
	}
	if !ok {
		return auth.StatusOnlyError(http.StatusUnauthorized)
	}
	return nil
}

func (opts Options) activeClientReference(ctx context.Context, a RegistrationAccess) (string, error) {
	if opts.ClientReference == nil {
		return "", nil
	}
	return opts.ClientReference(ctx, a)
}

func (opts Options) ownedClient(ctx context.Context, store ClientDirectoryStore, access RegistrationAccess, id string) (ClientDetails, error) {
	c, err := store.LookupOAuthClient(ctx, id)
	if err != nil {
		return ClientDetails{}, err
	}
	if c.UserID != nil && *c.UserID != "" {
		if *c.UserID == access.User.ID {
			return c, nil
		}
	} else if c.ReferenceID != nil && *c.ReferenceID != "" {
		ref, err := opts.activeClientReference(ctx, access)
		if err != nil {
			return ClientDetails{}, err
		}
		if ref == *c.ReferenceID {
			return c, nil
		}
	}
	return ClientDetails{}, auth.StatusOnlyError(http.StatusUnauthorized)
}

func (opts Options) clientEndpoint(action string) auth.Endpoint {
	return auth.Endpoint{Method: http.MethodGet, Path: "/oauth2/" + action, Handler: func(c auth.EndpointContext) (any, error) {
		ctx := c.Request.Context()
		c.ResponseHeader.Set("Cache-Control", "no-store")
		var id string
		if action != "get-clients" {
			values := c.Request.URL.Query()["client_id"]
			if len(values) != 1 {
				got := "undefined"
				if len(values) > 1 {
					got = "array"
				}
				return nil, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "[query.client_id] Invalid input: expected string, received " + got}
			}
			id = values[0]
		}
		session, err := c.Auth.GetSession(ctx, c.Request.Header)
		if err != nil {
			return nil, err
		}
		if session == nil {
			return nil, &auth.APIError{Status: 401, Code: "UNAUTHORIZED", Message: "Unauthorized"}
		}
		store, ok := c.Store().(ClientDirectoryStore)
		if !ok {
			return nil, &auth.APIError{Status: 501, Code: "OAUTH_CLIENT_DIRECTORY_UNAVAILABLE", Message: "The configured store does not support OAuth client lookup"}
		}
		notFound := &auth.OAuthError{Status: 404, Code: "not_found", Description: "client not found"}
		if action == "public-client" {
			client, err := store.PublicOAuthClient(ctx, id)
			if errors.Is(err, ErrClientNotFound) {
				return nil, notFound
			}
			client.RedirectURIs = []string{}
			return client, err
		}
		if err := session.Session.RequireOwner(); err != nil {
			return nil, err
		}
		access := RegistrationAccess{SessionResult: *session, Headers: c.Request.Header.Clone()}
		if action == "get-clients" {
			if err := opts.allowClient(ctx, access, "list", ""); err != nil {
				return nil, err
			}
			ref, err := opts.activeClientReference(ctx, access)
			if err != nil {
				return nil, err
			}
			return store.ListOAuthClients(ctx, session.User.ID, ref)
		}
		if err := opts.allowClient(ctx, access, "read", id); err != nil {
			return nil, err
		}
		client, err := opts.ownedClient(ctx, store, access, id)
		if errors.Is(err, ErrClientNotFound) {
			return nil, notFound
		}
		return client, err
	}}
}
