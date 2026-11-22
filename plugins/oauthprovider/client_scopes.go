package oauthprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/jsjson"
)

// ClientCredentialsScopeChange identifies the authorized registration, its ownership
// at authorization time, and the complete replacement for its machine scope grant.
type ClientCredentialsScopeChange struct {
	ClientID, ExpectedUserID, ExpectedReferenceID string
	Scopes                                        []string
	UpdatedAt                                     time.Time
}

// CheckTarget must be called against the current registration within the same
// transaction as the write. A change of ownership invalidates the authorization.
func (change ClientCredentialsScopeChange) CheckTarget(c ClientDetails) error {
	if c.ClientID != change.ClientID {
		return ErrClientNotFound
	}
	user, ref := c.ownerIDs()
	if user != change.ExpectedUserID || ref != change.ExpectedReferenceID {
		return auth.StatusOnlyError(http.StatusUnauthorized)
	}
	if len(change.Scopes) == 0 {
		return nil
	}
	if !slices.Contains(c.GrantTypes, "client_credentials") {
		return metadataProblem("client_credentials_scopes requires the client_credentials grant")
	}
	if c.TokenEndpointAuthMethod != nil && *c.TokenEndpointAuthMethod == "none" {
		return metadataProblem("public clients cannot be assigned client_credentials scopes")
	}
	return nil
}

// ClientCredentialsScopeStore changes only the machine grant and update timestamp.
// It must lock the registration and recheck CheckTarget at the point of the write.
type ClientCredentialsScopeStore interface {
	LookupOAuthClient(context.Context, string) (ClientDetails, error)
	SetOAuthClientCredentialsScopes(context.Context, ClientCredentialsScopeChange) error
}

// ClientManager provides server-only operations on OAuth registrations.
type ClientManager struct {
	auth  *auth.Auth
	store ClientCredentialsScopeStore
	opts  Options
}

// NewClientManager uses the same options as the mounted OAuth plugin. Its
// operations are called by host server code and have no public HTTP endpoints.
func NewClientManager(a *auth.Auth, store ClientCredentialsScopeStore, opts Options) (*ClientManager, error) {
	if a == nil || store == nil {
		return nil, errors.New("oauthprovider: client management requires auth and a client scope store")
	}
	return &ClientManager{auth: a, store: store, opts: opts.clientManagementOptions()}, nil
}

// SetClientCredentialsScopes replaces the client's machine scope ceiling. Owners
// may clear a grant. Assigning any scope or changing another owner's grant requires
// explicit approval from ClientPrivileges for configure-client-credentials-scopes.
func (m *ClientManager) SetClientCredentialsScopes(ctx context.Context, headers http.Header, id string, scopes []string) ([]string, error) {
	normalized, err := normalizeMachineScopes(scopes)
	if err != nil {
		return nil, err
	}
	session, err := m.auth.GetSession(ctx, headers)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, auth.StatusOnlyError(http.StatusUnauthorized)
	}
	if err := session.Session.RequireOwner(); err != nil {
		return nil, err
	}
	access := RegistrationAccess{SessionResult: *session, Headers: headers.Clone()}
	if err := m.opts.allowClient(ctx, access, "update", id); err != nil {
		return nil, err
	}
	if slices.Contains(m.opts.ImmutableClientIDs, id) {
		return nil, registrationProblem(400, "invalid_client", "trusted clients must be updated manually")
	}
	c, err := m.store.LookupOAuthClient(ctx, id)
	if err != nil {
		return nil, scopeManagementError(err)
	}
	owned, err := m.opts.ownsClient(ctx, access, c)
	if err != nil {
		return nil, err
	}
	if !owned {
		if err := m.opts.allowClient(ctx, access, "configure-client-credentials-scopes", id); err != nil {
			return nil, err
		}
	}
	user, ref := c.ownerIDs()
	change := ClientCredentialsScopeChange{ClientID: id, ExpectedUserID: user, ExpectedReferenceID: ref, Scopes: normalized, UpdatedAt: time.Now().UTC().Truncate(time.Second)}
	if err := change.CheckTarget(c); err != nil {
		return nil, err
	}
	var invalid []string
	for _, scope := range normalized {
		switch scope {
		case "openid", "profile", "email", "offline_access":
			invalid = append(invalid, scope)
		default:
			if !slices.Contains(m.opts.Scopes, scope) {
				invalid = append(invalid, scope)
			}
		}
	}
	if len(invalid) > 0 {
		return nil, registrationProblem(400, "invalid_scope", "The following client_credentials scopes are invalid: "+strings.Join(invalid, ", "))
	}
	if owned && len(normalized) > 0 {
		if err := m.opts.allowClient(ctx, access, "configure-client-credentials-scopes", id); err != nil {
			return nil, err
		}
	}
	if err := m.store.SetOAuthClientCredentialsScopes(ctx, change); err != nil {
		return nil, scopeManagementError(err)
	}
	return normalized, nil
}

func normalizeMachineScopes(scopes []string) ([]string, error) {
	normalized := make([]string, len(scopes))
	var issues []string
	for i, name := range scopes {
		normalized[i] = jsjson.TrimSpace(name)
		if normalized[i] == "" {
			issues = append(issues, fmt.Sprintf("[body.update.client_credentials_scopes.%d] Too small: expected string to have >=1 characters", i))
		}
	}
	if len(issues) > 0 {
		return nil, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: strings.Join(issues, "; ")}
	}
	return distinct(normalized), nil
}

func scopeManagementError(err error) error {
	if errors.Is(err, ErrClientNotFound) {
		return registrationProblem(404, "not_found", "client not found")
	}
	return err
}
