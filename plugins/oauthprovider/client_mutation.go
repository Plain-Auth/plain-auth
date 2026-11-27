package oauthprovider

import (
	"context"
	"errors"
	"slices"

	auth "github.com/Plain-Org/plain-auth"
)

func (opts Options) clientMutationAccess(c auth.EndpointContext, action string) (auth.EndpointContext, string, RegistrationAccess, error) {
	c.ResponseHeader.Set("Cache-Control", "no-store")
	c.ResponseHeader.Set("Pragma", "no-cache")
	var access RegistrationAccess
	id, ok := c.Body["client_id"].(string)
	if !ok {
		return c, "", access, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "[body.client_id] Invalid input: expected string, received " + consentFieldType(c.Body, "client_id")}
	}
	ctx := c.Request.Context()
	session, err := c.Auth.GetSession(ctx, c.Request.Header)
	if err != nil {
		return c, "", access, err
	}
	if session == nil {
		return c, "", access, &auth.APIError{Status: 401, Code: "UNAUTHORIZED", Message: "Unauthorized"}
	}
	if err := session.Session.RequireOwner(); err != nil {
		return c, "", access, err
	}
	access = RegistrationAccess{SessionResult: *session, Headers: c.Request.Header.Clone()}
	if err := opts.allowClient(ctx, access, action, id); err != nil {
		return c, "", access, err
	}
	if slices.Contains(opts.ImmutableClientIDs, id) {
		return c, "", access, registrationProblem(400, "invalid_client", "trusted clients must be updated manually")
	}
	c, err = opts.discoverRequestClient(c, id)
	return c, id, access, err
}

func (c ClientDetails) ownerIDs() (userID, referenceID string) {
	if c.UserID != nil && *c.UserID != "" {
		return *c.UserID, ""
	}
	if c.ReferenceID != nil {
		return "", *c.ReferenceID
	}
	return "", ""
}

// ClientDeletionStore removes a local registration and its dependent grants
// and tokens atomically. Implementations must recheck the current owner.
type ClientDeletionStore interface {
	ClientDirectoryStore
	DeleteOAuthClient(ctx context.Context, clientID, userID, referenceID string) error
}

func (opts Options) deleteClient(c auth.EndpointContext) (any, error) {
	c, id, access, err := opts.clientMutationAccess(c, "delete")
	if err != nil {
		return nil, err
	}
	store, ok := c.Store().(ClientDeletionStore)
	if !ok {
		return nil, &auth.APIError{Status: 501, Code: "OAUTH_CLIENT_DELETION_UNAVAILABLE", Message: "The configured store does not support OAuth client deletion"}
	}
	ctx := c.Request.Context()
	client, err := opts.ownedClient(ctx, store, access, id)
	if err == nil {
		user, ref := client.ownerIDs()
		err = store.DeleteOAuthClient(ctx, id, user, ref)
	}
	if errors.Is(err, ErrClientNotFound) {
		return nil, registrationProblem(404, "not_found", "client not found")
	}
	return auth.EmptyResponse{}, err
}
