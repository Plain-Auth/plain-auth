package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/jsjson"
)

// ErrClientChanged reports a client that changed between validation and
// the update's write.
var ErrClientChanged = errors.New("OAuth client changed")

// ownerUpdateFields are the registration fields an owner may change, as in
// another runtime's update schema; other fields are ignored.
var ownerUpdateFields = []string{"redirect_uris", "scope", "client_name", "client_uri", "logo_uri", "contacts", "tos_uri", "policy_uri",
	"software_id", "software_version", "software_statement", "post_logout_redirect_uris", "backchannel_logout_uri",
	"backchannel_logout_session_required", "application_type", "grant_types", "response_types"}

// ClientUpdate replaces an owner's registration fields. Fields names the
// fields to write from Metadata, which is the validated whole registration.
// Expected is the client the change was validated against; a store answers
// ErrClientChanged when the locked row differs from it.
type ClientUpdate struct {
	ClientID           string
	Expected           ClientDetails
	Metadata           RegistrationMetadata
	Fields             []string
	ClearMachineScopes bool
	UpdatedAt          time.Time
}

// ClientUpdateStore applies an owner's update in one transaction.
type ClientUpdateStore interface {
	UpdateOAuthClient(context.Context, ClientUpdate) (ClientDetails, error)
}

// updateClient serves POST /oauth2/update-client: an owner replaces
// registration fields, as another runtime's updateOAuthClient does. The
// merged registration is validated outside the store's transaction, and a
// client changed in the meantime answers 409, where that runtime writes
// without a lock.
func (opts Options) updateClient(c auth.EndpointContext) (any, error) {
	c.ResponseHeader.Set("Cache-Control", "no-store")
	update, ok := c.Body["update"].(map[string]any)
	if !ok {
		received := "undefined"
		if raw, present := c.Body["update"]; present {
			received = jsjson.TypeName(raw)
		}
		return nil, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "[body.update] Invalid input: expected object, received " + received}
	}
	id, ok := c.Body["client_id"].(string)
	if !ok {
		return nil, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "[body.client_id] Invalid input: expected string, received " + jsjson.TypeName(c.Body["client_id"])}
	}
	ctx, h := c.Request.Context(), c.Request.Header
	session, err := c.Auth.GetSession(ctx, h)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, auth.StatusOnlyError(http.StatusUnauthorized)
	}
	if err := session.Session.RequireOwner(); err != nil {
		return nil, err
	}
	access := RegistrationAccess{SessionResult: *session, Headers: h.Clone()}
	if err := opts.allowClient(ctx, access, "update", id); err != nil {
		return nil, err
	}
	if slices.Contains(opts.ImmutableClientIDs, id) {
		return nil, registrationProblem(400, "invalid_client", "trusted clients must be updated manually")
	}
	patch := map[string]any{}
	for _, name := range ownerUpdateFields {
		if value, present := update[name]; present {
			patch[name] = value
		}
	}
	if _, err := readRegistration(patch); err != nil {
		return nil, err
	}
	store, ok := c.Store().(ClientUpdateStore)
	directory, isDirectory := c.Store().(ClientDirectoryStore)
	if !ok || !isDirectory {
		return nil, &auth.APIError{Status: 501, Code: "OAUTH_CLIENT_UPDATE_UNAVAILABLE", Message: "The configured store does not support OAuth client updates"}
	}
	current, err := directory.LookupOAuthClient(ctx, id)
	if errors.Is(err, ErrClientNotFound) {
		return nil, registrationProblem(404, "not_found", "client not found")
	}
	if err != nil {
		return nil, err
	}
	owned, err := opts.ownsClient(ctx, access, current)
	if err != nil {
		return nil, err
	}
	if !owned {
		return nil, auth.StatusOnlyError(http.StatusUnauthorized)
	}
	if len(patch) == 0 {
		return current, nil
	}
	// The merged registration passes the same rules as a created client.
	raw, err := json.Marshal(current)
	if err != nil {
		return nil, err
	}
	var merged map[string]any
	if err := json.Unmarshal(raw, &merged); err != nil {
		return nil, err
	}
	delete(merged, "skip_consent")
	maps.Copy(merged, patch)
	m, err := readRegistration(merged)
	if err != nil {
		return nil, err
	}
	if err := opts.prepareMetadata(c.Auth, &m, managedClient); err != nil {
		return nil, err
	}
	fields := slices.Sorted(maps.Keys(patch))
	if slices.Contains(fields, "grant_types") && !slices.Contains(fields, "response_types") {
		fields = append(fields, "response_types")
	}
	change := ClientUpdate{ClientID: id, Expected: current, Metadata: m, Fields: fields, UpdatedAt: time.Now().UTC().Truncate(time.Second),
		ClearMachineScopes: !slices.Contains(m.GrantTypes, "client_credentials") || m.TokenEndpointAuthMethod == "none"}
	updated, err := store.UpdateOAuthClient(ctx, change)
	switch {
	case errors.Is(err, ErrClientNotFound):
		return nil, registrationProblem(404, "not_found", "client not found")
	case errors.Is(err, ErrClientChanged):
		return nil, registrationProblem(409, "invalid_request", "client changed while updating; retry")
	}
	return updated, err
}

// CheckTarget reports whether the locked client is the one the update was
// validated against.
func (u ClientUpdate) CheckTarget(locked ClientDetails) error {
	if locked.ClientID != u.ClientID {
		return ErrClientNotFound
	}
	if !reflect.DeepEqual(locked, u.Expected) {
		return ErrClientChanged
	}
	return nil
}
