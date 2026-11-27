package oauthprovider

import (
	"maps"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
)

// createClient serves POST /oauth2/create-client: a signed-in user creates an
// application without dynamic registration, as another runtime's
// createOAuthClient does. The route is mounted whether or not dynamic
// registration is enabled.
func (opts Options) createClient(c auth.EndpointContext) (any, error) {
	c.ResponseHeader.Set("Cache-Control", "no-store")
	c.ResponseHeader.Set("Pragma", "no-cache")
	// Fields an owner cannot set are dropped, as that runtime's body schema
	// drops unknown fields, where /oauth2/register refuses them.
	body := maps.Clone(c.Body)
	for _, name := range []string{"skip_consent", "subject_type", "resources"} {
		delete(body, name)
	}
	m, err := readRegistration(body)
	if err != nil {
		return nil, err
	}
	ctx, h := c.Request.Context(), c.Request.Header
	session, err := c.Auth.GetSession(ctx, h)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, &auth.APIError{Status: 401, Code: "UNAUTHORIZED", Message: "Unauthorized"}
	}
	if err := session.Session.RequireOwner(); err != nil {
		return nil, err
	}
	access := RegistrationAccess{SessionResult: *session, Headers: h.Clone()}
	if err := opts.allowClient(ctx, access, "create", ""); err != nil {
		return nil, err
	}
	if may := opts.Registration.MayCreate; may != nil {
		ok, err := may(ctx, access)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, auth.StatusOnlyError(401)
		}
	}
	reference, err := opts.activeClientReference(ctx, access)
	if err != nil {
		return nil, err
	}
	owner := ""
	if reference == "" {
		owner = session.User.ID
	}
	if err := opts.prepareMetadata(c.Auth, &m, managedClient); err != nil {
		return nil, err
	}
	// A client created without a scope may request every configured scope.
	var scopes []string
	if m.Scope != "" {
		scopes = strings.Fields(m.Scope)
	}
	return opts.persistClient(c, m, owner, reference, scopes, false)
}
