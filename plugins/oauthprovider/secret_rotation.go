package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// RotatedClient returns the one-time issued secret and the client's owner-visible metadata.
type RotatedClient struct {
	ClientDetails
	ClientSecret string `json:"client_secret"`
}

func (c RotatedClient) MarshalJSON() ([]byte, error) {
	return c.ClientDetails.marshalWithSecret(c.ClientSecret)
}
func (c *RotatedClient) UnmarshalJSON(data []byte) error {
	var details ClientDetails
	if err := json.Unmarshal(data, &details); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	var secret string
	if err := json.Unmarshal(fields["client_secret"], &secret); err != nil {
		return err
	}
	if secret == "" {
		return errors.New("oauthprovider: rotation response is missing the replacement credential")
	}
	*c = RotatedClient{ClientDetails: details, ClientSecret: secret}
	return nil
}

// ClientSecretReplacement carries exactly one authorized owner and the encoded replacement.
type ClientSecretReplacement struct {
	ClientID      string
	UserID        string
	ReferenceID   string
	EncodedSecret string
	UpdatedAt     time.Time
}

// SecretRotationStore atomically verifies current ownership, auth method and
// credential presence before writing the replacement. An authorized personal
// owner takes precedence over a tenant reference. Store only the encoded secret.
type SecretRotationStore interface {
	ClientDirectoryStore
	RotateOAuthClientSecret(ctx context.Context, change ClientSecretReplacement) (ClientDetails, error)
}

func (c ClientDetails) canRotateSecret() bool {
	return c.SecretExpiresAt != nil && (c.TokenEndpointAuthMethod == nil || *c.TokenEndpointAuthMethod == "client_secret_basic" || *c.TokenEndpointAuthMethod == "client_secret_post")
}

func (opts Options) rotateClientSecret(c auth.EndpointContext) (any, error) {
	ctx := c.Request.Context()
	id, access, err := opts.clientMutationAccess(c, "rotate")
	if err != nil {
		return nil, err
	}
	store, ok := c.Store().(SecretRotationStore)
	if !ok {
		return nil, &auth.APIError{Status: 501, Code: "OAUTH_CLIENT_ROTATION_UNAVAILABLE", Message: "The configured store does not support OAuth client secret rotation"}
	}
	client, err := opts.ownedClient(ctx, store, access, id)
	if errors.Is(err, ErrClientNotFound) {
		return nil, registrationProblem(404, "not_found", "client not found")
	}
	if err != nil {
		return nil, err
	}
	if !client.canRotateSecret() {
		return nil, rotationUnavailable()
	}
	user, ref := client.ownerIDs()
	issued, stored, err := opts.Registration.issueSecret(ctx)
	if err != nil {
		return nil, err
	}
	updated, err := store.RotateOAuthClientSecret(ctx, ClientSecretReplacement{ClientID: id, UserID: user, ReferenceID: ref, EncodedSecret: stored, UpdatedAt: time.Now().UTC().Truncate(time.Second)})
	if errors.Is(err, ErrClientNotFound) {
		return nil, registrationProblem(404, "not_found", "client not found")
	}
	if errors.Is(err, ErrSecretRotationUnavailable) {
		return nil, rotationUnavailable()
	}
	if err != nil {
		return nil, err
	}
	return RotatedClient{ClientDetails: updated, ClientSecret: issued}, nil
}

// ErrSecretRotationUnavailable identifies registrations without a rotatable shared credential.
var ErrSecretRotationUnavailable = errors.New("secret rotation is only available for clients using client_secret authentication")

func rotationUnavailable() error {
	return registrationProblem(http.StatusBadRequest, "invalid_client", ErrSecretRotationUnavailable.Error())
}
