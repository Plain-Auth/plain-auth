package oauthprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

const keyRotationPath = "/oauth2/client/rotate-keys"

const keyRotationOperation = `{
  "summary":"Replace the public keys of a registered OAuth application",
  "description":"Sign a single-use assertion with a current inline key and address it to this endpoint. Supply the complete replacement public JWK Set.",
  "security":[{}],
  "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object",
    "required":["client_assertion","client_assertion_type","jwks"],"properties":{
      "client_assertion":{"type":"string","format":"jwt"},
      "client_assertion_type":{"type":"string","enum":["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]},
      "jwks":{"type":"object","required":["keys"],"properties":{"keys":{"type":"array","minItems":1,"items":{"type":"object"}}}}
    }}}}},
  "responses":{"200":{"description":"Client ID and replacement public JWK Set","content":{"application/json":{"schema":{"type":"object","required":["client_id","jwks"],"properties":{"client_id":{"type":"string"},"jwks":{"type":"object","required":["keys"],"properties":{"keys":{"type":"array","items":{"type":"object"}}}}}}}}},"400":{"description":"Invalid assertion, client or replacement keys"},
    "401":{"description":"Signature or claims rejected"},"403":{"description":"Client key rotation is disabled"},"409":{"description":"The registration changed during rotation"}}
}`

// ClientKeyRotationStore verifies the locked registration through check and
// atomically reserves the assertion digest and replaces the inline keys. A
// duplicate digest must return ErrAssertionReplay. A failed write rolls back both changes.
type ClientKeyRotationStore interface {
	MachineClientReader
	RotateOAuthClientKeys(ctx context.Context, id, digest string, expires time.Time, keys json.RawMessage, check func(MachineClient) error) error
}

func (opts Options) rotateClientKeys(c auth.EndpointContext) (any, error) {
	c.ResponseHeader.Set("Cache-Control", "no-store")
	c.ResponseHeader.Set("Pragma", "no-cache")
	compact, ok := c.Body["client_assertion"].(string)
	if !ok {
		return nil, invalidClient("client_assertion must be a string")
	}
	kind, ok := c.Body["client_assertion_type"].(string)
	if !ok {
		return nil, invalidClient("client_assertion_type must be a string")
	}
	jwks, _ := c.Body["jwks"].(map[string]any)
	entries, _ := jwks["keys"].([]any)
	if len(entries) == 0 {
		return nil, metadataProblem("jwks must contain a non-empty keys array")
	}
	for _, entry := range entries {
		if _, ok := entry.(map[string]any); !ok {
			return nil, metadataProblem("jwks keys must be objects")
		}
	}
	if !opts.Assertions.AllowKeyRotation {
		return nil, registrationProblem(http.StatusForbidden, "access_denied", "Client key rotation is disabled")
	}
	keys, err := json.Marshal(map[string]any{"keys": entries})
	if err != nil {
		return nil, metadataProblem("jwks must be a public JWK Set")
	}
	if _, err := decodeAssertionKeys(keys); err != nil {
		return nil, metadataProblem("jwks must contain valid public asymmetric keys")
	}
	assertion, err := parseClientAssertion(kind, compact, "")
	if err != nil {
		return nil, err
	}
	c, err = opts.discoverRequestClient(c, assertion.clientID)
	if err != nil {
		return nil, err
	}
	ctx := c.Request.Context()
	store := c.Store().(ClientKeyRotationStore) // Validated at startup when enabled.
	first, err := store.LookupMachineClient(ctx, assertion.clientID)
	if err != nil {
		return nil, tokenEndpointError(c.ResponseHeader, "", err)
	}
	// A discovered client's keys belong to its published metadata.
	if ResolvedDiscovery(ctx, first.ClientID) != "" {
		return nil, invalidClient("client keys are not stored inline; rotate them where the client publishes them")
	}
	in := tokenRequest{id: assertion.clientID, method: "private_key_jwt"}
	if err := in.checkMethod(first); err != nil {
		return nil, err
	}
	if slices.Contains(opts.ImmutableClientIDs, first.ClientID) {
		return nil, invalidClient("trusted clients must be updated manually")
	}
	if first.JWKS == "" || first.JWKSURI != "" {
		return nil, invalidClient("client keys are not stored inline; rotate them where the client publishes them")
	}
	// Issuer-wide assertions never authorize changing an application's credentials.
	endpoint := c.Auth.PublicURL() + keyRotationPath
	digest, expires, err := opts.signedAssertion(c, assertion, first, endpoint)
	if err != nil {
		return nil, tokenEndpointError(c.ResponseHeader, "", err)
	}
	err = store.RotateOAuthClientKeys(ctx, first.ClientID, digest, expires, keys, func(current MachineClient) error {
		if !time.Now().Before(expires) {
			return failedAssertion()
		}
		if err := in.checkMethod(current); err != nil {
			return err
		}
		if first.RowID != current.RowID || first.JWKS != current.JWKS || current.JWKSURI != "" {
			return registrationProblem(http.StatusConflict, "invalid_request", "client keys changed while rotating; retry with a fresh client assertion")
		}
		return nil
	})
	if err != nil {
		return nil, tokenEndpointError(c.ResponseHeader, "", assertionStoreError(err))
	}
	return RotatedClientKeys{ClientID: first.ClientID, JWKS: keys}, nil
}

// RotatedClientKeys contains the public keys currently registered after a rotation.
type RotatedClientKeys struct {
	ClientID string          `json:"client_id"`
	JWKS     json.RawMessage `json:"jwks"`
}
