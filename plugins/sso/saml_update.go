package sso

import (
	"context"
	"encoding/json"

	auth "github.com/Plain-Org/plain-auth"
)

// SAMLMetadataStore replaces one registered IdP metadata document under a live
// direct-session and tenant check. ExpectedReference is the examined configuration.
type SAMLMetadataStore interface {
	UpdateSSOMetadata(ctx context.Context, actor Actor, id, recordID, expectedReference, metadata string, guard MutationGuard) (Provider, error)
}

var ErrMetadataStorageSize = &auth.APIError{Status: 400, Message: "SAML configuration exceeds the database column capacity"}

var ErrLinkedIdentity = &auth.APIError{Status: 409, Message: "Cannot change SSO provider identity fields while linked accounts exist"}

// WithIDPMetadata builds the effective assertion authority from the new XML alone.
func (c SAMLConfig) WithIDPMetadata(raw string) (*SAMLConfig, error) {
	if raw == "" || len(raw) > maxSAMLMetadataBytes {
		return nil, ErrInvalidSAML
	}
	c.IDPMetadata.Metadata = raw
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return DecodeSAMLConfig(data)
}

func (o Options) updateSAMLMetadata(c auth.EndpointContext, store Store, actor Actor) (any, error) {
	// Only the IdP metadata changes, so the recorded algorithms need no
	// recheck.
	id, _ := c.Body["providerId"].(string)
	if !MutableProviderID(id) || c.Auth.HasOAuthProvider(id) {
		return nil, ErrMissing
	}
	config, _ := c.Body["samlConfig"].(map[string]any)
	if samlKeyFields(config) {
		return nil, errSAMLKeyMaterial
	}
	metadata, _ := config["idpMetadata"].(map[string]any)
	raw, _ := metadata["metadata"].(string)
	if len(c.Body) != 2 || len(config) != 1 || len(metadata) != 1 || raw == "" || len(raw) > o.SAML.metadataLimit() {
		return nil, apiError(400, "Supply samlConfig.idpMetadata.metadata for this update")
	}
	ctx := c.Request.Context()
	visible, err := store.ReadSSOProviders(ctx, actor, id)
	if err != nil {
		return nil, err
	}
	if len(visible) != 1 || visible[0].SAML == nil {
		return nil, ErrMissing
	}
	current, err := store.(BrowserStore).FindBrowserProvider(ctx, Selector{ProviderID: id, Protocol: "saml"})
	if err != nil {
		return nil, err
	}
	if current.ID != visible[0].ID {
		return nil, ErrChanged
	}
	candidate := current.Provider
	candidate.SAML, err = current.SAML.WithIDPMetadata(raw)
	if err != nil {
		return nil, err
	}
	if _, err = o.samlSP(c, candidate); err != nil {
		return nil, err
	}
	writer, ok := store.(SAMLMetadataStore)
	if !ok {
		return nil, apiError(501, "This store does not support transactional SAML metadata updates")
	}
	p, err := writer.UpdateSSOMetadata(ctx, actor, id, current.ID, current.Reference, raw, o.GuardProviderMutation)
	if err != nil {
		return nil, err
	}
	public := sanitized(c, p)
	_, public.DomainVerified, err = o.domainStatus(ctx, store, p, "")
	return public, err
}
