package sso

import (
	"context"
	"encoding/json"
	"time"

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
	if len(c.Body) != 2 || len(config) != 1 || len(metadata) != 1 || raw == "" {
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
	// The size is checked once the caller may see the provider, as in
	// another runtime.
	if len(raw) > o.SAML.metadataLimit() {
		return nil, metadataTooLarge(o.SAML.metadataLimit())
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
	public := o.public(c, p)
	_, public.DomainVerified, err = o.domainStatus(ctx, store, p, "")
	return public, err
}

// metadataOnlyUpdate reports a body that replaces only the IdP metadata
// document, which keeps its dedicated path pinned to the examined
// configuration.
func metadataOnlyUpdate(body map[string]any) bool {
	config, _ := body["samlConfig"].(map[string]any)
	metadata, _ := config["idpMetadata"].(map[string]any)
	_, has := metadata["metadata"]
	return len(body) == 2 && len(config) == 1 && len(metadata) == 1 && has
}

// checkSAMLPatch refuses key material, SP metadata XML and an oversized IdP
// document before the store is touched.
func (o Options) checkSAMLPatch(patch map[string]any) error {
	if samlKeyFields(patch) {
		return errSAMLKeyMaterial
	}
	if sp, _ := patch["spMetadata"].(map[string]any); sp != nil {
		if _, ok := sp["metadata"]; ok {
			return errSPMetadataXML
		}
	}
	if idp, _ := patch["idpMetadata"].(map[string]any); idp != nil {
		if doc, _ := idp["metadata"].(string); len(doc) > o.SAML.metadataLimit() {
			return metadataTooLarge(o.SAML.metadataLimit())
		}
	}
	return nil
}

// mergeSAMLUpdate overlays the supplied SAML fields on the current
// configuration, as another runtime merges them: idpMetadata and spMetadata
// merge key by key, a mapping replaces the whole mapping, and a null
// idpInitiatedCallbackUrl clears it. The result passes the registration
// checks, and the algorithms are checked again when the patch names them.
func (o Options) mergeSAMLUpdate(current SAMLConfig, patch map[string]any, issuer string) (*SAMLConfig, error) {
	raw, err := json.Marshal(current)
	if err != nil {
		return nil, err
	}
	var merged map[string]any
	if err = json.Unmarshal(raw, &merged); err != nil {
		return nil, err
	}
	for key, value := range patch {
		switch key {
		case "idpInitiatedCallbackUrl":
			if value == nil {
				delete(merged, key)
				continue
			}
		case "idpMetadata", "spMetadata":
			fields, ok := value.(map[string]any)
			if !ok {
				return nil, ErrInvalidSAML
			}
			section, _ := merged[key].(map[string]any)
			if section == nil {
				section = map[string]any{}
			}
			for k, v := range fields {
				if v == nil {
					return nil, ErrInvalidSAML
				}
				section[k] = v
			}
			merged[key] = section
			continue
		case "entryPoint", "cert", "audience", "callbackUrl", "mapping", "wantAssertionsSigned", "authnRequestsSigned", "identifierFormat", "signatureAlgorithm", "digestAlgorithm":
		default:
			return nil, apiError(400, "Unsupported SAML update field")
		}
		if value == nil {
			return nil, ErrInvalidSAML
		}
		merged[key] = value
	}
	merged["issuer"] = issuer
	if raw, err = json.Marshal(merged); err != nil {
		return nil, err
	}
	next, err := DecodeSAMLConfig(raw)
	if err != nil {
		return nil, ErrInvalidSAML
	}
	if err = requireCertSource(next); err != nil {
		return nil, err
	}
	_, signature := patch["signatureAlgorithm"]
	_, digest := patch["digestAlgorithm"]
	if signature || digest {
		if err = o.SAML.Algorithms.checkConfig(*next); err != nil {
			return nil, err
		}
	}
	if !next.MetadataValidAt(time.Now()) {
		return nil, ErrInvalidSAML
	}
	return next, nil
}
