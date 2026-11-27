package oauthprovider

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"strings"
)

// ClientMetadataDocument is an OAuth client's metadata as a client discovery
// publishes it, such as a client ID metadata document: the registration
// metadata, the client's own identifier, the server-assigned fields a
// discovery profile must refuse, and every other member as the document
// gave it.
type ClientMetadataDocument struct {
	RegistrationMetadata
	ClientID        string  `json:"client_id"`
	ClientSecret    *string `json:"client_secret,omitempty"`
	SecretExpiresAt *int64  `json:"client_secret_expires_at,omitempty"`
	IssuedAt        *int64  `json:"client_id_issued_at,omitempty"`
	// Extensions holds the members outside this vocabulary, skip_consent
	// included, as raw JSON.
	Extensions map[string]json.RawMessage `json:"-"`
}

// documentFields is the vocabulary a metadata document types; every other
// member is an extension.
var documentFields = func() map[string]bool {
	names := map[string]bool{"client_id": true, "client_secret": true, "client_secret_expires_at": true, "client_id_issued_at": true}
	t := reflect.TypeFor[RegistrationMetadata]()
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		names[name] = true
	}
	return names
}()

// MarshalJSON writes the typed members and then each extension whose name
// is outside the typed vocabulary.
func (d ClientMetadataDocument) MarshalJSON() ([]byte, error) {
	type plain ClientMetadataDocument
	typed, err := json.Marshal(plain(d))
	if err != nil || len(d.Extensions) == 0 {
		return typed, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(typed, &members); err != nil {
		return nil, err
	}
	for name, value := range d.Extensions {
		if !documentFields[name] {
			members[name] = value
		}
	}
	return json.Marshal(members)
}

// ParseClientMetadataDocument reads a client metadata document, as another
// runtime's oauthClientMetadataSchema does. The registration request rules
// apply, except that skip_consent is kept as an extension; client_id must be
// a nonempty string, client_secret a string, and the two timestamps
// non-negative integers. Members outside the vocabulary are kept raw in
// Extensions. A refused document is an invalid_client_metadata error, or the
// error code registration gives the same field. Type errors use the
// registration wording, not the other runtime's schema library text.
func ParseClientMetadataDocument(raw []byte) (ClientMetadataDocument, error) {
	var d ClientMetadataDocument
	var members map[string]json.RawMessage
	var body map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if json.Unmarshal(raw, &members) != nil || members == nil || decoder.Decode(&body) != nil {
		return d, metadataProblem("metadata document is not a JSON object")
	}
	m, err := readRegistrationFields(body, true)
	if err != nil {
		return d, err
	}
	d.RegistrationMetadata = m
	id, ok := body["client_id"].(string)
	if !ok {
		return d, metadataProblem("invalid value for client_id")
	}
	if strings.TrimSpace(id) == "" {
		return d, metadataProblem("client_id cannot be empty")
	}
	d.ClientID = id
	if value, ok := body["client_secret"]; ok {
		secret, ok := value.(string)
		if !ok {
			return d, metadataProblem("invalid value for client_secret")
		}
		d.ClientSecret = &secret
	}
	for _, field := range []struct {
		name string
		out  **int64
	}{{"client_secret_expires_at", &d.SecretExpiresAt}, {"client_id_issued_at", &d.IssuedAt}} {
		value, ok := body[field.name]
		if !ok {
			continue
		}
		number, _ := value.(json.Number)
		x, err := strconv.ParseFloat(string(number), 64)
		if err != nil || x < 0 || x != math.Trunc(x) || x > 1<<53-1 {
			return d, metadataProblem(field.name + " must be a non-negative integer")
		}
		n := int64(x)
		*field.out = &n
	}
	for name, value := range members {
		if !documentFields[name] {
			if d.Extensions == nil {
				d.Extensions = map[string]json.RawMessage{}
			}
			d.Extensions[name] = value
		}
	}
	return d, nil
}

// forbiddenDocumentFields are the server-owned names, in wire and storage
// spellings, that a client ID metadata document must not carry.
var forbiddenDocumentFields = func() map[string]bool {
	names := map[string]bool{}
	for _, name := range strings.Fields(`disabled client_secret client_secret_expires_at client_id_issued_at
		skip_consent enable_end_session require_pkce reference_id user_id resources clientSecret
		clientDiscoveryId skipConsent enableEndSession requirePKCE referenceId userId clientId
		applicationType tokenEndpointAuthMethod redirectUris postLogoutRedirectUris grantTypes
		responseTypes scopes expiresAt createdAt updatedAt softwareId softwareVersion
		softwareStatement backchannelLogoutUri backchannelLogoutSessionRequired jwksUri
		dpopBoundAccessTokens subjectType`) {
		names[name] = true
	}
	return names
}()

// IsForbiddenMetadataDocumentField reports whether a client ID metadata
// document must not carry the member, as another runtime's
// isForbiddenCimdClientMetadataField does: the exact, case-sensitive set of
// server-owned names in both wire and storage spellings.
func IsForbiddenMetadataDocumentField(name string) bool {
	return forbiddenDocumentFields[name]
}
