package oauthprovider

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
)

// A metadata document keeps unknown members, skip_consent included, and
// writes them back; client_id, client_secret and the timestamps are typed;
// the registration rules still apply; and anything but an object is refused.
func TestParseClientMetadataDocument(t *testing.T) {
	full := `{"client_id":"https://app.example.test/client.json","client_name":"App","redirect_uris":["https://app.example.test/cb"],
		"token_endpoint_auth_method":"none","grant_types":["authorization_code"],"response_types":["code"],"client_secret_expires_at":1e3,
		"client_id_issued_at":0,"client_secret":"s","skip_consent":true,"software_x":{"a":[1,2]},"jwks":{"keys":[{"kty":"OKP","crv":"Ed25519","x":"abc"}]}}`
	d, err := ParseClientMetadataDocument([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	if d.ClientID != "https://app.example.test/client.json" || *d.Name != "App" || d.TokenEndpointAuthMethod != "none" || *d.SecretExpiresAt != 1000 || *d.IssuedAt != 0 || *d.ClientSecret != "s" {
		t.Fatal("the typed members were not read", d)
	}
	if len(d.Extensions) != 2 || string(d.Extensions["skip_consent"]) != "true" || string(d.Extensions["software_x"]) != `{"a":[1,2]}` {
		t.Fatal("the extensions were not kept raw", d.Extensions)
	}
	out, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if back["skip_consent"] != true || back["client_id"] != d.ClientID || back["client_secret_expires_at"] != 1000.0 || back["client_name"] != "App" || back["software_x"] == nil {
		t.Fatal("MarshalJSON lost a member", string(out))
	}
	// An extension cannot override a typed member when written.
	d.Extensions["client_secret"] = json.RawMessage(`"planted"`)
	d.ClientSecret = nil
	if out, _ := json.Marshal(d); strings.Contains(string(out), "planted") {
		t.Fatal("an extension wrote a typed member", string(out))
	}
	refused := map[string]struct{ doc, code, description string }{
		"missing client_id":   {`{"client_name":"App"}`, "invalid_client_metadata", "invalid value for client_id"},
		"empty client_id":     {`{"client_id":""}`, "invalid_client_metadata", "client_id cannot be empty"},
		"blank client_id":     {`{"client_id":"  "}`, "invalid_client_metadata", "client_id cannot be empty"},
		"numeric client_id":   {`{"client_id":7}`, "invalid_client_metadata", "invalid value for client_id"},
		"numeric secret":      {`{"client_id":"a","client_secret":7}`, "invalid_client_metadata", "invalid value for client_secret"},
		"negative expiry":     {`{"client_id":"a","client_secret_expires_at":-1}`, "invalid_client_metadata", "client_secret_expires_at must be a non-negative integer"},
		"fractional issued":   {`{"client_id":"a","client_id_issued_at":1.5}`, "invalid_client_metadata", "client_id_issued_at must be a non-negative integer"},
		"string expiry":       {`{"client_id":"a","client_secret_expires_at":"5"}`, "invalid_client_metadata", "client_secret_expires_at must be a non-negative integer"},
		"unsafe integer":      {`{"client_id":"a","client_id_issued_at":9007199254740992}`, "invalid_client_metadata", "client_id_issued_at must be a non-negative integer"},
		"empty redirect_uris": {`{"client_id":"a","redirect_uris":[]}`, "invalid_redirect_uri", "redirect_uris must contain at least one value"},
		"blank client_name":   {`{"client_id":"a","client_name":" "}`, "invalid_client_metadata", "client_name cannot be empty"},
		"application_type":    {`{"client_id":"a","application_type":"desktop"}`, "invalid_client_metadata", "application_type must be web or native"},
		"response_type":       {`{"client_id":"a","response_types":["token"]}`, "invalid_client_metadata", "unsupported response_type token"},
		"jwks shape":          {`{"client_id":"a","jwks":{"keys":[]}}`, "invalid_client_metadata", "jwks must be an RFC 7517 JWK Set object with a non-empty keys array"},
		"null member":         {`{"client_id":"a","client_uri":null}`, "invalid_client_metadata", "invalid value for client_uri"},
		"array":               {`[]`, "invalid_client_metadata", "metadata document is not a JSON object"},
		"null":                {`null`, "invalid_client_metadata", "metadata document is not a JSON object"},
		"trailing data":       {`{"client_id":"a"} {}`, "invalid_client_metadata", "metadata document is not a JSON object"},
		"registration first":  {`{"client_name":" ","client_id":""}`, "invalid_client_metadata", "client_name cannot be empty"},
	}
	for name, tc := range refused {
		_, err := ParseClientMetadataDocument([]byte(tc.doc))
		var oauthErr *auth.OAuthError
		if !errors.As(err, &oauthErr) || oauthErr.Code != tc.code || oauthErr.Description != tc.description {
			t.Error("wrong refusal for", name, err)
		}
	}
	// A minimal document has no extensions and no optional members.
	if d, err := ParseClientMetadataDocument([]byte(`{"client_id":"a"}`)); err != nil || d.Extensions != nil || d.ClientSecret != nil || d.IssuedAt != nil {
		t.Fatal("a minimal document was misread", d, err)
	}
}

// Registration still refuses skip_consent.
func TestRegistrationRefusesSkipConsent(t *testing.T) {
	_, err := readRegistration(map[string]any{"skip_consent": false})
	var oauthErr *auth.OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Description != "skip_consent cannot be set during dynamic client registration" {
		t.Fatal("registration accepted skip_consent", err)
	}
}

// The forbidden names are the exact, case-sensitive set of 36.
func TestIsForbiddenMetadataDocumentField(t *testing.T) {
	names := strings.Fields(`disabled client_secret client_secret_expires_at client_id_issued_at skip_consent enable_end_session
		require_pkce reference_id user_id resources clientSecret clientDiscoveryId skipConsent enableEndSession requirePKCE
		referenceId userId clientId applicationType tokenEndpointAuthMethod redirectUris postLogoutRedirectUris grantTypes
		responseTypes scopes expiresAt createdAt updatedAt softwareId softwareVersion softwareStatement backchannelLogoutUri
		backchannelLogoutSessionRequired jwksUri dpopBoundAccessTokens subjectType`)
	if len(names) != 36 || len(forbiddenDocumentFields) != 36 {
		t.Fatal("the forbidden set is not 36 names", len(names), len(forbiddenDocumentFields))
	}
	for _, name := range names {
		if !IsForbiddenMetadataDocumentField(name) {
			t.Error("a server-owned name was allowed", name)
		}
	}
	for _, name := range []string{"client_id", "client_name", "jwks", "jwks_uri", "redirect_uris", "Disabled", "SKIP_CONSENT"} {
		if IsForbiddenMetadataDocumentField(name) {
			t.Error("a document name was forbidden", name)
		}
	}
}
