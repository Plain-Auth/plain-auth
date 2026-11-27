package cimd

import (
	"slices"
	"strings"
	"testing"
)

func TestIsClientIDURLCandidate(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://app.example.test/client.json": true, "HTTPS://app.example.test/c": true, "https:app.example.test/c": true, "https:/app.example.test/c": true,
		"http://app.example.test/c": false, "https://": false, "https:": false, "app": false, "": false, "urn:example:app": false,
	} {
		if got := IsClientIDURLCandidate(raw); got != want {
			t.Error("wrong candidate answer", raw, got)
		}
	}
}

// Each client ID URL refusal, in another runtime's order.
func TestValidateClientIDURL(t *testing.T) {
	for _, valid := range []string{"https://app.example.test/client.json", "https://APP.Example.test/c", "https://app.example.test:443/c", "https://app.example.test/c?x=1", "https://my_app.example.test/c"} {
		if err := ValidateClientIDURL(valid); err != nil {
			t.Error("a valid client ID URL was refused", valid, err)
		}
	}
	for raw, want := range map[string]string{
		"https://app.example.test/a/../c":    "client_id URL MUST NOT contain dot segments",
		"https://app.example.test/a/%2e%2e/": "client_id URL MUST NOT contain dot segments",
		"https://app.example.test/./c":       "client_id URL MUST NOT contain dot segments",
		"https://app.example.test/c#f":       "client_id URL MUST NOT contain a fragment",
		"https://app.example.test:99999/c":   "client_id is not a valid URL",
		"https://app.example.test/a b":       "client_id is not a valid URL",
		"https://exa mple.test/c":            "client_id is not a valid URL",
		"https://a<b.test/c":                 "client_id is not a valid URL",
		"http://app.example.test/c":          "client_id URL must use HTTPS",
		"https:app.example.test/c":           "client_id URL MUST use an explicit HTTPS authority form",
		"https:/app.example.test/c":          "client_id URL MUST use an explicit HTTPS authority form",
		"https:///c":                         "client_id URL MUST use an explicit HTTPS authority form",
		"https://app.example.test":           "client_id URL MUST contain an explicit path component",
		"https://app.example.test?x=1":       "client_id URL MUST contain an explicit path component",
		"https://user:pw@app.example.test/c": "client_id URL MUST NOT contain credentials",
		"https://localhost/c":                "client_id URL must not target a private or reserved address",
		"https://10.0.0.1/c":                 "client_id URL must not target a private or reserved address",
		"https://metadata.goog/c":            "client_id URL must not target a private or reserved address",
	} {
		if err := ValidateClientIDURL(raw); err == nil || err.Error() != want {
			t.Error("wrong client ID URL refusal", raw, err, want)
		}
	}
}

const id = "https://app.example.test/client.json"

func doc(members string) []byte {
	if members != "" {
		members = "," + members
	}
	return []byte(`{"client_id":"` + id + `"` + members + `}`)
}

// Each metadata document refusal, in another runtime's order; the MCP
// profile's requirements; warnings; origin-bound fields; and the none
// default.
func TestValidateMetadata(t *testing.T) {
	refused := map[string]struct {
		raw     []byte
		profile Profile
		want    string
	}{
		"array":             {[]byte(`[]`), "", "metadata document is not a JSON object"},
		"null":              {[]byte(`null`), "", "metadata document is not a JSON object"},
		"forbidden":         {doc(`"client_secret":"s"`), "", `metadata document MUST NOT contain "client_secret"`},
		"document order":    {doc(`"skip_consent":true,"disabled":true`), "", `metadata document MUST NOT contain "skip_consent"`},
		"storage spelling":  {doc(`"redirectUris":[]`), "", `metadata document MUST NOT contain "redirectUris"`},
		"type error":        {doc(`"client_uri":7`), "", "invalid value for client_uri"},
		"client_id":         {[]byte(`{"client_id":"https://other.example.test/c"}`), "", `client_id "https://other.example.test/c" does not match the metadata document URL`},
		"mcp client_name":   {doc(`"redirect_uris":["https://app.example.test/cb"]`), ProfileMCP20260728, "client_name must be a non-empty string"},
		"blank client_name": {doc(`"client_name":" ","redirect_uris":["https://app.example.test/cb"]`), ProfileMCP20260728, "client_name cannot be empty"},
		"backchannel":       {doc(`"backchannel_logout_uri":"https://app.example.test/l"`), "", `metadata document MUST NOT contain "backchannel_logout_uri"`},
		"backchannel flag":  {doc(`"backchannel_logout_session_required":true`), "", `metadata document MUST NOT contain "backchannel_logout_session_required"`},
		"symmetric":         {doc(`"token_endpoint_auth_method":"client_secret_jwt"`), "", `symmetric auth method "client_secret_jwt" is prohibited for Client ID Metadata Document clients`},
		"other method":      {doc(`"token_endpoint_auth_method":"tls_client_auth"`), "", `token_endpoint_auth_method must be "none" or "private_key_jwt" for Client ID Metadata Document clients`},
		"keyless":           {doc(`"token_endpoint_auth_method":"private_key_jwt"`), "", "private_key_jwt requires either jwks or jwks_uri in the metadata document"},
		"private jwk":       {doc(`"jwks":{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}]}`), "", "jwks must contain only structurally valid public keys"},
		"jwks_uri relative": {doc(`"jwks_uri":"keys"`), "", "jwks_uri must be a valid URL"},
		"jwks_uri user":     {doc(`"jwks_uri":"https://u:p@app.example.test/keys"`), "", "jwks_uri must not contain credentials"},
		"jwks_uri fragment": {doc(`"jwks_uri":"https://app.example.test/keys#k"`), "", "jwks_uri must not contain a fragment"},
		"mcp redirects":     {doc(`"client_name":"App"`), ProfileMCP20260728, "redirect_uris must be a non-empty array of absolute HTTP(S) or private-use URIs"},
		"bad redirect":      {doc(`"redirect_uris":["ws://app.example.test/cb"]`), "", "redirect_uris must be a non-empty array of absolute HTTP(S) or private-use URIs"},
		"pathless custom":   {doc(`"redirect_uris":["myapp://host"]`), "", "redirect_uris must be a non-empty array of absolute HTTP(S) or private-use URIs"},
		"empty authority":   {doc(`"redirect_uris":["com.example.app:///cb"]`), "", "redirect_uris must be a non-empty array of absolute HTTP(S) or private-use URIs"},
		"logo private":      {doc(`"logo_uri":"https://10.0.0.1/logo.png"`), "", "logo_uri must not point to a private or reserved address"},
		"tos credentials":   {doc(`"tos_uri":"https://u:p@app.example.test/tos"`), "", "tos_uri must not contain credentials"},
		"policy scheme":     {doc(`"policy_uri":"ftp://app.example.test/policy"`), "", "policy_uri must use HTTP(S)"},
		"client_uri url":    {doc(`"client_uri":"not a url"`), "", "client_uri is not a valid URL"},
		"logout origin":     {doc(`"post_logout_redirect_uris":["https://other.example.test/bye"]`), "", `post_logout_redirect_uris value "https://other.example.test/bye" must have the same origin as client_id (https://app.example.test)`},
		"logout host":       {doc(`"post_logout_redirect_uris":["myapp://other.example/logout"]`), "", `post_logout_redirect_uris value "myapp://other.example/logout" must have the same origin as client_id (https://app.example.test)`},
		"logout scheme":     {doc(`"post_logout_redirect_uris":["ftp://app.example.test/bye"]`), "", "all values for post_logout_redirect_uris must use HTTP(S) or a private-use scheme"},
	}
	for name, tc := range refused {
		_, _, err := ValidateMetadata(id, tc.raw, ValidationOptions{Profile: tc.profile})
		if err == nil || err.Error() != tc.want {
			t.Error("wrong refusal for", name, err)
		}
	}
	// Accepted documents.
	got, warnings, err := ValidateMetadata(id, doc(`"client_name":"App","x_custom":1,"client_uri":"https://www.example.test/","redirect_uris":["https://app.example.test/cb","com.example.app:/cb","myapp://host/cb","http://127.0.0.1:7777/cb"],
		"post_logout_redirect_uris":["https://app.example.test/bye","com.example.app:/logout","http://localhost:7777/bye"]`), ValidationOptions{Profile: ProfileMCP20260728})
	if err != nil || got.TokenEndpointAuthMethod != "none" || got.Extensions != nil || len(warnings) != 0 || *got.Name != "App" {
		t.Fatal("a valid document was refused or misread", err, got, warnings)
	}
	if _, _, err := ValidateMetadata(id, doc(""), ValidationOptions{}); err != nil {
		t.Fatal("the generic profile required client_name or redirect_uris", err)
	}
	if method, _, _ := ValidateMetadata(id, doc(`"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://keys.example.test/jwks"`), ValidationOptions{}); method.TokenEndpointAuthMethod != "private_key_jwt" {
		t.Fatal("a stated method was replaced", method.TokenEndpointAuthMethod)
	}
	// Warnings.
	for _, tc := range []struct{ url, warning string }{
		{"https://app.example.test/", "client_id URL path / is NOT RECOMMENDED (§3)"},
		{"https://app.example.test/c?q=1", "client_id URL SHOULD NOT contain a query string (§3)"},
	} {
		_, warnings, err := ValidateMetadata(tc.url, []byte(`{"client_id":"`+tc.url+`"}`), ValidationOptions{})
		if err != nil || !slices.Contains(warnings, tc.warning) {
			t.Error("missing warning", tc.url, warnings, err)
		}
	}
	// Origin-bound fields.
	custom := ValidationOptions{OriginBoundFields: []string{"client_uri"}}
	if _, _, err := ValidateMetadata(id, doc(`"client_uri":"https://www.example.test/"`), custom); err == nil || !strings.Contains(err.Error(), "client_uri value") {
		t.Fatal("a custom origin-bound field was not bound", err)
	}
	if _, _, err := ValidateMetadata(id, doc(`"post_logout_redirect_uris":["https://other.example.test/bye"]`), custom); err != nil {
		t.Fatal("the default field stayed bound with a custom list", err)
	}
	if _, _, err := ValidateMetadata(id, doc(`"post_logout_redirect_uris":["https://other.example.test/bye"]`), ValidationOptions{OriginBoundFields: []string{}}); err != nil {
		t.Fatal("an empty list did not disable binding", err)
	}
	bound := ValidationOptions{OriginBoundFields: []string{"redirect_uris"}}
	if _, _, err := ValidateMetadata(id, doc(`"redirect_uris":["myapp://other.example/cb","http://127.0.0.1:9/cb"]`), bound); err != nil {
		t.Fatal("private-use and loopback redirect URIs were bound", err)
	}
	if _, _, err := ValidateMetadata(id, doc(`"redirect_uris":["https://other.example.test/cb"]`), bound); err == nil {
		t.Fatal("a cross-origin redirect URI passed a bound redirect_uris")
	}
	// The loopback exemption is for redirect URIs alone.
	if _, _, err := ValidateMetadata(id, doc(`"jwks_uri":"https://127.0.0.1/keys"`), ValidationOptions{OriginBoundFields: []string{"jwks_uri"}}); err == nil {
		t.Fatal("a loopback URL in a bound field other than a redirect field was exempt")
	}
}
