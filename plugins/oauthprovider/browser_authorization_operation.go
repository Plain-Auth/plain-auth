package oauthprovider

import (
	"encoding/json"
	"net/http"
	"slices"
)

func browserAuthorizationOperation(method string) json.RawMessage {
	required := []string{"response_type", "client_id", "redirect_uri"}
	props := map[string]any{}
	var params []map[string]any
	for _, key := range []string{"response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method", "prompt", "max_age"} {
		field := map[string]any{"type": "string"}
		switch key {
		case "response_type":
			field["enum"] = []string{"code"}
		case "code_challenge_method":
			field["enum"] = []string{"S256"}
		case "max_age":
			field = map[string]any{"type": "integer", "minimum": 0}
		}
		props[key] = field
		params = append(params, map[string]any{"name": key, "in": "query", "required": slices.Contains(required, key), "schema": field})
	}
	operation := map[string]any{
		"summary":     "Authorize an OAuth client using a browser session",
		"description": "Issues a code for a registered callback when the signed-in owner has approved the requested scopes or the operator has configured the client to skip consent. The issuer can redirect the browser to host sign-in, signup, account selection, post-login and consent pages. A configured signup policy rechecks the active account before code issuance. Silent requests that require interaction receive an OAuth error.",
		"responses": map[string]any{
			"302": map[string]string{"description": "Navigate to a host interaction page, the registered callback or the issuer’s error page"},
			"200": map[string]any{"description": "Redirect instruction for a fetch or JSON client", "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object", "required": []string{"redirect", "url"}, "properties": map[string]any{"redirect": map[string]any{"type": "boolean"}, "url": map[string]any{"type": "string", "format": "uri"}}}}}},
			"429": map[string]string{"description": "Authorization endpoint rate limit exceeded"},
		},
	}
	if method == http.MethodPost {
		operation["requestBody"] = map[string]any{"required": true, "content": map[string]any{tokenFormType: map[string]any{"schema": map[string]any{"type": "object", "required": required, "properties": props}}}}
	} else {
		operation["parameters"] = params
	}
	b, _ := json.Marshal(operation)
	return b
}
