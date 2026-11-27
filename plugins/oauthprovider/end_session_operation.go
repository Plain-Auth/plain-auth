package oauthprovider

import (
	"encoding/json"
	"net/http"
)

// endSessionOperation describes RP-Initiated Logout for OpenAPI.
func endSessionOperation(method string) json.RawMessage {
	props := map[string]any{}
	var params []map[string]any
	for _, key := range logoutFields {
		field := map[string]any{"type": "string"}
		if key == "post_logout_redirect_uri" {
			field["format"] = "uri"
		}
		props[key] = field
		params = append(params, map[string]any{"name": key, "in": "query", "required": false, "schema": field})
	}
	operation := map[string]any{
		"summary": "End a browser session at the request of an OAuth client",
		"description": "RP-Initiated Logout. A valid id_token_hint for the current browser session, or one sent without browser cookies, ends that session. A request without a usable hint, or for another session, needs the user's confirmation: a browser gets a confirmation page and other callers get 400 invalid_request. " +
			"An exact registered post_logout_redirect_uri is followed, with state added.",
		"responses": map[string]any{
			"200": map[string]any{"description": "Logged out, a confirmation page for a browser, or a redirect instruction for a fetch or JSON client", "content": map[string]any{
				"application/json": map[string]any{"schema": map[string]any{"type": "object", "nullable": true, "properties": map[string]any{"redirect": map[string]any{"type": "boolean"}, "url": map[string]any{"type": "string", "format": "uri"}}}},
				"text/html":        map[string]any{"schema": map[string]any{"type": "string"}},
			}},
			"302": map[string]string{"description": "Redirect to the registered post-logout URI"},
			"400": map[string]string{"description": "Invalid request, unknown or disabled client, or confirmation required"},
			"401": map[string]string{"description": "The client may not end sessions, or the id_token_hint is invalid"},
		},
	}
	if method == http.MethodPost {
		schema := map[string]any{"type": "object", "properties": props}
		operation["requestBody"] = map[string]any{"required": false, "content": map[string]any{tokenFormType: map[string]any{"schema": schema}, "application/json": map[string]any{"schema": schema}}}
	} else {
		operation["parameters"] = params
	}
	b, _ := json.Marshal(operation)
	return b
}

// endSessionConfirmOperation describes the confirmation form's target.
var endSessionConfirmOperation = func() json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"summary":     "Confirm a browser logout",
		"description": "Completes RP-Initiated Logout after the user confirms on the page /oauth2/end-session showed, using its signed confirmation cookie.",
		"requestBody": map[string]any{"required": true, "content": map[string]any{tokenFormType: map[string]any{"schema": map[string]any{
			"type": "object", "required": []string{"action"}, "properties": map[string]any{"action": map[string]any{"type": "string", "enum": []string{"confirm"}}}}}}},
		"responses": map[string]any{
			"200": map[string]string{"description": "Logged out"},
			"302": map[string]string{"description": "Redirect to the registered post-logout URI"},
			"400": map[string]string{"description": "The confirmation is invalid or expired"},
		},
	})
	return b
}()
