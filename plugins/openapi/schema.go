// Package openapi publishes an OpenAPI 3.1 description of an auth handler.
package openapi

import (
	_ "embed"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"

	"github.com/Stonewrit/stonewrit-auth"
)

//go:embed catalog.json
var catalogData []byte

var catalogue = sync.OnceValue(func() map[string]json.RawMessage {
	var rows map[string]json.RawMessage
	if err := json.Unmarshal(catalogData, &rows); err != nil {
		panic(err)
	}
	return rows
})

func schemaPath(r stonewrit.HTTPRoute) string {
	if r.Plugin == "" {
		switch r.Path {
		case "/reset-password/:token":
			return "/reset-password/{token}"
		case "/callback/:id":
			return "/callback/{id}"
		}
	}
	return r.Path
}

func knownPlugin(id string) bool {
	switch id {
	case "", "admin", "anonymous", "api-key", "device-authorization", "email-otp", "jwt", "magic-link", "multi-session", "one-tap", "one-time-token", "organization", "passkey", "stripe", "two-factor", "username":
		return true
	}
	return false
}

func content(media string, schema object) object { return object{media: object{"schema": schema}} }
func response(media string, schema object) object {
	return object{"description": "Success", "content": content(media, schema)}
}

func sessionProtection(route stonewrit.HTTPRoute) bool {
	switch route.Plugin {
	case "admin", "organization", "api-key":
		return true
	case "stripe":
		return route.Path != "/stripe/webhook" && route.Path != "/subscription/success"
	case "passkey":
		return route.Path != "/passkey/generate-authenticate-options" && route.Path != "/passkey/verify-authentication"
	}
	switch route.Path {
	case "/list-accounts", "/list-sessions", "/revoke-session", "/revoke-sessions", "/revoke-other-sessions", "/unlink-account", "/update-user", "/change-password", "/verify-password", "/change-email", "/delete-user", "/delete-user/callback", "/link-social", "/get-access-token", "/refresh-token", "/account-info", "/delete-anonymous-user", "/device/approve", "/device/deny", "/one-time-token/generate", "/token", "/two-factor/enable", "/two-factor/disable", "/two-factor/get-totp-uri", "/two-factor/generate-backup-codes", "/email-otp/change-email", "/email-otp/request-email-change":
		return true
	}
	return false
}

func publicResponse(route stonewrit.HTTPRoute, info stonewrit.HTTPDescription, factor bool) object {
	if route.Plugin == "jwt" && route.Path != "/token" {
		return responseObject(object{"keys": array(object{"type": "object"})}, "keys")
	}
	switch route.Path {
	case "/get-session":
		if info.CustomSession {
			return object{}
		}
		return object{"anyOf": []object{modelRef("SessionResult"), {"type": "null"}}}
	case "/sign-in/email", "/sign-up/email", "/sign-in/username":
		props := object{"token": object{"type": []string{"string", "null"}}, "user": modelRef("User")}
		if route.Path != "/sign-up/email" {
			props["redirect"] = object{"type": "boolean"}
			props["url"] = object{"type": "string"}
		}
		login := responseObject(props, "token", "user")
		if factor {
			return object{"oneOf": []object{login, responseObject(object{"twoFactorRedirect": object{"const": true}, "twoFactorMethods": array(object{"type": "string"})}, "twoFactorRedirect", "twoFactorMethods")}}
		}
		return login
	case "/list-accounts":
		return array(modelRef("Account"))
	case "/list-sessions":
		return array(modelRef("Session"))
	case "/get-access-token":
		return modelSchema(reflect.TypeFor[stonewrit.AccessTokenResult]())
	case "/refresh-token":
		return modelSchema(reflect.TypeFor[stonewrit.RefreshTokenResult]())
	case "/account-info":
		return modelSchema(reflect.TypeFor[stonewrit.AccountInfoResult]())
	case "/admin/get-user", "/admin/update-user":
		return modelRef("User")
	case "/admin/list-users":
		return responseObject(object{"users": array(modelRef("User")), "total": object{"type": "integer"}, "limit": object{"type": "integer"}, "offset": object{"type": "integer"}}, "users", "total")
	case "/admin/impersonate-user", "/admin/stop-impersonating":
		return modelRef("SessionResult")
	case "/api-key/get", "/api-key/update":
		return modelRef("APIKey")
	case "/api-key/create":
		return object{"allOf": []object{modelRef("APIKey"), responseObject(object{"key": object{"type": "string"}}, "key")}}
	case "/api-key/list":
		return responseObject(object{"apiKeys": array(modelRef("APIKey")), "total": object{"type": "integer"}, "limit": object{"type": "integer"}, "offset": object{"type": "integer"}}, "apiKeys", "total")
	case "/organization/create":
		return object{"allOf": []object{modelRef("Organization"), responseObject(object{"members": array(modelRef("Member"))}, "members")}}
	case "/organization/get-organization", "/organization/set-active":
		return object{"anyOf": []object{modelRef("Organization"), {"type": "null"}}}
	case "/organization/create-team", "/organization/update-team":
		return modelRef("Team")
	case "/organization/list-user-teams", "/organization/list-teams":
		return array(modelRef("Team"))
	case "/organization/list-team-members":
		return array(modelRef("TeamMember"))
	case "/token", "/one-time-token/generate":
		return responseObject(object{"token": object{"type": "string"}}, "token")
	case "/organization/list":
		return array(modelRef("Organization"))
	case "/passkey/list-user-passkeys":
		return array(modelRef("Passkey"))
	case "/subscription/list":
		return array(modelRef("Subscription"))
	case "/ok":
		return responseObject(object{"ok": object{"const": true}}, "ok")
	case "/sign-out":
		return responseObject(object{"success": object{"type": "boolean"}}, "success")
	case "/revoke-session", "/revoke-sessions", "/revoke-other-sessions", "/unlink-account", "/verify-password", "/update-user":
		return responseObject(object{"status": object{"type": "boolean"}}, "status")
	case "/subscription/cancel", "/subscription/billing-portal", "/subscription/upgrade":
		return responseObject(object{"url": object{"type": "string", "format": "uri"}, "redirect": object{"type": "boolean"}}, "url", "redirect")
	}
	return object{}
}

func keepFields(schema object, names ...string) {
	fields, ok := schema["properties"].(object)
	if !ok {
		return
	}
	allowed := make(map[string]bool, len(names))
	for _, k := range names {
		allowed[k] = true
	}
	for k := range fields {
		if !allowed[k] {
			delete(fields, k)
		}
	}
	if req, ok := schema["required"].([]any); ok {
		kept := req[:0]
		for _, k := range req {
			if name, ok := k.(string); ok && allowed[name] {
				kept = append(kept, k)
			}
		}
		schema["required"] = kept
	}
}

func adjustRequest(op object, r stonewrit.HTTPRoute, info stonewrit.HTTPDescription, a *stonewrit.Auth) {
	switch r.Path {
	case "/account-info":
		op["parameters"] = []object{{"name": "accountId", "in": "query", "required": true, "schema": object{"type": "string"}}}
		return
	case "/get-access-token", "/refresh-token":
		op["requestBody"] = object{"required": true, "content": content("application/json", responseObject(object{"accountId": object{"type": "string"}}, "accountId"))}
		return
	case "/error":
		op["parameters"] = []object{{"name": "error", "in": "query", "schema": object{"type": "string"}}, {"name": "error_description", "in": "query", "schema": object{"type": "string"}}}
		return
	case "/sign-out":
		delete(op, "requestBody")
		return
	case "/passkey/generate-register-options":
		op["parameters"] = []object{{"name": "name", "in": "query", "schema": object{"type": "string"}}, {"name": "authenticatorAttachment", "in": "query", "schema": object{"type": "string", "enum": []string{"platform", "cross-platform"}}}}
		return
	}
	if r.Path == "/stripe/webhook" {
		op["requestBody"] = object{"required": true, "content": content("application/json", responseObject(object{"id": object{"type": "string"}, "type": object{"type": "string"}, "data": object{"type": "object"}}, "id", "type", "data"))}
		return
	}
	if r.Path == "/organization/get-organization" {
		op["parameters"] = []object{{"in": "query", "name": "organizationId", "schema": object{"type": "string"}}, {"in": "query", "name": "organizationSlug", "schema": object{"type": "string"}}}
	}
	if r.Path == "/get-session" {
		op["parameters"] = []object{{"in": "query", "name": "disableRefresh", "schema": object{"type": "boolean"}}}
	}
	if r.Path == "/get-session" && r.Method == "POST" {
		delete(op, "requestBody")
		return
	}
	body, _ := op["requestBody"].(object)
	if body == nil {
		return
	}
	media, _ := body["content"].(object)
	jsonMedia, _ := media["application/json"].(object)
	schema, _ := jsonMedia["schema"].(object)
	if schema == nil {
		return
	}
	fields, _ := schema["properties"].(object)
	if required, ok := schema["required"].([]any); ok && len(required) > 0 {
		body["required"] = true
	}
	switch r.Path {
	case "/sign-up/email", "/update-user":
		if fields == nil {
			fields = object{}
			schema["properties"] = fields
		}
		if r.Path == "/update-user" {
			schema["type"] = "object"
			delete(schema, "allOf")
			fields["name"] = object{"type": "string"}
			fields["image"] = object{"type": []string{"string", "null"}}
		} else {
			fields["email"] = object{"type": "string", "format": "email"}
			fields["password"] = object{"type": "string", "format": "password", "minLength": info.MinPassword, "maxLength": info.MaxPassword}
		}
		if a.HasPlugin("username") {
			userType := object{"type": "string"}
			if r.Path == "/update-user" {
				userType = object{"type": []string{"string", "null"}}
			}
			fields["username"] = userType
			if info.DisplayUsername {
				fields["displayUsername"] = userType
			}
		}
	case "/sign-in/email":
		fields["email"] = object{"type": "string", "format": "email"}
		fields["password"] = object{"type": "string", "format": "password"}
	case "/sign-in/social", "/link-social":
		keepFields(schema, "provider", "callbackURL", "errorCallbackURL", "newUserCallbackURL", "disableRedirect", "idToken")
		fields["provider"] = object{"type": "string", "enum": info.Providers}
	case "/subscription/upgrade":
		keepFields(schema, "plan", "annual", "referenceId", "customerType", "subscriptionId", "successUrl", "cancelUrl", "returnUrl", "disableRedirect")
	case "/organization/create":
		keepFields(schema, "name", "slug", "logo", "metadata", "keepCurrentActiveOrganization")
	case "/passkey/verify-registration":
		fields["createSession"] = object{"const": false}
	case "/unlink-account":
		schema = responseObject(object{"accountId": object{"type": "string"}}, "accountId")
		jsonMedia["schema"] = schema
	case "/api-key/create", "/api-key/update":
		for _, key := range []string{"permissions", "refillAmount", "refillInterval", "rateLimitMax", "rateLimitTimeWindow", "rateLimitEnabled", "remaining"} {
			delete(fields, key)
		}
		if r.Path == "/api-key/create" {
			delete(fields, "userId")
		}
	}
	switch r.Path {
	case "/sign-up/email", "/sign-in/email", "/device/code", "/device/token":
		media["application/x-www-form-urlencoded"] = jsonMedia
	case "/callback/:id":
		delete(media, "application/json")
		media["application/x-www-form-urlencoded"] = object{"schema": responseObject(object{"code": object{"type": "string"}, "state": object{"type": "string"}, "error": object{"type": "string"}, "user": object{"type": "string"}, "error_description": object{"type": "string"}, "iss": object{"type": "string"}, "device_id": object{"type": "string"}}, "state")}
		op["parameters"] = []object{{"in": "path", "name": "id", "required": true, "schema": object{"type": "string", "enum": info.Providers}}}
	}
}

func standardOperation(r stonewrit.HTTPRoute, info stonewrit.HTTPDescription, a *stonewrit.Auth) (object, error) {
	op := object{}
	key := r.Method + " " + schemaPath(r)
	builtin := knownPlugin(r.Plugin)
	if raw := catalogue()[key]; builtin && raw != nil {
		if err := json.Unmarshal(raw, &op); err != nil {
			return nil, err
		}
	}
	if _, ok := op["operationId"]; !ok {
		op["operationId"] = strings.ToLower(r.Method) + strings.NewReplacer("/", "_", ":", "").Replace(r.Path)
	}
	tag := r.Plugin
	if tag == "" {
		tag = "Core"
	}
	op["tags"] = []string{tag}
	op["security"] = []object{}
	if builtin && (sessionProtection(r) || r.Path == "/get-session" || r.Path == "/device") {
		security := []object{{"apiKeyCookie": []string{}}}
		if r.Path == "/get-session" || r.Path == "/device" {
			security = append(security, object{})
		}
		if a.HasPlugin("bearer") {
			security = append(security, object{"bearerAuth": []string{}})
		}
		op["security"] = security
	}
	if r.Plugin == "stripe" && r.Path == "/stripe/webhook" {
		op["security"] = []object{{"stripeSignature": []string{}}}
	}
	result := object{}
	if builtin {
		result = publicResponse(r, info, a.HasPlugin("two-factor"))
	}
	responses := object{"200": response("application/json", result), "default": object{"$ref": "#/components/responses/Error"}}
	if builtin {
		switch r.Path {
		case "/error":
			responses["200"] = response("text/html", object{"type": "string"})
		case "/reset-password/:token", "/callback/:id", "/subscription/success":
			delete(responses, "200")
			responses["302"] = object{"description": "Redirect to the configured destination", "headers": object{"Location": object{"schema": object{"type": "string"}}}}
		case "/verify-email", "/magic-link/verify", "/delete-user/callback":
			responses["302"] = object{"description": "Redirect to the trusted callback"}
		case "/device/code", "/device/token":
			responses["default"] = response("application/json", responseObject(object{"error": object{"type": "string"}, "error_description": object{"type": "string"}}, "error"))
			responses["default"].(object)["description"] = "Device authorization error"
		}
	}
	op["responses"] = responses
	if builtin {
		adjustRequest(op, r, info, a)
	}
	if r.OpenAPI != nil {
		var metadata object
		if err := json.Unmarshal(r.OpenAPI, &metadata); err != nil {
			return nil, err
		}
		for key, value := range metadata {
			op[key] = value
		}
	}
	return op, nil
}

// Generate returns a fresh OpenAPI document for this configured instance.
func Generate(a *stonewrit.Auth) (map[string]any, error) {
	if a == nil {
		return nil, errors.New("openapi: auth instance is required")
	}
	info := a.DescribeHTTP()
	schemes := object{"apiKeyCookie": object{"type": "apiKey", "in": "cookie", "name": info.SessionCookie}}
	if a.HasPlugin("bearer") {
		schemes["bearerAuth"] = object{"type": "http", "scheme": "bearer"}
	}
	paths := object{}
	for _, r := range info.Routes {
		if r.Plugin == "open-api" {
			continue
		}
		if r.Plugin == "stripe" && r.Path == "/stripe/webhook" {
			schemes["stripeSignature"] = object{"type": "apiKey", "in": "header", "name": "Stripe-Signature"}
		}
		path := schemaPath(r)
		methods, _ := paths[path].(object)
		if methods == nil {
			methods = object{}
			paths[path] = methods
		}
		op, err := standardOperation(r, info, a)
		if err != nil {
			return nil, err
		}
		methods[strings.ToLower(r.Method)] = op
	}
	return object{"openapi": "3.1.1", "info": object{"title": "StoneWrit Auth", "version": "1.0"}, "servers": []object{{"url": info.ServerURL}},
		"paths": paths, "components": object{"schemas": models(a, info), "securitySchemes": schemes,
			"responses": object{"Error": object{"description": "Request failed", "content": content("application/json", modelRef("Error"))}}}}, nil
}
