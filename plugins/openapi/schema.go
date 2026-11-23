// Package openapi publishes an OpenAPI 3.1 description of an auth handler.
package openapi

import (
	_ "embed"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/organization"
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

func schemaPath(r plainauth.HTTPRoute) string {
	if r.Plugin == "oauth-proxy" && r.Path == "/callback/:id/oauth-proxy" {
		return "/callback/{id}/oauth-proxy"
	}
	if r.Plugin == "sso" && strings.HasSuffix(r.Path, "/:providerId") {
		return strings.TrimSuffix(r.Path, "/:providerId") + "/{providerId}"
	}
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
	case "", "admin", "anonymous", "api-key", "device-authorization", "email-otp", "jwt", "magic-link", "multi-session", "oauth-popup", "oauth-proxy", "one-tap", "one-time-token", "organization", "passkey", "phone-number", "sso", "stripe", "two-factor", "username":
		return true
	}
	return false
}

func content(media string, schema object) object { return object{media: object{"schema": schema}} }
func response(media string, schema object) object {
	return object{"description": "Success", "content": content(media, schema)}
}

func sessionProtection(route plainauth.HTTPRoute) bool {
	switch route.Plugin {
	case "admin", "organization", "api-key":
		return true
	case "sso":
		switch route.Path {
		case "/sso/register", "/sso/update-provider", "/sso/providers", "/sso/get-provider", "/sso/delete-provider", "/sso/request-domain-verification", "/sso/verify-domain":
			return true
		}
		return false
	case "stripe":
		return route.Path != "/stripe/webhook" && route.Path != "/subscription/success"
	case "passkey":
		return route.Path != "/passkey/generate-authenticate-options" && route.Path != "/passkey/verify-authentication"
	}
	switch route.Path {
	case "/update-session", "/list-accounts", "/list-sessions", "/revoke-session", "/revoke-sessions", "/revoke-other-sessions", "/unlink-account", "/update-user", "/change-password", "/verify-password", "/change-email", "/delete-user", "/delete-user/callback", "/link-social", "/get-access-token", "/refresh-token", "/account-info", "/delete-anonymous-user", "/device/approve", "/device/deny", "/one-time-token/generate", "/token", "/two-factor/enable", "/two-factor/disable", "/two-factor/get-totp-uri", "/two-factor/generate-backup-codes", "/email-otp/change-email", "/email-otp/request-email-change":
		return true
	}
	return false
}

func loginResponse(success object, factor bool) object {
	if !factor {
		return success
	}
	challenge := responseObject(object{"twoFactorRedirect": object{"const": true}, "twoFactorMethods": array(object{"type": "string"})}, "twoFactorRedirect", "twoFactorMethods")
	return object{"oneOf": []object{success, challenge}}
}

func organizationMemberProfile() object {
	return object{"allOf": []object{modelRef("Member"), responseObject(object{"user": modelSchema(reflect.TypeFor[organization.MemberUser]())}, "user")}}
}

func publicResponse(route plainauth.HTTPRoute, info plainauth.HTTPDescription, factor bool) object {
	if route.Plugin == "sso" {
		return ssoResponse(route.Path, info)
	}
	if route.Plugin == "jwt" && route.Path != "/token" {
		return responseObject(object{"keys": array(object{"type": "object"})}, "keys")
	}
	switch route.Path {
	case "/sign-in/social":
		return object{"anyOf": []object{
			responseObject(object{"url": object{"type": "string"}, "redirect": object{"type": "boolean"}}, "url", "redirect"),
			responseObject(object{"user": modelRef("User"), "token": object{"type": "string"}, "redirect": object{"const": false}}, "user", "token", "redirect"),
		}}
	case "/update-session":
		return responseObject(object{"session": modelRef("Session")}, "session")
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
		return loginResponse(login, factor)
	case "/phone-number/verify":
		verified := responseObject(object{"status": object{"const": true}, "token": object{"type": []string{"string", "null"}}, "user": modelRef("User")}, "status", "token", "user")
		return loginResponse(verified, factor)
	case "/sign-in/phone-number":
		return loginResponse(responseObject(object{"token": object{"type": "string"}, "user": modelRef("User")}, "token", "user"), factor)
	case "/phone-number/request-password-reset", "/phone-number/reset-password":
		return responseObject(object{"status": object{"const": true}}, "status")
	case "/phone-number/send-otp":
		return responseObject(object{"message": object{"const": "code sent"}}, "message")
	case "/list-accounts":
		return array(modelRef("Account"))
	case "/list-sessions":
		return array(modelRef("Session"))
	case "/get-access-token":
		return modelSchema(reflect.TypeFor[plainauth.AccessTokenResult]())
	case "/refresh-token":
		return modelSchema(reflect.TypeFor[plainauth.RefreshTokenResult]())
	case "/account-info":
		return modelSchema(reflect.TypeFor[plainauth.AccountInfoResult]())
	case "/sign-in/email-otp":
		return responseObject(object{"user": modelRef("User"), "token": object{"type": "string"}}, "token", "user")
	case "/admin/create-user":
		return responseObject(object{"user": modelRef("User")}, "user")
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
	case "/organization/update":
		return modelRef("Organization")
	case "/organization/check-slug":
		return responseObject(object{"status": object{"type": "boolean"}}, "status")
	case "/organization/get-full-organization":
		return object{"anyOf": []object{modelRef("FullOrganization"), {"type": "null"}}}
	case "/organization/get-organization":
		return object{"anyOf": []object{modelRef("Organization"), {"type": "null"}}}
	case "/organization/set-active", "/organization/set-active-team":
		model := "Organization"
		if route.Path == "/organization/set-active-team" {
			model = "Team"
		}
		shapes := []object{modelRef(model), {"type": "null"}}
		if info.OAuthSelectionContinuation {
			shapes = append(shapes, responseObject(object{"redirect": object{"const": true}, "url": object{"type": "string"}}, "redirect", "url"))
		}
		return object{"anyOf": shapes}
	case "/organization/update-member-role":
		return modelRef("Member")
	case "/organization/get-active-member", "/organization/list-members":
		member := organizationMemberProfile()
		if route.Path == "/organization/list-members" {
			return responseObject(object{"members": array(member), "total": object{"type": "integer"}}, "members", "total")
		}
		return member
	case "/organization/update-role":
		return responseObject(object{"success": object{"const": true}, "roleData": modelRef("OrganizationRole")}, "success", "roleData")
	case "/organization/create-role":
		return responseObject(object{"success": object{"const": true}, "roleData": modelRef("OrganizationRole"), "statements": object{"type": "object", "additionalProperties": array(object{"type": "string"})}}, "success", "roleData", "statements")
	case "/organization/delete-role":
		return responseObject(object{"success": object{"const": true}}, "success")
	case "/organization/get-role":
		return modelRef("OrganizationRole")
	case "/organization/list-roles":
		return array(modelRef("OrganizationRole"))
	case "/organization/get-active-member-role":
		return responseObject(object{"role": object{"type": "string"}}, "role")
	case "/organization/create-team", "/organization/update-team":
		return modelRef("Team")
	case "/organization/list-user-teams", "/organization/list-teams":
		return array(modelRef("Team"))
	case "/organization/list-team-members":
		return array(modelRef("TeamMember"))
	case "/token", "/one-time-token/generate":
		return responseObject(object{"token": object{"type": "string"}}, "token")
	case "/organization/has-permission":
		return responseObject(object{"success": object{"type": "boolean"}, "error": object{"type": "null"}}, "success", "error")
	case "/organization/invite-member", "/organization/cancel-invitation":
		return modelRef("Invitation")
	case "/organization/accept-invitation":
		return responseObject(object{"invitation": modelRef("Invitation"), "member": modelRef("Member")}, "invitation", "member")
	case "/organization/reject-invitation":
		return responseObject(object{"invitation": modelRef("Invitation"), "member": object{"type": "null"}}, "invitation", "member")
	case "/organization/get-invitation":
		return object{"allOf": []object{modelRef("Invitation"), responseObject(object{"organizationName": object{"type": "string"}, "organizationSlug": object{"type": "string"}, "inviterEmail": object{"type": "string", "format": "email"}}, "organizationName", "organizationSlug", "inviterEmail")}}
	case "/organization/list-user-invitations":
		return array(object{"allOf": []object{modelRef("Invitation"), responseObject(object{"organizationName": object{"type": "string"}}, "organizationName")}})
	case "/organization/list-invitations":
		return array(modelRef("Invitation"))
	case "/organization/list":
		return array(modelRef("Organization"))
	case "/passkey/verify-registration":
		return object{"allOf": []object{modelRef("Passkey"), responseObject(object{"session": modelRef("Session"), "user": modelRef("User")})}}
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

type userInputMode int

const (
	partialUpdate userInputMode = iota
	createUser
	createOrSignIn
)

// addUserInputs extends a request without shadowing credentials such as an OTP code.
// For a combined sign-in or registration route, the existing account needs only its proof.
func addUserInputs(schema object, info plainauth.HTTPDescription, mode userInputMode) {
	properties, _ := schema["properties"].(object)
	if properties == nil {
		properties = object{}
		schema["properties"] = properties
	}
	for name, field := range info.UserFields {
		if !field.Writable || properties[name] != nil {
			continue
		}
		property := scalarFieldSchema(field)
		if !field.Returned {
			property["writeOnly"] = true
		}
		if mode == createOrSignIn {
			property["description"] = "Applied only when creating a user."
			if slices.Contains(info.RequiredUserInputs, name) {
				property["description"] = "Required when creating a user."
			}
		}
		properties[name] = property
	}
	if mode == createUser && len(info.RequiredUserInputs) > 0 {
		required, _ := schema["required"].([]any)
		for _, name := range info.RequiredUserInputs {
			required = append(required, name)
		}
		schema["required"] = required
	}
}

// Form decoding preserves text. JSON is the only signup encoding that can supply
// a required boolean or integer without a default.
func signupFormSchema(schema object, info plainauth.HTTPDescription) object {
	form := maps.Clone(schema)
	properties := maps.Clone(schema["properties"].(object))
	form["properties"] = properties
	properties["rememberMe"] = false
	for name, field := range info.UserFields {
		if !field.Writable {
			continue
		}
		if field.Type != plainauth.FieldString && field.Type != plainauth.FieldDate {
			if slices.Contains(info.RequiredUserInputs, name) {
				return nil
			}
			properties[name] = false
			continue
		}
		property := maps.Clone(properties[name].(object))
		property["type"] = "string"
		properties[name] = property
	}
	return form
}

func addRoleInputFields(properties object, defs map[string]plainauth.HTTPField) []string {
	var required []string
	for name, f := range defs {
		if f.Writable {
			properties[name] = scalarFieldSchema(f)
			if f.Required {
				required = append(required, name)
			}
		}
	}
	slices.Sort(required)
	return required
}

func adjustRequest(op object, r plainauth.HTTPRoute, info plainauth.HTTPDescription, a *plainauth.Auth) {
	if r.Plugin == "organization" && r.Path == "/organization/create-team" {
		body := responseObject(object{"name": object{"type": "string"}, "organizationId": object{"type": "string"}}, "name")
		op["requestBody"] = object{"required": true, "content": content("application/json", body)}
	}
	if r.Plugin == "organization" && r.Path == "/organization/create-role" {
		body := responseObject(object{
			"organizationId": object{"type": "string"},
			"role":           object{"type": "string", "minLength": 1},
			"permission":     object{"type": "object", "additionalProperties": array(object{"type": "string"})},
		}, "role", "permission")
		properties := object{}
		required := addRoleInputFields(properties, info.OrganizationRoleFields)
		body["properties"].(object)["additionalFields"] = responseObject(properties, required...)
		if info.RoleFieldsRequiredOnCreate {
			body["required"] = append(body["required"].([]string), "additionalFields")
		}
		op["requestBody"] = object{"required": true, "content": content("application/json", body)}
	}
	if r.Plugin == "organization" && (r.Path == "/organization/delete-role" || r.Path == "/organization/update-role") {
		body := responseObject(object{
			"organizationId": object{"type": "string"},
			"roleName":       object{"type": "string"},
			"roleId":         object{"type": "string"},
		})
		if r.Path == "/organization/update-role" {
			properties := object{"roleName": object{"type": "string"}, "permission": object{"type": "object", "additionalProperties": array(object{"type": "string"})}}
			addRoleInputFields(properties, info.OrganizationRoleFields)
			body["properties"].(object)["data"] = responseObject(properties)
			body["required"] = []string{"data"}
		}
		body["anyOf"] = []object{
			responseObject(object{"roleName": object{"type": "string", "minLength": 1}}, "roleName"),
			responseObject(object{"roleId": object{"type": "string", "minLength": 1}}, "roleId"),
		}
		op["requestBody"] = object{"required": true, "content": content("application/json", body)}
	}
	if r.Plugin == "organization" && (r.Path == "/organization/get-role" || r.Path == "/organization/list-roles") {
		params := []object{{"name": "organizationId", "in": "query", "schema": object{"type": "string"}, "description": "Omit to use the active organization."}}
		if r.Path == "/organization/get-role" {
			op["description"] = "Supply a nonempty roleName or roleId. A valid name takes precedence."
			for _, field := range []string{"roleName", "roleId"} {
				params = append(params, object{"name": field, "in": "query", "schema": object{"type": "string", "minLength": 1}})
			}
		}
		op["parameters"] = params
	}
	if r.Plugin == "organization" && r.Path == "/organization/get-invitation" {
		op["parameters"] = []object{{"name": "id", "in": "query", "required": true, "schema": object{"type": "string"}}}
	}
	if r.Plugin == "organization" && r.Path == "/organization/list-user-invitations" {
		// Selecting a mailbox is a trusted Go operation.
		delete(op, "parameters")
	}
	if r.Plugin == "oauth-proxy" {
		params := []object{
			{"name": "callbackURL", "in": "query", "required": true, "schema": object{"type": "string"}},
			{"name": "profile", "in": "query", "required": true, "schema": object{"type": "string"}, "description": "Encrypted, short-lived return from the production callback."},
		}
		if r.Path == "/oauth-proxy-callback" {
			op["operationId"] = "oauthProxyCallback"
			op["deprecated"] = true
		} else {
			op["operationId"] = "oauthProxyCompletion"
			provider := object{"type": "string"}
			if len(info.Providers) > 0 {
				provider["enum"] = info.Providers
			}
			params = append(params, object{"name": "id", "in": "path", "required": true, "schema": provider})
		}
		op["parameters"] = params
		op["security"] = []object{{"oauthProxyState": []string{}}}
		return
	}
	if r.Plugin == "sso" {
		describeSSORequest(op, r, info)
		return
	}
	switch r.Path {
	case "/organization/has-permission":
		actions := object{"type": "object", "additionalProperties": array(object{"type": "string"})}
		legacy := object{"type": "object", "deprecated": true, "additionalProperties": array(object{"type": "string"})}
		request := object{"type": "object", "properties": object{"organizationId": object{"type": "string"}}, "oneOf": []object{
			responseObject(object{"permissions": actions}, "permissions"),
			responseObject(object{"permission": legacy}, "permission"),
		}}
		op["requestBody"] = object{"required": true, "content": content("application/json", request)}
		return
	case "/update-session":
		fields := object{}
		for name, f := range info.SessionFields {
			if f.Writable {
				fields[name] = scalarFieldSchema(f)
			}
		}
		op["requestBody"] = object{"required": true, "content": content("application/json", responseObject(fields))}
		return
	case "/oauth-popup/start":
		var parameters []object
		for _, field := range []string{"provider", "popupOrigin", "popupNonce", "callbackURL", "errorCallbackURL", "newUserCallbackURL", "scopes", "requestSignUp", "additionalData"} {
			parameters = append(parameters, object{"in": "query", "name": field, "required": field == "provider" || field == "popupOrigin", "schema": object{"type": "string"}})
		}
		op["parameters"] = parameters
		return
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
		op["parameters"] = []object{{"name": "context", "in": "query", "schema": object{"type": "string"}}, {"name": "name", "in": "query", "schema": object{"type": "string"}}, {"name": "authenticatorAttachment", "in": "query", "schema": object{"type": "string", "enum": []string{"platform", "cross-platform"}}}}
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
	case "/organization/set-active", "/organization/set-active-team":
		delete(body, "required")
		description := "Select an organization for the current session by ID or slug. An empty request uses the current selection. A null organizationId clears both organization and team."
		if r.Path == "/organization/set-active-team" {
			description = "Select a team in the current session’s active organization. An omitted or empty ID uses the current team. A null teamId clears the team."
		}
		if info.OAuthSelectionContinuation {
			fields["oauth_query"] = object{"type": "string", "description": "Optional signed query from the host’s OAuth post-login page. Requires a direct browser session."}
			description += " When a signed post-login request resumes, a JSON client receives the next URL and a browser navigation receives its location."
			op["responses"].(object)["302"] = object{"description": "Navigate to the next step of the signed OAuth request", "headers": object{"Location": object{"schema": object{"type": "string"}}}}
		}
		op["description"] = description
	case "/sign-up/email", "/update-user":
		if fields == nil {
			fields = object{}
			schema["properties"] = fields
		}
		if r.Path == "/update-user" {
			schema["type"] = "object"
			delete(schema, "allOf")
			if a.HasPlugin("phone-number") {
				fields["phoneNumber"] = object{"type": "null", "description": "Clear the verified phone number on the signed-in owner's profile."}
			}
			fields["name"] = object{"type": "string"}
			fields["image"] = object{"type": []string{"string", "null"}}
		} else {
			if a.HasPlugin("phone-number") {
				fields["phoneNumber"] = object{"enum": []any{nil, ""}, "description": "Leave empty on email signup. Verify the number to attach it to the account."}
			}
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
		mode := partialUpdate
		if r.Path == "/sign-up/email" {
			mode = createUser
		}
		addUserInputs(schema, info, mode)
	case "/admin/create-user":
		if len(info.UserFields) != 0 {
			data := fields["data"].(object)
			addUserInputs(data, info, createUser)
			if len(info.RequiredUserInputs) != 0 {
				schema["required"] = append(schema["required"].([]any), "data")
			}
		}
	case "/sign-in/email-otp":
		if info.EmailOTPRegistration {
			addUserInputs(schema, info, createOrSignIn)
		}
	case "/phone-number/verify":
		fields["updatePhoneNumber"] = object{"type": "boolean", "description": "Link this number to the account in a direct owner session."}
		fields["code"] = object{"type": "string", "writeOnly": true}
		if info.PhoneRegistration {
			addUserInputs(schema, info, createOrSignIn)
		}
	case "/sign-in/phone-number":
		fields["password"] = object{"type": "string", "format": "password", "writeOnly": true, "maxLength": info.MaxPassword}
	case "/phone-number/reset-password":
		fields["otp"] = object{"type": "string", "writeOnly": true}
		fields["newPassword"] = object{"type": "string", "format": "password", "writeOnly": true, "minLength": info.MinPassword, "maxLength": info.MaxPassword}
	case "/sign-in/email":
		fields["email"] = object{"type": "string", "format": "email"}
		fields["password"] = object{"type": "string", "format": "password"}
	case "/sign-in/social", "/link-social":
		keepFields(schema, "provider", "callbackURL", "errorCallbackURL", "newUserCallbackURL", "disableRedirect", "idToken")
		fields["provider"] = object{"type": "string", "enum": info.Providers}
		if r.Path == "/sign-in/social" && info.OAuthLoginContinuation {
			fields["oauth_query"] = object{"type": "string", "description": "Verified query from the issuer login page."}
		}
	case "/subscription/upgrade":
		keepFields(schema, "plan", "annual", "referenceId", "customerType", "subscriptionId", "successUrl", "cancelUrl", "returnUrl", "disableRedirect")
	case "/organization/create":
		keepFields(schema, "name", "slug", "logo", "metadata", "keepCurrentActiveOrganization")
	case "/passkey/verify-registration":
		fields["createSession"] = object{"type": "boolean"}
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
	case "/sign-up/email":
		if form := signupFormSchema(schema, info); form != nil {
			media["application/x-www-form-urlencoded"] = object{"schema": form}
		} else {
			delete(media, "application/x-www-form-urlencoded")
		}
	case "/sign-in/email", "/device/code", "/device/token":
		media["application/x-www-form-urlencoded"] = jsonMedia
	case "/callback/:id":
		delete(media, "application/json")
		media["application/x-www-form-urlencoded"] = object{"schema": responseObject(object{"code": object{"type": "string"}, "state": object{"type": "string"}, "error": object{"type": "string"}, "user": object{"type": "string"}, "error_description": object{"type": "string"}, "iss": object{"type": "string"}, "device_id": object{"type": "string"}}, "state")}
		op["parameters"] = []object{{"in": "path", "name": "id", "required": true, "schema": object{"type": "string", "enum": info.Providers}}}
	}
}

func standardOperation(r plainauth.HTTPRoute, info plainauth.HTTPDescription, a *plainauth.Auth) (object, error) {
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
	optionalSession := r.Path == "/get-session" || r.Path == "/device" || r.Plugin == "phone-number" && r.Path == "/phone-number/verify"
	if builtin && (sessionProtection(r) || optionalSession) {
		security := []object{{"apiKeyCookie": []string{}}}
		if optionalSession {
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
	status := r.SuccessStatus
	if status == 0 {
		status = http.StatusOK
	}
	success := strconv.Itoa(status)
	responses := object{"default": object{"$ref": "#/components/responses/Error"}}
	if status == http.StatusNoContent {
		responses[success] = object{"description": "No content"}
	} else {
		responses[success] = response("application/json", result)
	}
	if builtin {
		switch r.Path {
		case "/sso/saml2/sp/metadata":
			responses[success] = response("application/xml", object{"type": "string"})
		case "/oauth-popup/start":
			responses["302"] = object{"description": "Navigate the popup to the provider", "headers": object{"Location": object{"schema": object{"type": "string"}}}}
			responses[success] = response("text/html", object{"type": "string"})
		case "/error":
			responses[success] = response("text/html", object{"type": "string"})
		case "/reset-password/:token", "/callback/:id", "/callback/:id/oauth-proxy", "/oauth-proxy-callback", "/subscription/success", "/sso/callback", "/sso/callback/:providerId", "/sso/saml2/sp/acs/:providerId", "/sso/saml2/logout/:providerId", "/sso/saml2/sp/slo/:providerId":
			delete(responses, success)
			responses["302"] = object{"description": "Redirect to the configured destination", "headers": object{"Location": object{"schema": object{"type": "string"}}}}
			if (r.Path == "/callback/:id" || r.Plugin == "oauth-proxy") && r.Method == "GET" {
				media := object{}
				if a.HasPlugin("oauth-popup") {
					media["text/html"] = object{"schema": object{"type": "string"}}
				}
				if info.OAuthLoginContinuation {
					media["application/json"] = object{"schema": responseObject(object{"redirect": object{"const": true}, "url": object{"type": "string"}}, "redirect", "url")}
				}
				if len(media) > 0 {
					responses["200"] = object{"description": "Success", "content": media}
				}
			}
		case "/sign-in/social":
			if info.OAuthLoginContinuation {
				responses["302"] = object{"description": "Continue a signed issuer login after direct ID-token verification", "headers": object{"Location": object{"schema": object{"type": "string"}}}}
			}
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
func Generate(a *plainauth.Auth) (map[string]any, error) {
	if a == nil {
		return nil, errors.New("openapi: auth instance is required")
	}
	info := a.DescribeHTTP()
	schemes := object{"apiKeyCookie": object{"type": "apiKey", "in": "cookie", "name": info.SessionCookie}}
	if info.OAuthProxyStateCookie != "" {
		schemes["oauthProxyState"] = object{"type": "apiKey", "in": "cookie", "name": info.OAuthProxyStateCookie}
	}
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
		if r.Plugin == "oauth-provider" && (r.Path == "/oauth2/token" || r.Path == "/oauth2/introspect" || r.Path == "/oauth2/revoke") {
			schemes["clientSecretBasic"] = object{"type": "http", "scheme": "basic"}
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
	return object{"openapi": "3.1.1", "info": object{"title": "Plain Auth", "version": "1.0"}, "servers": []object{{"url": info.ServerURL}},
		"paths": paths, "components": object{"schemas": models(a, info), "securitySchemes": schemes,
			"responses": object{"Error": object{"description": "Request failed", "content": content("application/json", modelRef("Error"))}}}}, nil
}
