package openapi

import (
	"reflect"
	"slices"

	"github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/plugins/sso"
)

func ssoResponse(path string, info stonewrit.HTTPDescription) object {
	text := object{"type": "string"}
	switch path {
	case "/sso/register":
		// Document safe registration fields by allowlist. Unlike management reads,
		// the administrator's actual response can also contain client credentials.
		fields := object{
			"id": text, "providerId": text, "userId": text, "domain": text, "issuer": text, "organizationId": text,
			"redirectURI": object{"type": "string", "format": "uri"}, "samlConfig": object{"type": "null"},
			"oidcConfig": responseObject(object{"issuer": text, "discoveryEndpoint": text, "authorizationEndpoint": text,
				"tokenEndpoint": text, "jwksEndpoint": text, "userInfoEndpoint": text, "pkce": object{"type": "boolean"}}),
		}
		required := []string{"id", "providerId", "userId", "domain", "issuer", "redirectURI", "oidcConfig", "samlConfig"}
		if slices.ContainsFunc(info.Routes, func(r stonewrit.HTTPRoute) bool {
			return r.Plugin == "sso" && r.Path == "/sso/request-domain-verification"
		}) {
			fields["domainVerified"] = object{"const": false}
			fields["domainVerificationToken"] = text
			required = append(required, "domainVerified", "domainVerificationToken")
		}
		return responseObject(fields, required...)
	case "/sso/providers":
		return responseObject(object{"providers": array(modelSchema(reflect.TypeFor[sso.PublicProvider]()))}, "providers")
	case "/sso/get-provider":
		return modelSchema(reflect.TypeFor[sso.PublicProvider]())
	case "/sso/delete-provider":
		return responseObject(object{"success": object{"const": true}}, "success")
	case "/sign-in/sso":
		return responseObject(object{"url": object{"type": "string", "format": "uri"}, "redirect": object{"const": true}}, "url", "redirect")
	case "/sso/request-domain-verification":
		return responseObject(object{"domainVerificationToken": text}, "domainVerificationToken")
	}
	return object{}
}

func describeSSORequest(op object, path string, info stonewrit.HTTPDescription) {
	text := object{"type": "string"}
	providerID := object{"type": "string", "minLength": 1}
	body := func(schema object) {
		op["requestBody"] = object{"required": true, "content": content("application/json", schema)}
	}
	switch path {
	case "/sso/register":
		op["description"] = "Requires a direct session and an available registration slot. Organization registration requires a current owner or administrator. The confidential response can echo submitted OIDC credentials."
		config := modelSchema(reflect.TypeFor[sso.Config]())
		properties := config["properties"].(object)
		delete(properties, "issuer") // The top-level issuer controls discovery and identity validation.
		properties["clientSecret"] = object{"type": "string", "minLength": 1, "writeOnly": true}
		properties["skipDiscovery"] = object{"type": "boolean"}
		properties["tokenEndpointAuthentication"] = object{"enum": []string{"client_secret_basic", "client_secret_post", ""}}
		properties["clientId"] = object{"type": "string", "minLength": 1}
		config["required"] = []string{"clientId", "clientSecret"}
		config["if"] = object{"properties": object{"skipDiscovery": object{"const": true}}, "required": []string{"skipDiscovery"}}
		config["then"] = object{"required": []string{"authorizationEndpoint", "tokenEndpoint", "jwksEndpoint"}}
		body(responseObject(object{"providerId": providerID, "domain": text, "issuer": object{"type": "string", "format": "uri"},
			"organizationId": text, "overrideUserInfo": object{"type": "boolean"}, "oidcConfig": config}, "providerId", "domain", "issuer", "oidcConfig"))
	case "/sso/providers":
		op["description"] = "List the caller’s personal directories and directories in organizations they own or administer. Client identifiers are masked."
	case "/sso/get-provider":
		op["description"] = "Read a personal directory as its creator, or an organization directory as its owner or administrator. Client identifiers are masked."
		op["parameters"] = []object{{"name": "providerId", "in": "query", "required": true, "schema": providerID}}
	case "/sso/delete-provider", "/sso/request-domain-verification", "/sso/verify-domain":
		op["description"] = "Requires a direct session from the personal provider’s creator or a current owner or administrator of its organization."
		body(responseObject(object{"providerId": providerID}, "providerId"))
	case "/sign-in/sso":
		op["description"] = "Begin sign-in in a browser. Open the returned authorization URL in the same browser."
		callback := object{"type": "string", "minLength": 1, "description": "A trusted absolute URL or application path."}
		schema := responseObject(object{"providerId": providerID, "organizationSlug": text, "domain": text, "email": text,
			"callbackURL": callback, "newUserCallbackURL": callback, "errorCallbackURL": callback, "providerType": object{"enum": []string{"oidc", ""}},
			"loginHint": text, "requestSignUp": object{"type": "boolean"}, "scopes": array(object{"type": "string", "minLength": 1}),
			"additionalParams": object{"type": "object", "additionalProperties": text, "description": "Additional authorization parameters. Protocol parameters are reserved."}}, "callbackURL")
		schema["anyOf"] = []object{{"required": []string{"providerId"}}, {"required": []string{"organizationSlug"}}, {"required": []string{"domain"}}, {"required": []string{"email"}}}
		body(schema)
	case "/sso/callback", "/sso/callback/:providerId":
		op["description"] = "Complete the browser-bound OIDC flow. Successful authentication redirects to the trusted application callback. Invalid state or rejected authentication may redirect to an error page. No signed-in session is required."
		params := []object{
			{"name": "state", "in": "query", "required": true, "schema": object{"type": "string", "minLength": 1, "maxLength": 128}},
			{"name": "code", "in": "query", "description": "Authorization code on success.", "schema": text},
			{"name": "error", "in": "query", "description": "Identity provider error on failure.", "schema": text},
			{"name": "iss", "in": "query", "description": "Issuer if supplied by the identity provider.", "schema": text},
			{"name": info.SSOStateCookie, "in": "cookie", "required": true, "description": "Browser binding issued at sign-in.", "schema": text},
		}
		if path == "/sso/callback/:providerId" {
			params = append(params, object{"name": "providerId", "in": "path", "required": true, "schema": providerID})
		}
		op["parameters"] = params
	}
}
