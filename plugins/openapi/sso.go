package openapi

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"

	"github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
)

func samlConfigSchema() object {
	text := object{"type": "string", "minLength": 1}
	cert := object{"oneOf": []object{text, {"type": "array", "items": text, "minItems": 1, "maxItems": 8}}}
	encryption := object{"type": "boolean", "description": "Require encrypted assertions. The host must configure an RSA recipient key and certificate."}
	idp := responseObject(object{"entityID": text, "cert": cert, "metadata": text, "isAssertionEncrypted": encryption})
	idp["properties"].(object)["singleLogoutService"] = array(responseObject(object{"Binding": text, "Location": object{"type": "string", "format": "uri"}}, "Binding", "Location"))
	idp["properties"].(object)["singleSignOnService"] = array(responseObject(object{"Binding": text, "Location": object{"type": "string", "format": "uri"}}, "Binding", "Location"))
	idp["additionalProperties"] = false
	sp := responseObject(object{"entityID": text, "isAssertionEncrypted": encryption, "binding": text})
	sp["additionalProperties"] = false
	idp["anyOf"] = []object{{"required": []string{"entityID"}}, {"required": []string{"metadata"}}}
	config := responseObject(object{"callbackUrl": text, "idpInitiatedCallbackUrl": text, "entryPoint": object{"type": "string", "format": "uri"}, "cert": cert, "audience": text, "idpMetadata": idp, "spMetadata": sp, "wantAssertionsSigned": object{"type": "boolean"}, "authnRequestsSigned": object{"type": "boolean"}, "identifierFormat": text, "mapping": modelSchema(reflect.TypeFor[sso.SAMLMapping]()),
		"signatureAlgorithm": object{"type": "string", "minLength": 1, "description": "XML signature algorithm URI or a short form such as rsa-sha256, checked against SAMLOptions.Algorithms at registration."},
		"digestAlgorithm":    object{"type": "string", "minLength": 1, "description": "XML digest algorithm URI or a short form such as sha256, checked against SAMLOptions.Algorithms at registration."}}, "entryPoint", "idpMetadata")
	config["anyOf"] = []object{{"properties": object{"idpMetadata": object{"required": []string{"metadata"}}}}, {"required": []string{"cert"}}, {"properties": object{"idpMetadata": object{"required": []string{"cert"}}}}}
	return config
}

func ssoResponse(path string, info plainauth.HTTPDescription) object {
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
		if info.SAMLStateCookie != "" {
			fields["samlConfig"] = object{"oneOf": []object{samlConfigSchema(), {"type": "null"}}}
			fields["oidcConfig"] = object{"oneOf": []object{fields["oidcConfig"].(object), {"type": "null"}}}
		}
		required := []string{"id", "providerId", "userId", "domain", "issuer", "redirectURI", "oidcConfig", "samlConfig"}
		if slices.ContainsFunc(info.Routes, func(r plainauth.HTTPRoute) bool {
			return r.Plugin == "sso" && r.Path == "/sso/request-domain-verification"
		}) {
			fields["domainVerified"] = object{"const": false}
			fields["domainVerificationToken"] = text
			required = append(required, "domainVerified", "domainVerificationToken")
		}
		return returnedProviderFields(responseObject(fields, required...), routeProviderFields(info, path))
	case "/sso/providers":
		return responseObject(object{"providers": array(returnedProviderFields(modelSchema(reflect.TypeFor[sso.PublicProvider]()), routeProviderFields(info, path)))}, "providers")
	case "/sso/get-provider", "/sso/update-provider":
		return returnedProviderFields(modelSchema(reflect.TypeFor[sso.PublicProvider]()), routeProviderFields(info, path))
	case "/sso/delete-provider":
		return responseObject(object{"success": object{"const": true}}, "success")
	case "/sign-in/sso":
		return responseObject(object{"url": object{"type": "string", "format": "uri"}, "redirect": object{"const": true}}, "url", "redirect")
	case "/sso/request-domain-verification":
		return responseObject(object{"domainVerificationToken": text}, "domainVerificationToken")
	}
	return object{}
}

func describeSSORequest(op object, route plainauth.HTTPRoute, info plainauth.HTTPDescription) {
	path := route.Path
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
		properties["tokenEndpointAuthentication"] = object{"enum": []string{"client_secret_basic", "client_secret_post", "private_key_jwt", ""}}
		properties["clientId"] = object{"type": "string", "minLength": 1}
		config["required"] = []string{"clientId"}
		registration := responseObject(object{"providerId": providerID, "domain": text, "issuer": object{"type": "string", "format": "uri"}, "organizationId": text, "overrideUserInfo": object{"type": "boolean"}, "oidcConfig": config}, "providerId", "domain", "issuer", "oidcConfig")
		if info.SAMLStateCookie != "" {
			registration["properties"].(object)["samlConfig"] = samlConfigSchema()
			registration["required"] = []string{"providerId", "domain", "issuer"}
			registration["oneOf"] = []object{{"required": []string{"oidcConfig"}}, {"required": []string{"samlConfig"}}}
		}
		withProviderFields(registration, providerFields(route.OpenAPI), true)
		body(registration)

	case "/sso/update-provider":
		op["description"] = "Change a managed provider’s issuer, domain or OIDC configuration with the manager’s session; a supplied mapping replaces the whole mapping. Changing the issuer, client ID or an endpoint returns a conflict while accounts are linked."
		config := modelSchema(reflect.TypeFor[sso.Config]())
		properties := config["properties"].(object)
		delete(properties, "issuer")
		properties["clientSecret"] = object{"type": "string", "minLength": 1, "writeOnly": true}
		properties["skipDiscovery"] = object{"type": "boolean"}
		properties["tokenEndpointAuthentication"] = object{"enum": []string{"client_secret_basic", "client_secret_post", "private_key_jwt"}}
		// Every field is optional in a partial update; unknown keys and null
		// are refused.
		properties["pkce"] = object{"type": "boolean"}
		delete(config, "required")
		config["additionalProperties"] = false
		update := responseObject(object{"providerId": providerID, "issuer": object{"type": "string", "format": "uri"}, "domain": text, "oidcConfig": config}, "providerId")
		update["additionalProperties"] = false
		if info.SAMLStateCookie != "" {
			op["description"] = op["description"].(string) + " For a SAML directory, samlConfig merges entryPoint, cert, audience, callbackUrl, idpInitiatedCallbackUrl (null clears it), mapping, wantAssertionsSigned, authnRequestsSigned, identifierFormat, the algorithms and the idpMetadata and spMetadata fields under the registration checks. An issuer change also moves the default SP entity ID. Changing the IdP entity or sign-in service, the SP entity ID, NameID format, audience or signing policy returns a conflict while accounts are linked; a certificate rotation does not."
			saml := object{"type": "object", "properties": object{"entryPoint": object{"type": "string", "format": "uri"}, "cert": object{}, "audience": text, "callbackUrl": text,
				"idpInitiatedCallbackUrl": object{"type": []string{"string", "null"}}, "mapping": object{"type": "object"}, "wantAssertionsSigned": object{"type": "boolean"}, "authnRequestsSigned": object{"type": "boolean"},
				"identifierFormat": text, "signatureAlgorithm": text, "digestAlgorithm": text, "idpMetadata": object{"type": "object", "properties": object{"metadata": text, "entityID": text, "cert": object{}, "isAssertionEncrypted": object{"type": "boolean"},
					"singleSignOnService": object{"type": "array"}, "singleLogoutService": object{"type": "array"}}}, "spMetadata": object{"type": "object", "properties": object{"entityID": text, "binding": text, "isAssertionEncrypted": object{"type": "boolean"}}}}, "additionalProperties": false}
			update["properties"].(object)["samlConfig"] = saml
		}
		withProviderFields(update, providerFields(route.OpenAPI), false)
		body(update)
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
			"callbackURL": callback, "newUserCallbackURL": callback, "errorCallbackURL": callback, "providerType": object{"type": "string", "enum": []string{"oidc", "saml"}},
			"loginHint": text, "requestSignUp": object{"type": "boolean"}, "scopes": array(object{"type": "string", "minLength": 1}),
			"additionalParams": object{"type": "object", "additionalProperties": text, "description": "Additional authorization parameters. Protocol parameters are reserved."}}, "callbackURL")
		if info.OAuthLoginContinuation {
			schema["properties"].(object)["oauth_query"] = object{"type": "string", "description": "Verified issuer login query to resume after an OIDC sign-in."}
		}
		schema["anyOf"] = []object{{"required": []string{"providerId"}}, {"required": []string{"organizationSlug"}}, {"required": []string{"domain"}}, {"required": []string{"email"}}}
		body(schema)
	case "/sso/saml2/sp/metadata":
		op["parameters"] = []object{{"name": "providerId", "in": "query", "required": true, "schema": providerID}}
	case "/sso/saml2/logout/:providerId":
		op["description"] = "Revoke the active SAML browser session and redirect to its registered identity provider."
		op["security"] = []object{{"apiKeyCookie": []string{}}}
		op["parameters"] = []object{{"name": "providerId", "in": "path", "required": true, "schema": providerID}}
		body(responseObject(object{"callbackURL": text}))
	case "/sso/saml2/sp/slo/:providerId":
		var mode struct {
			Incoming bool `json:"x-plainauth-idp-logout"`
		}
		if len(route.OpenAPI) != 0 {
			_ = json.Unmarshal(route.OpenAPI, &mode)
		}
		op["description"] = "Consume the initiating browser's signed HTTP-Redirect logout acknowledgement."
		op["security"] = []object{}
		params := []object{{"name": "providerId", "in": "path", "required": true, "schema": providerID}, {"name": info.SAMLLogoutCookie, "in": "cookie", "required": !mode.Incoming, "schema": text, "description": "Required when processing a LogoutResponse."}}
		if mode.Incoming {
			op["description"] = "Provide exactly one signed HTTP-Redirect protocol message. A LogoutResponse requires the browser binding and RelayState. A LogoutRequest revokes the exact signed NameID and SessionIndex and returns a signed response to the directory."
			params = append(params, object{"name": "SAMLRequest", "in": "query", "required": false, "schema": text})
		}
		for _, key := range []string{"SAMLResponse", "RelayState", "SigAlg", "Signature"} {
			params = append(params, object{"name": key, "in": "query", "required": !mode.Incoming || key == "SigAlg" || key == "Signature", "schema": text})
		}
		op["parameters"] = params

	case "/sso/saml2/sp/acs/:providerId":
		if route.Method == "GET" {
			// The GET only returns a signed-in browser; it takes no response.
			op["description"] = "Return a signed-in browser to a trusted RelayState, or the application origin. Any other browser goes to the error page with error=invalid_request."
			op["security"] = []object{{"apiKeyCookie": []string{}}}
			op["parameters"] = []object{{"name": "providerId", "in": "path", "required": true, "schema": providerID}, {"name": "RelayState", "in": "query", "required": false, "schema": text}}
			break
		}
		var mode struct {
			Portal bool `json:"x-plainauth-idp-initiated"`
		}
		if len(route.OpenAPI) != 0 {
			_ = json.Unmarshal(route.OpenAPI, &mode)
		}
		required := []string{"SAMLResponse"}
		params := []object{{"name": "providerId", "in": "path", "required": true, "schema": providerID}, {"name": info.SAMLStateCookie, "in": "cookie", "required": !mode.Portal, "schema": text, "description": "Browser binding for a service-provider-initiated request."}}
		if mode.Portal {
			params = append(params, object{"name": "Origin", "in": "header", "required": false, "schema": text, "description": "A portal POST without RelayState requires the exact origin of its reviewed IdP."})
			op["description"] = "A service-provider return requires RelayState and its browser cookie. A reviewed IdP portal returns a signed assertion without RelayState or InResponseTo."
		} else {
			required = append(required, "RelayState")
		}
		op["parameters"] = params
		body := responseObject(object{"SAMLResponse": text, "RelayState": text}, required...)
		op["requestBody"] = object{"required": true, "content": object{"application/x-www-form-urlencoded": object{"schema": body}, "application/json": object{"schema": body}}}

	case "/sso/callback", "/sso/callback/:providerId":
		op["description"] = "Complete the browser-bound OIDC flow. Successful authentication redirects to the trusted application callback. Invalid state or rejected authentication may redirect to an error page. No signed-in session is required."
		if info.OAuthLoginContinuation {
			op["description"] = "Complete the browser-bound OIDC flow. A signed issuer login continues authorization with the new session. A navigation receives the next location and a JSON client receives its URL. Ordinary login uses the application's trusted callback."
			op["responses"].(object)["200"] = response("application/json", responseObject(object{"redirect": object{"const": true}, "url": text}, "redirect", "url"))
		}
		var mode struct {
			Restart bool `json:"x-plainauth-idp-initiated"`
		}
		if len(route.OpenAPI) != 0 {
			_ = json.Unmarshal(route.OpenAPI, &mode)
		}
		if mode.Restart {
			op["description"] = op["description"].(string) + " A code without state, for a provider the host's policy approves, discards the code and redirects to a new authorization at the identity provider; a policy error answers 503."
			op["responses"].(object)["503"] = object{"description": "The IdP-initiated sign-in policy is unavailable."}
		}
		params := []object{
			{"name": "state", "in": "query", "required": !mode.Restart, "schema": object{"type": "string", "minLength": 1, "maxLength": 128}},
			{"name": "code", "in": "query", "description": "Authorization code on success.", "schema": text},
			{"name": "error", "in": "query", "description": "Identity provider error on failure.", "schema": text},
			{"name": "iss", "in": "query", "description": "Issuer if supplied by the identity provider.", "schema": text},
			{"name": info.SSOStateCookie, "in": "cookie", "required": !mode.Restart, "description": "Browser binding issued at sign-in.", "schema": text},
		}
		if path == "/sso/callback/:providerId" {
			params = append(params, object{"name": "providerId", "in": "path", "required": true, "schema": providerID})
		}
		op["parameters"] = params
	}
}

// providerField is one declared SSO provider field from the sso plugin's
// x-plainauth-provider-fields extension.
type providerField struct {
	Schema   object `json:"schema"`
	Input    bool   `json:"input"`
	Required bool   `json:"required"`
	Returned bool   `json:"returned"`
}

func providerFields(raw json.RawMessage) map[string]providerField {
	var doc struct {
		Fields map[string]providerField `json:"x-plainauth-provider-fields"`
	}
	if len(raw) != 0 {
		_ = json.Unmarshal(raw, &doc)
	}
	return doc.Fields
}

// routeProviderFields returns the declared fields of the sso route at path.
func routeProviderFields(info plainauth.HTTPDescription, path string) map[string]providerField {
	for _, r := range info.Routes {
		if r.Plugin == "sso" && r.Path == path {
			return providerFields(r.OpenAPI)
		}
	}
	return nil
}

// withProviderFields adds the declared fields a request may set to a body
// schema, requiring the required ones at registration.
func withProviderFields(schema object, fields map[string]providerField, create bool) {
	properties := schema["properties"].(object)
	required, _ := schema["required"].([]string)
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		f := fields[name]
		if !f.Input {
			continue
		}
		properties[name] = f.Schema
		if create && f.Required {
			required = append(required, name)
		}
	}
	if len(required) > 0 {
		schema["required"] = required
	}
}

// returnedProviderFields adds the declared fields responses return.
func returnedProviderFields(schema object, fields map[string]providerField) object {
	if len(fields) == 0 {
		return schema
	}
	properties, _ := schema["properties"].(object)
	if properties == nil {
		return schema
	}
	for name, f := range fields {
		if f.Returned {
			properties[name] = f.Schema
		}
	}
	return schema
}
