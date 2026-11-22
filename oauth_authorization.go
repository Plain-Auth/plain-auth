package plainauth

import (
	"slices"
	"strings"

	"golang.org/x/oauth2"
)

// Client request parameters only affect this outbound authorization URL.
func authorizationOptions(body wireBody, defaults []string) ([]oauth2.AuthCodeOption, error) {
	var options []oauth2.AuthCodeOption
	if value, present := body["scopes"]; present {
		items, ok := value.([]any)
		if !ok {
			return nil, fieldTypeError("scopes", "array", body)
		}
		scopes := slices.Clone(defaults)
		for _, item := range items {
			scope, ok := item.(string)
			if !ok {
				return nil, validationError("scopes must contain strings")
			}
			if scope != "" && !slices.Contains(scopes, scope) {
				scopes = append(scopes, scope)
			}
		}
		if len(scopes) > 0 {
			options = append(options, oauth2.SetAuthURLParam("scope", strings.Join(scopes, " ")))
		}
	}
	if value, present := body["loginHint"]; present {
		hint, ok := value.(string)
		if !ok {
			return nil, fieldTypeError("loginHint", "string", body)
		}
		if hint != "" {
			options = append(options, oauth2.SetAuthURLParam("login_hint", hint))
		}
	}
	if value, present := body["additionalParams"]; present {
		params, ok := value.(map[string]any)
		if !ok {
			return nil, fieldTypeError("additionalParams", "object", body)
		}
		for key, raw := range params {
			switch strings.ToLower(key) {
			case "state", "client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "nonce", "scope", "client_key", "appid", "request", "request_uri", "client_secret":
				return nil, validationError("additionalParams contains a reserved OAuth parameter")
			}
			v, ok := raw.(string)
			if !ok {
				return nil, validationError("additionalParams must contain string values")
			}
			options = append(options, oauth2.SetAuthURLParam(key, v))
		}
	}
	return options, nil
}
