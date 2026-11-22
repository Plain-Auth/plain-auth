package plainauth

import "testing"

func TestSocialAuthorizationOptionValidation(t *testing.T) {
	for _, key := range []string{"STATE", "client_key", "appid", "request", "request_uri", "client_secret"} {
		if _, err := authorizationOptions(wireBody{"additionalParams": map[string]any{key: "fixture"}}, nil); err == nil {
			t.Errorf("accepted %s", key)
		}
	}
	for _, body := range []wireBody{{"loginHint": false}, {"scopes": "contacts"}, {"scopes": []any{10}}, {"additionalParams": []any{}}, {"additionalParams": map[string]any{"display": true}}} {
		if _, err := authorizationOptions(body, nil); err == nil {
			t.Errorf("accepted invalid field type %#v", body)
		}
	}
}
