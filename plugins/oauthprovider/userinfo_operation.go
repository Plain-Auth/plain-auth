package oauthprovider

import (
	"encoding/json"
	"net/http"
)

func userInfoOperation(method string) json.RawMessage {
	const base = `{"summary":"Read claims about the authenticated OpenID Connect user",
    "security":[{"bearerAuth":[]},{"OAuth2":["openid"]}],
    "parameters":[{"name":"Authorization","in":"header","schema":{"type":"string"}},{"name":"DPoP","in":"header","schema":{"type":"string"}}],
    "responses":{"200":{"description":"User profile for the granted scopes and requested claims","content":{"application/json":{"schema":{"type":"object","required":["sub"],"properties":{"sub":{"type":"string"},"name":{"type":"string"},"given_name":{"type":"string"},"family_name":{"type":"string"},"picture":{"type":"string"},"email":{"type":"string","format":"email"},"email_verified":{"type":"boolean"}}}}}},
    "400":{"description":"Conflicting token transport, missing scope or user"},"401":{"description":"A valid access token and any required sender proof are required","headers":{"WWW-Authenticate":{"schema":{"type":"string"}}}}}`
	if method == http.MethodPost {
		return json.RawMessage(base + `,"requestBody":{"content":{"application/x-www-form-urlencoded":{"schema":{"type":"object","properties":{"access_token":{"type":"string"}}}}}}}`)
	}
	return json.RawMessage(base + "}")
}
