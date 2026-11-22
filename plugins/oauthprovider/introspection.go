package oauthprovider

import (
	"context"
	"strings"
	"time"
	"unicode"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/jsjson"
)

// MachineIntrospectionStore reads the current caller registration and its
// unrevoked, unbound machine token in a single consistent snapshot. Return a nil
// record for an unknown digest, a different owner or any other token kind.
// Return ErrClientNotFound for a missing registration. digest may be empty
// when only the caller's current credentials need to be checked.
type MachineIntrospectionStore interface {
	MachineClientReader
	InspectMachineToken(ctx context.Context, clientID, digest string) (MachineClient, *MachineTokenRecord, error)
}

const introspectionOperation = `{
  "summary":"Check the status of an opaque machine access token",
  "security":[{"clientSecretBasic":[]},{}],
  "description":"Authenticate as the issuing application using its registered method: HTTP Basic, client_secret_post or private_key_jwt.",
  "requestBody":{"required":true,"content":{"application/x-www-form-urlencoded":{"schema":{
    "type":"object","required":["token"],"properties":{"token":{"type":"string"},"token_type_hint":{"type":"string"},
      "client_id":{"type":"string"},"client_secret":{"type":"string","format":"password"},"client_assertion_type":{"type":"string","enum":["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]},
      "client_assertion":{"type":"string","format":"jwt"}}
  }}}},
  "responses":{"200":{"description":"Current token status","content":{"application/json":{"schema":{
    "type":"object","required":["active"],"properties":{"active":{"type":"boolean"},"iss":{"type":"string"},
      "client_id":{"type":"string"},"azp":{"type":"string"},"scope":{"type":"string"},
      "token_type":{"type":"string"},"exp":{"type":"integer"},"iat":{"type":"integer"}}
  }}}},"400":{"description":"Invalid form or client credentials"},"401":{"description":"Client authentication required"},
  "415":{"description":"Unsupported request media type"}}
}`

func (opts Options) introspect(c auth.EndpointContext) (any, error) {
	req, err := readTokenAction(c, true)
	if err != nil {
		return nil, err
	}
	store, ok := c.Store().(MachineIntrospectionStore)
	if !ok {
		return nil, &auth.APIError{Status: 501, Code: "OAUTH_INTROSPECTION_STORE_UNAVAILABLE", Message: "The configured store does not support OAuth token introspection"}
	}
	ctx := c.Request.Context()
	in := req.client
	first, err := opts.authenticateClient(c, store, in, "/oauth2/introspect")
	if err != nil {
		return nil, tokenEndpointError(c.ResponseHeader, req.challenge, err)
	}
	var digest string
	raw, prefixed := strings.CutPrefix(req.token, opts.Tokens.OpaquePrefix)
	if prefixed && raw != "" && req.hint != "refresh_token" {
		digest, err = opts.Tokens.storedOpaque(ctx, raw)
		if err != nil {
			return nil, err
		}
	}
	current, record, err := store.InspectMachineToken(ctx, in.id, digest)
	if err == nil {
		err = in.recheckClient(first, current)
	}
	if err != nil {
		return nil, tokenEndpointError(c.ResponseHeader, req.challenge, err)
	}
	if digest == "" || record == nil || record.StoredToken != digest || !record.ExpiresAt.After(time.Now()) {
		return map[string]bool{"active": false}, nil
	}
	return map[string]any{
		"active": true, "iss": c.Auth.OAuthIssuer(), "client_id": in.id, "azp": in.id,
		"scope": strings.Join(record.Scopes, " "), "token_type": "Bearer",
		"exp": record.ExpiresAt.Unix(), "iat": record.IssuedAt.Unix(),
	}, nil
}

type tokenAction struct {
	client                 tokenRequest
	challenge, token, hint string
}

func readTokenAction(c auth.EndpointContext, requireSecret bool) (tokenAction, error) {
	c.ResponseHeader.Set("Cache-Control", "no-store")
	c.ResponseHeader.Set("Pragma", "no-cache")
	form, err := readTokenForm(c.Request)
	if err != nil {
		return tokenAction{}, err
	}
	tokens := form["token"]
	if len(tokens) == 0 {
		return tokenAction{}, registrationProblem(400, "invalid_request", "token is required")
	}
	in, challenge, err := parseTokenCredentials(form, c.Request.Header.Values("Authorization"))
	if err != nil {
		return tokenAction{}, tokenEndpointError(c.ResponseHeader, challenge, err)
	}
	if in.id == "" || (requireSecret && in.secret == "" && in.assertion == nil) {
		return tokenAction{}, tokenEndpointError(c.ResponseHeader, "Basic", invalidClient("missing required credentials"))
	}
	raw := tokens[len(tokens)-1]
	if raw == "" {
		if !requireSecret {
			return tokenAction{}, registrationProblem(400, "invalid_request", "missing a required token for revocation")
		}
		return tokenAction{}, registrationProblem(400, "invalid_request", "missing a required token for introspection")
	}
	req := tokenAction{client: in, challenge: challenge, token: stripTokenScheme(raw)}
	if hints := form["token_type_hint"]; len(hints) != 0 {
		req.hint = hints[len(hints)-1]
	}
	return req, nil
}

func stripTokenScheme(token string) string {
	token = jsjson.TrimSpace(token)
	space := strings.IndexFunc(token, unicode.IsSpace)
	if space > 0 && (strings.EqualFold(token[:space], "Bearer") || strings.EqualFold(token[:space], "DPoP")) {
		return jsjson.TrimSpace(token[space:])
	}
	return token
}
