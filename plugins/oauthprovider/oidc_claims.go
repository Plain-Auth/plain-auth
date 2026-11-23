package oauthprovider

import (
	"encoding/json"
	"errors"
	"slices"

	auth "github.com/Plain-Org/plain-auth"
)

// parseOIDCClaims validates the two OIDC claim sets and checks the requested
// authentication context against the assurance this issuer can attest.
func parseOIDCClaims(raw string) (map[string]any, *auth.OAuthError) {
	invalid := &auth.OAuthError{Status: 400, Code: "invalid_request", Description: "claims must be a valid Claims request object"}
	var doc map[string]any
	if json.Unmarshal([]byte(raw), &doc) != nil || doc == nil {
		return nil, invalid
	}
	for _, set := range []string{"userinfo", "id_token"} {
		value, supplied := doc[set]
		if !supplied {
			continue
		}
		claims, ok := value.(map[string]any)
		if !ok {
			return nil, invalid
		}
		for _, value := range claims {
			if _, ok := value.(map[string]any); value != nil && !ok {
				return nil, invalid
			}
		}
	}
	identity, _ := doc["id_token"].(map[string]any)
	acr, _ := identity["acr"].(map[string]any)
	essential, ok := acr["essential"].(bool)
	if _, exists := acr["essential"]; exists && !ok {
		return nil, invalid
	}
	satisfied := true
	if v, exists := acr["value"]; exists {
		s, ok := v.(string)
		if !ok {
			return nil, invalid
		}
		satisfied = s == "0"
	}
	if v, exists := acr["values"]; exists {
		values, ok := v.([]any)
		if !ok {
			return nil, invalid
		}
		match := false
		for _, item := range values {
			s, ok := item.(string)
			if !ok {
				return nil, invalid
			}
			if s == "0" {
				match = true
			}
		}
		satisfied = satisfied && match
	}
	if essential && !satisfied {
		return nil, &auth.OAuthError{Status: 400, Code: "access_denied", Description: "essential acr requirement cannot be met"}
	}
	return doc, nil
}

func filterUserInfoClaims(doc map[string]any, accepted []string) string {
	if claims, ok := doc["userinfo"].(map[string]any); ok {
		for name := range claims {
			if !slices.Contains(accepted, name) {
				delete(claims, name)
			}
		}
		if len(claims) == 0 {
			delete(doc, "userinfo")
		}
	}
	if len(doc) == 0 {
		return ""
	}
	raw, _ := json.Marshal(doc) // The input was decoded from JSON.
	return string(raw)
}

func (opts Options) consentClaims(request string, selection any) (string, error) {
	raw, err := json.Marshal(selection)
	if err != nil {
		return "", err
	}
	if s, ok := selection.(string); ok {
		raw = []byte(s)
	}
	if _, problem := parseOIDCClaims(string(raw)); problem != nil {
		return "", problem
	}
	selected, err := opts.authorizedUserInfoClaims(raw)
	if err != nil {
		return "", err
	}
	if request == "" {
		if len(selected) != 0 {
			return "", registrationProblem(400, "invalid_request", "claim not originally requested")
		}
		return "", nil
	}
	doc, problem := parseOIDCClaims(request)
	if problem != nil {
		return "", problem
	}
	requested, err := opts.authorizedUserInfoClaims(json.RawMessage(request))
	if err != nil {
		return "", errors.New("oauthprovider: invalid consent claim request")
	}
	for _, name := range selected {
		if !slices.Contains(requested, name) {
			return "", registrationProblem(400, "invalid_request", "claim not originally requested")
		}
	}
	return filterUserInfoClaims(doc, selected), nil
}
