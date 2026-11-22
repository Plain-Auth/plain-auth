package oauthprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ChallengeOptions configures the WWW-Authenticate response from a protected API.
type ChallengeOptions struct {
	// MetadataMappings supplies public HTTPS metadata URLs for URNs and opaque identifiers.
	MetadataMappings map[string]string
	// Scopes hints which scopes a client can request when initially authenticating.
	Scopes []string
	// DPoPSigningAlgorithms lists proof algorithms accepted by the resource verifier.
	DPoPSigningAlgorithms []string
}

// ResourceChallenges holds validated, immutable challenge configuration.
type ResourceChallenges struct {
	metadata []string
	scopes   string
	algs     string
}

// NewResourceChallenges derives one metadata pointer per protected resource, in order.
// Resource identifiers and their mappings come from the host application's configuration.
func NewResourceChallenges(resources []string, opts ChallengeOptions) (*ResourceChallenges, error) {
	if len(resources) == 0 {
		return nil, errors.New("oauthprovider: challenges require a protected resource")
	}
	scopes, err := challengeScopes(opts.Scopes)
	if err != nil {
		return nil, err
	}
	algs := opts.DPoPSigningAlgorithms
	if algs == nil {
		algs = resourceSigningAlgorithms()
	}
	for _, alg := range algs {
		if !validDPoPAlgorithm(alg) {
			return nil, fmt.Errorf("oauthprovider: invalid DPoP signing algorithm %q", alg)
		}
	}
	challenges := &ResourceChallenges{scopes: scopes, algs: strings.Join(algs, " ")}
	for _, resource := range resources {
		u, err := url.Parse(resource)
		if resource == "" || strings.ContainsAny(resource, "\r\n\t") || err != nil {
			return nil, fmt.Errorf("oauthprovider: invalid resource %q", resource)
		}
		metadata := opts.MetadataMappings[resource]
		if u.Host != "" || u.Scheme == "http" || u.Scheme == "https" {
			u, err = metadataURL(resource, true)
			if err != nil {
				return nil, fmt.Errorf("oauthprovider: invalid resource: %w", err)
			}
			_, target := resourceMetadataPath(u)
			metadata = u.Scheme + "://" + u.Host + target
		} else if _, err := metadataURL(metadata, true); err != nil {
			return nil, fmt.Errorf("oauthprovider: resource %q requires an HTTPS metadata mapping", resource)
		}
		challenges.metadata = append(challenges.metadata, metadata)
	}
	return challenges, nil
}

// ResourceFailure describes a public failure reported by the application's token verifier.
// MissingScopes identifies a 403 that can be resolved by requesting more scopes.
// Message and Description may be sent to the client. Keep internal errors separate.
type ResourceFailure struct {
	Status        int
	Code          string
	Message       string
	Description   string
	MissingScopes []string
}

func challengeScopes(scopes []string) (string, error) {
	seen := make(map[string]bool, len(scopes))
	unique := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if !validScope(scope) {
			return "", fmt.Errorf("oauthprovider: invalid challenge scope %q", scope)
		}
		if !seen[scope] {
			seen[scope] = true
			unique = append(unique, scope)
		}
	}
	return strings.Join(unique, " "), nil
}

func headerDescription(s string) string {
	s = strings.Map(func(c rune) rune {
		switch {
		case c == '"':
			return '\''
		case c < ' ' || c > '~' || c == '\\':
			return ' '
		default:
			return c
		}
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

func quotedParameter(name, value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	return name + "=\"" + strings.ReplaceAll(value, "\"", "\\\"") + "\""
}

// Write sends a Bearer or DPoP challenge including the original public JSON error.
// It leaves w untouched and returns false for ordinary permission denials and server
// failures. A nil request selects the challenge from the verifier's failure alone.
func (c *ResourceChallenges) Write(w http.ResponseWriter, r *http.Request, failure ResourceFailure) (bool, error) {
	scope := c.scopes
	description := failure.Description
	if description == "" {
		description = failure.Message
	}
	code, message := failure.Code, failure.Message
	insufficient := failure.Status == http.StatusForbidden && code == "insufficient_scope" && len(failure.MissingScopes) != 0
	if insufficient {
		var err error
		scope, err = challengeScopes(failure.MissingScopes)
		if err != nil {
			return false, err
		}
		if description == "" {
			description = "access token is missing required scope: " + strings.Join(failure.MissingScopes, " ")
		}
		message = description
	} else if failure.Status != http.StatusUnauthorized {
		return false, nil
	}

	dpop := needsDPoPChallenge(r, code, description)
	if dpop && code == "" {
		code = "invalid_token"
	} else if !dpop && !insufficient && code != "invalid_token" {
		code = ""
	}
	var desc string
	if code != "" {
		if !validScope(code) {
			return false, errors.New("oauthprovider: invalid challenge error code")
		}
		desc = headerDescription(description)
	}
	var header string
	if dpop {
		params := []string{quotedParameter("error", code)}
		if insufficient {
			params = append(params, quotedParameter("scope", scope))
		}
		params = appendParameter(params, "error_description", desc)
		params = append(params, quotedParameter("algs", c.algs))
		header = "DPoP " + strings.Join(params, ", ")
	} else {
		header = c.bearerHeader(code, desc, scope)
	}

	h := w.Header()
	h.Add("WWW-Authenticate", header)
	h.Add("Access-Control-Expose-Headers", "WWW-Authenticate")
	h.Set("Content-Type", "application/json")
	w.WriteHeader(failure.Status)
	body := map[string]string{"message": message}
	if code != "" {
		body["error"], body["error_description"] = code, description
	}
	return true, json.NewEncoder(w).Encode(body)
}

func needsDPoPChallenge(r *http.Request, code, description string) bool {
	var scheme string
	if r != nil {
		if fields := strings.Fields(r.Header.Get("Authorization")); len(fields) >= 2 {
			scheme = fields[0]
		}
	}
	if strings.EqualFold(scheme, "DPoP") {
		return true
	}
	proofFailure := code == "invalid_dpop_proof" || (code == "invalid_token" && strings.Contains(description, "DPoP"))
	return proofFailure && (r == nil || strings.EqualFold(scheme, "Bearer"))
}

func appendParameter(params []string, name, value string) []string {
	if value != "" {
		return append(params, quotedParameter(name, value))
	}
	return params
}

func (c *ResourceChallenges) bearerHeader(code, description, scope string) string {
	params := appendParameter(nil, "error", code)
	lastName, lastValue := "scope", scope
	if code == "insufficient_scope" {
		params = appendParameter(params, "scope", scope)
		lastName, lastValue = "error_description", description
	} else {
		params = appendParameter(params, "error_description", description)
	}
	challenges := make([]string, 0, len(c.metadata))
	for _, metadata := range c.metadata {
		parts := append(params, quotedParameter("resource_metadata", metadata))
		parts = appendParameter(parts, lastName, lastValue)
		challenges = append(challenges, "Bearer "+strings.Join(parts, ", "))
	}
	return strings.Join(challenges, ", ")
}
