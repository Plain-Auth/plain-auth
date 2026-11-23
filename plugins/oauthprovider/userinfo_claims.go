package oauthprovider

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
)

// A stored code can carry the claims object directly or as an encoded query parameter.
func (opts Options) grantUserInfoClaims(raw json.RawMessage, openid bool) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if raw[0] == '"' {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, err
		}
		raw = []byte(value)
	}
	if openid {
		if _, problem := parseOIDCClaims(string(raw)); problem != nil {
			return nil, problem
		}
	}
	return opts.authorizedUserInfoClaims(raw)
}

func (opts Options) authorizedUserInfoClaims(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, errors.New("invalid authorization claims object")
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(raw, &claims); err != nil || claims["userinfo"] == nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(claims["userinfo"]))
	if kind, err := d.Token(); err != nil || kind != json.Delim('{') {
		return nil, errors.New("invalid userinfo claim request")
	}
	allowed := opts.supportedUserInfoClaims()
	var granted []string
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, err
		}
		// A requested member is null or an object carrying claim preferences.
		var member map[string]json.RawMessage
		if err := d.Decode(&member); err != nil {
			return nil, err
		}
		name := key.(string)
		if slices.Contains(allowed, name) && !slices.Contains(granted, name) {
			granted = append(granted, name)
		}
	}
	return granted, nil
}

func (opts Options) supportedUserInfoClaims() []string {
	allowed := opts.UserInfo.SupportedClaims
	if allowed == nil {
		allowed = []string{"sub", "iss", "aud", "exp", "iat", "sid", "scope", "azp"}
		if slices.Contains(opts.Scopes, "profile") {
			allowed = append(allowed, "name", "picture", "given_name", "family_name")
		}
		if slices.Contains(opts.Scopes, "email") {
			allowed = append(allowed, "email", "email_verified")
		}
	}
	return allowed
}

func (opts UserInfoOptions) projectClaims(c auth.EndpointContext, in UserInfoInput, subject string) (map[string]any, error) {
	// An unresolved standard claim remains reserved when its scope or its
	// individual name was granted, but is omitted from the JSON response.
	result := map[string]any{"sub": subject}
	standard := map[string]bool{"sub": true}
	claim := func(name, scope string, value any) {
		if slices.Contains(in.Scopes, scope) || slices.Contains(in.RequestedClaims, name) {
			standard[name] = true
			if value != nil {
				result[name] = value
			}
		}
	}
	claim("name", "profile", in.User.Name)
	var picture any
	if in.User.Image != nil {
		picture = *in.User.Image
	}
	claim("picture", "profile", picture)
	parts := strings.FieldsFunc(in.User.Name, func(r rune) bool { return r == ' ' })
	var given, family any
	if len(parts) > 1 {
		given = strings.Join(parts[:len(parts)-1], " ")
		family = parts[len(parts)-1]
	}
	claim("given_name", "profile", given)
	claim("family_name", "profile", family)
	claim("email", "email", in.User.Email)
	claim("email_verified", "email", in.User.EmailVerified)
	ctx := c.Request.Context()
	for _, extend := range opts.Extensions {
		extra, err := extend(ctx, in)
		if err != nil {
			return nil, err
		}
		for name, value := range extra {
			if standard[name] {
				continue
			}
			if _, exists := result[name]; exists {
				c.Auth.Logger().WarnContext(ctx, "OAuth UserInfo extensions supplied the same claim", "claim", name)
				continue
			}
			result[name] = value
		}
	}
	if opts.CustomClaims != nil {
		extra, err := opts.CustomClaims(ctx, in)
		if err != nil {
			return nil, err
		}
		for name, value := range extra {
			if name != "sub" {
				result[name] = value
			}
		}
	}
	return result, nil
}
