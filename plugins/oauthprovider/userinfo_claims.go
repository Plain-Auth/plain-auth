package oauthprovider

import (
	"slices"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
)

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
