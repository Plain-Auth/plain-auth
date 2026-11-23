package providers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"golang.org/x/oauth2"
)

// MicrosoftEntraID configures a single organization tenant. Account identity is
// the signed directory object ID. The tenant must be a concrete GUID.
func MicrosoftEntraID(ctx context.Context, tenantID, clientID, secret string) (auth.OAuthProvider, error) {
	if !tenantIDPattern.MatchString(tenantID) {
		return auth.OAuthProvider{}, errors.New("Entra sign-in requires a tenant GUID")
	}
	tenantID = strings.ToLower(tenantID)
	p, err := OpenIDConnect(ctx, microsoftAuthority+"/"+tenantID+"/v2.0", clientID, secret)
	if err != nil {
		return auth.OAuthProvider{}, err
	}
	client := p.HTTPClient
	// The browser exchange and any native ID token must both bind to the tenant.
	resolve, verify := p.Resolve, p.VerifyIDToken
	p.Resolve = func(ctx context.Context, token *oauth2.Token, nonce string) (auth.OAuthProfile, error) {
		if token == nil {
			return auth.OAuthProfile{}, errors.New("missing Entra token")
		}
		signed, err := resolve(ctx, token, nonce)
		if err != nil {
			return auth.OAuthProfile{}, err
		}
		claims, err := entraClaims(signed, tenantID)
		if err != nil {
			return auth.OAuthProfile{}, err
		}
		var graph profileData
		if token.AccessToken != "" {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://graph.microsoft.com/oidc/userinfo", nil)
			if err != nil {
				return auth.OAuthProfile{}, err
			}
			req.Header.Set("Authorization", "Bearer "+token.AccessToken)
			req.Header.Set("Accept", "application/json")
			// Graph supplies optional profile fields when its subject matches the ID token.
			reply, err := providerJSON(client, req)
			if err == nil && reply.text("sub") == claims.text("sub") {
				graph = reply
			}
		}
		return entraProfile(claims, graph), nil
	}
	p.VerifyIDToken = func(ctx context.Context, raw, nonce string) (auth.OAuthProfile, time.Time, error) {
		signed, exp, err := verify(ctx, raw, nonce)
		if err != nil {
			return auth.OAuthProfile{}, time.Time{}, err
		}
		claims, err := entraClaims(signed, tenantID)
		if err != nil {
			return auth.OAuthProfile{}, time.Time{}, err
		}
		return entraProfile(claims, nil), exp, nil
	}
	return p, nil
}

func entraClaims(signed auth.OAuthProfile, tenant string) (profileData, error) {
	data, _ := signed.Data.(map[string]any)
	c := profileData(data)
	if strings.TrimSpace(c.text("oid")) == "" || c.text("sub") == "" || !strings.EqualFold(c.text("tid"), tenant) {
		return nil, errors.New("missing or mismatched signed Entra directory identity")
	}
	return c, nil
}

func entraName(p profileData) string {
	if name := p.text("name"); name != "" {
		return name
	}
	return strings.TrimSpace(p.text("given_name", "givenname") + " " + p.text("family_name", "familyname"))
}

func entraProfile(claims, graph profileData) auth.OAuthProfile {
	result := auth.OAuthProfile{Subject: claims.text("oid"), Name: entraName(claims), Email: claims.text("email")}
	if result.Name == "" {
		result.Name = entraName(graph)
	}
	if result.Email == "" {
		result.Email = graph.text("email")
	}
	if result.Email == "" {
		result.Email = result.Subject + "@microsoft-entra-id.placeholder.invalid"
	} else if _, exists := claims["email_verified"]; exists {
		result.EmailVerified = claims.verified("email_verified")
	} else if graph.text("email") == result.Email {
		result.EmailVerified = graph.verified("email_verified")
	}
	image := claims.text("picture")
	if image == "" {
		image = graph.text("picture")
	}
	fields := map[string]any{}
	for k, v := range graph {
		fields[k] = v
	}
	for k, v := range claims {
		fields[k] = v
	}
	fields["email"], fields["name"], fields["emailVerified"] = result.Email, result.Name, result.EmailVerified
	if image != "" {
		result.Image = &image
		fields["image"] = image
	}
	result.Data = fields
	return result
}
