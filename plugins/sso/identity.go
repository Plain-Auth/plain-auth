package sso

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/publicnet"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var invalidIdentity = errors.New("invalid identity provider response")

var publicTransport = publicnet.Transport(invalidIdentity)

type providerTransport struct {
	auth    *auth.Auth
	trusted http.RoundTripper
}

func secureBrowserEndpoint(host *auth.Auth, raw string) error {
	if err := checkEndpoint(host, raw); err != nil {
		return err
	}
	u, _ := endpointURL(raw)
	if u.Scheme == "https" {
		return nil
	}
	name := u.Hostname()
	if host.ExplicitlyTrustedOrigin(raw) && (net.ParseIP(name).IsLoopback() || strings.EqualFold(name, "localhost")) {
		return nil
	}
	return apiError(400, "Enterprise identity endpoints require HTTPS")
}

func (t providerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	raw := req.URL.String()
	if e := secureBrowserEndpoint(t.auth, raw); e != nil {
		return nil, e
	}
	transport := http.RoundTripper(publicTransport)
	trusted := t.auth.ExplicitlyTrustedOrigin(raw)
	if trusted {
		transport = t.trusted
	}
	res, e := transport.RoundTrip(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return nil, errors.New("enterprise identity endpoint redirected")
	}
	const bound = 1 << 20
	data, e := io.ReadAll(io.LimitReader(res.Body, bound+1))
	if e != nil || len(data) > bound {
		return nil, invalidIdentity
	}
	res.Body = io.NopCloser(bytes.NewReader(data))
	return res, nil
}
func providerHTTP(host *auth.Auth, configured *http.Client) *http.Client {
	trusted := http.DefaultTransport
	timeout := 10 * time.Second
	if configured != nil {
		if configured.Transport != nil {
			trusted = configured.Transport
		}
		if configured.Timeout > 0 && configured.Timeout < timeout {
			timeout = configured.Timeout
		}
	}
	return &http.Client{Transport: providerTransport{host, trusted}, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// resolveIdentity also returns the verified ID token claims, nil without an
// ID token.
func resolveIdentity(ctx context.Context, client *http.Client, p BrowserProvider, token *oauth2.Token, nonce string) (auth.OAuthProfile, map[string]any, error) {
	var out auth.OAuthProfile
	var claims, idClaims map[string]any
	raw, ok := token.Extra("id_token").(string)
	if token.Extra("id_token") != nil && (!ok || raw == "") {
		return out, nil, invalidIdentity
	}
	sub := ""
	if raw != "" {
		cfg := p.OIDC
		verifier := oidc.NewVerifier(p.Issuer, oidc.NewRemoteKeySet(oidc.ClientContext(ctx, client), cfg.JWKSEndpoint), &oidc.Config{ClientID: cfg.ClientID, SupportedSigningAlgs: signingAlgorithms})
		verified, e := verifier.Verify(ctx, raw)
		if e != nil || verified.Issuer != p.Issuer || verified.Subject == "" || nonce == "" || verified.Nonce != nonce || verified.IssuedAt.IsZero() || verified.IssuedAt.After(time.Now().Add(1*time.Minute)) || !verified.Expiry.After(verified.IssuedAt) {
			return out, nil, invalidIdentity
		}
		if verified.AccessTokenHash != "" && verified.VerifyAccessToken(token.AccessToken) != nil {
			return out, nil, invalidIdentity
		}
		if e := verified.Claims(&claims); e != nil {
			return out, nil, invalidIdentity
		}
		idClaims = claims
		azp, has := claims["azp"]
		if (len(verified.Audience) > 1 || has) && azp != cfg.ClientID {
			return out, nil, invalidIdentity
		}
		sub = verified.Subject
	}
	if endpoint := p.OIDC.UserInfoEndpoint; endpoint != "" {
		if token.AccessToken == "" {
			return out, nil, invalidIdentity
		}
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if e != nil {
			return out, nil, invalidIdentity
		}
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		req.Header.Set("Accept", "application/json")
		res, e := client.Do(req)
		if e != nil {
			return out, nil, invalidIdentity
		}
		defer res.Body.Close()
		claims = nil
		if res.StatusCode != 200 || json.NewDecoder(res.Body).Decode(&claims) != nil {
			return out, nil, invalidIdentity
		}
		id, ok := claims["sub"].(string)
		if !ok || id == "" || sub != "" && sub != id {
			return out, nil, invalidIdentity
		}
		sub = id
	}
	if sub == "" || claims == nil {
		return out, nil, invalidIdentity
	}
	field := func(k, def string) any {
		key, _ := p.OIDC.Mapping[k].(string)
		if key == "" {
			key = def
		}
		return claims[key]
	}
	email, _ := field("email", "email").(string)
	if list, ok := field("email", "email").([]any); ok {
		for _, entry := range list {
			if e, ok := entry.(string); ok && e != "" {
				email = e
				break
			}
		}
	}
	name, _ := field("name", "name").(string)
	out = auth.OAuthProfile{Subject: sub, Email: email, Name: name, Data: claims}
	if photo, ok := field("image", "picture").(string); ok && photo != "" {
		out.Image = &photo
	}
	// Only declared user fields that are not server-only are written.
	extra, _ := p.OIDC.Mapping["extraFields"].(map[string]any)
	for name, claim := range extra {
		key, _ := claim.(string)
		if value, has := claims[key]; has {
			if out.AdditionalFields == nil {
				out.AdditionalFields = map[string]any{}
			}
			out.AdditionalFields[name] = value
		}
	}
	return out, idClaims, nil
}
