package sso

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var invalidIdentity = errors.New("invalid identity provider response")

func publicAddress(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.Zone() != "" || a.Is6() && !v6Global.Contains(a) {
		return false
	}
	for _, prefix := range specialIPs {
		if prefix.Contains(a) {
			return false
		}
	}
	return true
}

// Resolve and dial the same vetted address. A proxy, custom dialer, or second
// DNS resolution must not redirect untrusted tenant endpoints to internal hosts.
var publicTransport = &http.Transport{TLSHandshakeTimeout: 5 * time.Second, IdleConnTimeout: 30 * time.Second, MaxResponseHeaderBytes: 32 << 10,
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(addr)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil || len(ips) == 0 {
			return nil, invalidIdentity
		}
		for _, ip := range ips {
			if !publicAddress(ip) {
				return nil, invalidIdentity
			}
		}
		var d net.Dialer
		for _, ip := range ips {
			conn, e := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if e == nil {
				return conn, nil
			}
		}
		return nil, invalidIdentity
	}}

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
func resolveIdentity(ctx context.Context, client *http.Client, p BrowserProvider, token *oauth2.Token, nonce string) (auth.OAuthProfile, error) {
	var out auth.OAuthProfile
	var claims map[string]any
	raw, ok := token.Extra("id_token").(string)
	if token.Extra("id_token") != nil && (!ok || raw == "") {
		return out, invalidIdentity
	}
	sub := ""
	if raw != "" {
		cfg := p.OIDC
		verifier := oidc.NewVerifier(p.Issuer, oidc.NewRemoteKeySet(oidc.ClientContext(ctx, client), cfg.JWKSEndpoint), &oidc.Config{ClientID: cfg.ClientID, SupportedSigningAlgs: []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}})
		verified, e := verifier.Verify(ctx, raw)
		if e != nil || verified.Issuer != p.Issuer || verified.Subject == "" || nonce == "" || verified.Nonce != nonce || verified.IssuedAt.IsZero() || verified.IssuedAt.After(time.Now().Add(1*time.Minute)) || !verified.Expiry.After(verified.IssuedAt) {
			return out, invalidIdentity
		}
		if verified.AccessTokenHash != "" && verified.VerifyAccessToken(token.AccessToken) != nil {
			return out, invalidIdentity
		}
		if e := verified.Claims(&claims); e != nil {
			return out, invalidIdentity
		}
		azp, has := claims["azp"]
		if (len(verified.Audience) > 1 || has) && azp != cfg.ClientID {
			return out, invalidIdentity
		}
		sub = verified.Subject
	}
	if endpoint := p.OIDC.UserInfoEndpoint; endpoint != "" {
		if token.AccessToken == "" {
			return out, invalidIdentity
		}
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if e != nil {
			return out, invalidIdentity
		}
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		req.Header.Set("Accept", "application/json")
		res, e := client.Do(req)
		if e != nil {
			return out, invalidIdentity
		}
		defer res.Body.Close()
		claims = nil
		if res.StatusCode != 200 || json.NewDecoder(res.Body).Decode(&claims) != nil {
			return out, invalidIdentity
		}
		id, ok := claims["sub"].(string)
		if !ok || id == "" || sub != "" && sub != id {
			return out, invalidIdentity
		}
		sub = id
	}
	if sub == "" || claims == nil {
		return out, invalidIdentity
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
	return out, nil
}
