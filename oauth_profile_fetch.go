package plainauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const maxProfileBytes = 1 << 20

var errUserInfo = errors.New("auth: the provider's user info could not be read")

// userInfoResolver reads a hand-configured provider's profile. An ID token
// from the token response that names a subject and an email is used as it
// is: it came straight from the token endpoint over TLS, which OpenID
// Connect allows without checking its signature. Otherwise the profile comes
// from endpoint, called with the access token, and its subject is its id.
func userInfoResolver(endpoint string) func(context.Context, *oauth2.Token, string) (OAuthProfile, error) {
	return func(ctx context.Context, t *oauth2.Token, _ string) (OAuthProfile, error) {
		raw, _ := t.Extra("id_token").(string)
		if claims := unverifiedClaims(raw); jsonText(claims["sub"]) != "" && jsonText(claims["email"]) != "" {
			return mappedProfile(claims, jsonText(claims["sub"])), nil
		}
		if t.AccessToken == "" {
			return OAuthProfile{}, errUserInfo
		}
		client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
		if client == nil {
			client = &http.Client{Timeout: 15 * time.Second}
		}
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			return OAuthProfile{}, errUserInfo
		}
		req.Header.Set("Authorization", "Bearer "+t.AccessToken)
		req.Header.Set("Accept", "application/json")
		res, err := client.Do(req)
		if err != nil {
			return OAuthProfile{}, errUserInfo
		}
		defer res.Body.Close()
		body, err := io.ReadAll(io.LimitReader(res.Body, maxProfileBytes+1))
		if err != nil || res.StatusCode/100 != 2 || len(body) > maxProfileBytes {
			return OAuthProfile{}, errUserInfo
		}
		profile := decodeObject(body)
		if profile == nil {
			return OAuthProfile{}, errUserInfo
		}
		return mappedProfile(profile, jsonText(profile["id"])), nil
	}
}

// mappedProfile maps the standard claims. Data is the whole object with
// emailVerified, image and, when it has none, id added.
func mappedProfile(claims map[string]any, subject string) OAuthProfile {
	verified := claims["email_verified"] == true || claims["email_verified"] == "true"
	p := OAuthProfile{Subject: subject, Email: jsonText(claims["email"]), Name: jsonText(claims["name"]), EmailVerified: verified}
	data := maps.Clone(claims)
	if _, set := data["id"]; !set {
		data["id"] = subject
	}
	data["emailVerified"] = verified
	if picture := jsonText(claims["picture"]); picture != "" {
		p.Image = &picture
		data["image"] = picture
	}
	p.Data = data
	return p
}

// unverifiedClaims decodes a compact JWT's payload without checking its
// signature, or returns nil.
func unverifiedClaims(raw string) map[string]any {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	return decodeObject(payload)
}

func decodeObject(raw []byte) map[string]any {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var out map[string]any
	if d.Decode(&out) != nil || d.More() {
		return nil
	}
	return out
}

// jsonText returns a JSON string, or a number's text.
func jsonText(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	}
	return ""
}
