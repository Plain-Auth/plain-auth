package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RemoteVerification introspects access tokens at the issuer, as another
// runtime's remoteVerify does, so an API can accept opaque tokens and see
// ended sessions.
type RemoteVerification struct {
	// IntrospectionURL is the issuer's /oauth2/introspect, over HTTPS or
	// HTTP on loopback, since the request carries the API's secret.
	IntrospectionURL string
	// ClientID and ClientSecret authenticate the API, registered with
	// client_secret_post and linked to its resource.
	ClientID, ClientSecret string
	// Force skips the local JWT check, and with it the typ check.
	Force bool
	// AllowMissingAudience accepts a response without aud; a mismatched
	// aud is still refused.
	AllowMissingAudience bool
}

// maxIntrospectionBytes caps an introspection response (safety).
const maxIntrospectionBytes = 64 << 10

func newIntrospectionClient(transport http.RoundTripper) *http.Client {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// errIntrospectionFailed marks a failed introspection call.
var errIntrospectionFailed = errors.New("oauthprovider: introspection failed")

// errIntrospection is a failed introspection call; its status is kept,
// never the secret.
func errIntrospection(status int) error {
	if status == 0 {
		return errIntrospectionFailed
	}
	return fmt.Errorf("%w with status %d", errIntrospectionFailed, status)
}

// introspect posts the token to the issuer and checks the response's
// claims as the local check does, without typ and with exp optional, as
// RFC 7662 allows. active must be JSON true, where another runtime accepts
// any truthy value (safety).
func (v *AccessTokenVerifier) introspect(ctx context.Context, token string) (map[string]any, error) {
	r := v.opts.Remote
	form := url.Values{"client_id": {r.ClientID}, "client_secret": {r.ClientSecret}, "token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.IntrospectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errIntrospection(0)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := v.http.Do(req)
	if err != nil {
		return nil, errIntrospection(0)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, errIntrospection(res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxIntrospectionBytes+1))
	if err != nil || len(raw) > maxIntrospectionBytes {
		return nil, errIntrospection(res.StatusCode)
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil || claims == nil {
		return nil, errIntrospection(res.StatusCode)
	}
	if claims["active"] != true {
		return nil, invalidToken("token inactive")
	}
	aud := claims["aud"]
	skipAudience := (aud == nil || aud == "") && r.AllowMissingAudience
	if err := v.checkClaims(claims, !skipAudience, false); err != nil {
		return nil, err
	}
	return claims, nil
}
