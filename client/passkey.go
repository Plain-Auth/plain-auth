package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/passkey"
	"github.com/go-webauthn/webauthn/protocol"
)

type PasskeyRegistrationRequest struct {
	Name, AuthenticatorAttachment string
	Context                       *string
}

// BeginPasskeyRegistration returns public-key creation options for a browser or native authenticator.
func (c *Client) BeginPasskeyRegistration(ctx context.Context, in PasskeyRegistrationRequest) (*protocol.PublicKeyCredentialCreationOptions, error) {
	q := url.Values{}
	if in.Name != "" {
		q.Set("name", in.Name)
	}
	if in.AuthenticatorAttachment != "" {
		q.Set("authenticatorAttachment", in.AuthenticatorAttachment)
	}
	if in.Context != nil {
		q.Set("context", *in.Context)
	}
	route := "/passkey/generate-register-options"
	if len(q) > 0 {
		route += "?" + q.Encode()
	}
	var out protocol.PublicKeyCredentialCreationOptions
	if err := c.Do(ctx, http.MethodGet, route, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
func (c *Client) FinishPasskeyRegistration(ctx context.Context, response json.RawMessage, name string, createSession bool) (*passkey.RegistrationResult, error) {
	var out passkey.RegistrationResult
	if err := c.Do(ctx, http.MethodPost, "/passkey/verify-registration", map[string]any{"response": response, "name": name, "createSession": createSession}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) BeginPasskeyLogin(ctx context.Context) (*protocol.PublicKeyCredentialRequestOptions, error) {
	var out protocol.PublicKeyCredentialRequestOptions
	if err := c.Do(ctx, http.MethodGet, "/passkey/generate-authenticate-options", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
func (c *Client) FinishPasskeyLogin(ctx context.Context, response json.RawMessage) (*plainauth.SessionResult, error) {
	var out plainauth.SessionResult
	if err := c.Do(ctx, http.MethodPost, "/passkey/verify-authentication", map[string]any{"response": response}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
