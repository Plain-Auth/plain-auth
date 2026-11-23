package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestRefreshTokenFormat(t *testing.T) {
	ctx := t.Context()
	failure := errors.New("callback failed")
	for _, failureAt := range []string{"generate", "hash", "encode"} {
		for _, callbackErr := range []error{nil, failure} {
			step := func(name, value string) (string, error) {
				if name == failureAt {
					return "", callbackErr
				}
				return value, nil
			}
			opts := TokenOptions{
				GenerateRefreshToken: func(context.Context) (string, error) { return step("generate", "raw") },
				HashRefreshToken:     func(context.Context, string) (string, error) { return step("hash", "digest") },
				EncodeRefreshToken:   func(context.Context, string, string) (string, error) { return step("encode", "wire") },
			}
			wire, digest, err := opts.issueRefreshToken(ctx, "session")
			if err == nil || callbackErr != nil && !errors.Is(err, callbackErr) || wire != "" || digest != "" {
				t.Fatalf("failed %s returned credentials or lost the error", failureAt)
			}
		}
	}
	for _, opts := range []TokenOptions{
		{RefreshLifetime: -time.Hour}, {RefreshLifetime: 1500 * time.Millisecond},
		{EncodeRefreshToken: func(context.Context, string, string) (string, error) { return "encoded", nil }},
	} {
		if _, err := New(Options{Tokens: opts}); err == nil {
			t.Fatal("accepted invalid refresh token configuration")
		}
	}
}

func TestAuthorizationCodeUserInfoClaims(t *testing.T) {
	opts := Options{Scopes: []string{"profile"}}
	req := `{"userinfo":{"unknown":null,"name":{},"email":null,"sub":null}}`
	wire, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []json.RawMessage{[]byte(req), wire} {
		got, err := opts.authorizedUserInfoClaims(raw)
		if err != nil || !slices.Equal(got, []string{"name", "sub"}) {
			t.Fatal(got, err)
		}
	}
	for _, raw := range []string{`{}`, `{"UserInfo":{"sub":null}}`} {
		if got, err := opts.authorizedUserInfoClaims([]byte(raw)); err != nil || len(got) != 0 {
			t.Fatal(got, err)
		}
	}
	for _, raw := range []string{"null", "[]", `"invalid"`, `{"userinfo":null}`, `{"userinfo":{"name":"yes"}}`} {
		if got, err := opts.authorizedUserInfoClaims([]byte(raw)); err == nil || len(got) != 0 {
			t.Fatal("accepted malformed claims", raw)
		}
	}
}
