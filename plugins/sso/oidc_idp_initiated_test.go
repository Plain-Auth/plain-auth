package sso

import (
	"context"
	"errors"
	"testing"
)

// A policy that fails or panics never approves a restart.
func TestOIDCDirectoryPolicyFailure(t *testing.T) {
	for _, policy := range []OIDCDirectoryPolicy{
		func(context.Context, OIDCDirectory) (bool, error) { return true, errors.New("directory unavailable") },
		func(context.Context, OIDCDirectory) (bool, error) { panic("directory unavailable") },
	} {
		if allowed, err := policy.authorize(t.Context(), OIDCDirectory{ProviderID: "acme"}); allowed || err == nil {
			t.Fatal("a failing OIDC directory policy authorized a restart", allowed, err)
		}
	}
}
