package main

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"

	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

func registrationFixtureOptions() op.Options {
	mode := os.Getenv("CONFORMANCE_CLIENT_REGISTRATION")
	opts := op.Options{}
	if mode == "directory" {
		opts.Registration.Enabled = true
		opts.ImmutableClientIDs = []string{"operator-managed"}
		opts.ClientReference = func(_ context.Context, a op.RegistrationAccess) (string, error) {
			if strings.HasPrefix(a.User.Email, "team-") {
				return "reports-team", nil
			}
			return "", nil
		}
		opts.ClientPrivileges = func(_ context.Context, a op.ClientAccess) (bool, error) {
			return a.Headers.Get("X-Deny-Action") != a.Action && (a.ClientID == "" || a.Headers.Get("X-Deny-Client") != a.ClientID), nil
		}
		return opts
	}
	if mode == "" || mode == "disabled" {
		return opts
	}
	opts.ImmutableClientIDs = []string{"operator-managed"}
	opts.ClientPrivileges = func(_ context.Context, a op.ClientAccess) (bool, error) { return a.Headers.Get("X-Deny") == "", nil }
	opts.PairwiseSecret = strings.Repeat("p", 32)
	opts.Scopes = []string{"openid", "email", "reports", "extra"}
	optional := false
	opts.Registration = op.RegistrationOptions{
		Enabled: true, AllowUnauthenticated: mode == "open", DefaultApplicationType: "infer", SecretPrefix: "fixture_",
		DefaultScopes: []string{"openid", "email"}, AllowedScopes: []string{"reports"}, RequirePKCE: &optional,
		AllowHTTPRedirect: func(u *url.URL) bool { return u.Hostname() == "dev.example.test" },
		MayCreate: func(_ context.Context, a op.RegistrationAccess) (bool, error) {
			return a.Headers.Get("X-Deny") == "", nil
		},
		ClientReference: func(_ context.Context, a op.RegistrationAccess) (string, error) {
			if a.User.Email == "tenant-rotation@registration.test" {
				return "workspace", nil
			}
			return a.Headers.Get("X-Ref"), nil
		},
		ValidateInitialToken: func(_ context.Context, token string, _ http.Header, m op.RegistrationMetadata) (*op.InitialAuthorization, error) {
			switch token {
			case "initial":
				return &op.InitialAuthorization{ReferenceID: "workspace"}, nil
			case "callback-error":
				return nil, errors.New("private fixture message")
			}
			return nil, nil
		},
	}
	if mode == "resources" {
		opts.Registration.DefaultResources = []string{"urn:reports"}
		opts.Registration.AllowedResources = []string{"urn:billing", "urn:disabled", "urn:missing"}
	}
	return opts
}
