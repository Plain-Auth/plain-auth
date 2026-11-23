package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/plugins/organization"
)

// Expose the host's server-only method to the local comparison process.
func clientScopeFixture(a *auth.Auth, store op.ClientCredentialsScopeStore, fallback http.Handler) http.Handler {
	manager, err := op.NewClientManager(a, store, registrationFixtureOptions())
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /__fixture/client-scopes", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ClientID string   `json:"client_id"`
			Scopes   []string `json:"client_credentials_scopes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		granted, err := manager.SetClientCredentialsScopes(r.Context(), r.Header, body.ClientID, body.Scopes)
		if err != nil {
			var problem *auth.OAuthError
			var api *auth.APIError
			switch {
			case errors.As(err, &problem):
				w.WriteHeader(problem.Status)
				json.NewEncoder(w).Encode(problem)
			case errors.As(err, &api):
				w.WriteHeader(api.Status)
				if api.Code != "" {
					json.NewEncoder(w).Encode(api)
				}
			default:
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string][]string{"client_credentials_scopes": granted})
	})
	mux.Handle("/", fallback)
	return mux
}

func registrationFixtureOptions() op.Options {
	mode := os.Getenv("CONFORMANCE_CLIENT_REGISTRATION")
	opts := op.Options{Authorization: op.BrowserAuthorizationOptions{LoginPage: "/login", SignupPage: "/signup", ConsentPage: "/consent"}}
	if os.Getenv("CONFORMANCE_ISSUER_METADATA") == "1" {
		opts.Metadata.Scopes = []string{"reports"}
		opts.Metadata.TokenAuthMethods = []string{"private_key_jwt", "client_secret_post"}
		opts.DPoP.SigningAlgorithms = []string{"ES256"}
	}
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
	if mode == "protected" {
		opts.Authorization.CheckSignup = func(_ context.Context, a op.RegistrationAccess, scopes []string) (*op.SignupStep, error) {
			if a.User.Email != "onboarding@issuer.test" || a.User.ID != a.Session.UserID || a.Headers.Get("Cookie") == "" || !slices.Contains(scopes, "reports") {
				return nil, nil
			}
			switch a.User.Name {
			case "Registration":
				return &op.SignupStep{}, nil
			case "Profile":
				return &op.SignupStep{Page: "/setup"}, nil
			}
			return nil, nil
		}
		opts.Authorization.SelectAccount = op.AccountSelectionOptions{
			Page: "/choose-account",
			ShouldRedirect: func(_ context.Context, a op.RegistrationAccess, scopes []string) (bool, error) {
				return a.Headers.Get("X-Choose-Account") == "yes" && a.Session.UserID == a.User.ID && len(scopes) == 1 && scopes[0] == "reports", nil
			},
		}
		opts.Assertions.AllowKeyRotation = true
		opts.Tokens = op.TokenOptions{MachineLifetime: 10 * time.Minute, ScopeLifetimes: map[string]time.Duration{"reports": 90 * time.Second}, OpaquePrefix: "access_"}
		opts.Tokens.OpaqueResourceTokens = os.Getenv("CONFORMANCE_OPAQUE_RESOURCE_TOKENS") == "1"
	}
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

func configurePostLoginFixture(opts *op.Options, store organization.Store) {
	opts.Authorization.PostLogin = &op.PostLoginOptions{
		Page: "/select-organization",
		ShouldRedirect: func(ctx context.Context, a op.PostLoginContext) (bool, error) {
			orgs, err := store.OrganizationsForUser(ctx, a.User.ID)
			if err != nil {
				return false, err
			}
			valid := slices.ContainsFunc(orgs, func(o organization.Organization) bool {
				return a.Session.ActiveOrganizationID != nil && *a.Session.ActiveOrganizationID == o.ID
			})
			return !valid || (len(orgs) > 1 && !a.IsContinuation), nil
		},
	}
	opts.Authorization.ConsentReference = func(_ context.Context, a op.RegistrationAccess, _ []string) (string, error) {
		if a.Session.ActiveOrganizationID == nil {
			return "", errors.New("select an organization")
		}
		return *a.Session.ActiveOrganizationID, nil
	}
}
