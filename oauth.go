package plainauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"time"

	"golang.org/x/oauth2"
)

// OAuthProfile identifies a person by their stable provider subject.
type OAuthProfile struct {
	// AdditionalFields is an explicit mapping from the authenticated provider
	// profile to configured user attributes for first-time account creation.
	AdditionalFields map[string]any `json:"-"`

	// Data is the authenticated provider profile returned by the account-info endpoint.
	Data                 any `json:"-"`
	Subject, Email, Name string
	Image                *string
	EmailVerified        bool
}

// OAuthProvider configures an authorization-code provider. Resolve must obtain
// identity from an authenticated provider endpoint or a verified ID token.
// For OpenID Connect it must verify the supplied nonce.
type OAuthProvider struct {
	Config oauth2.Config
	// EndSessionEndpoint is the provider's registered OIDC logout endpoint.
	EndSessionEndpoint string
	// PostLogoutRedirectURI is the default application return URI after provider logout.
	PostLogoutRedirectURI string
	DisableProviderLogout bool
	// CustomizeAuthorization adapts fixed provider-specific parameter names.
	CustomizeAuthorization func(*url.URL)
	// ExchangeCode handles providers with a nonstandard token endpoint protocol.
	ExchangeCode  func(context.Context, oauth2.Config, string, string, url.Values) (*oauth2.Token, error)
	Resolve       func(context.Context, *oauth2.Token, string) (OAuthProfile, error)
	VerifyIDToken func(ctx context.Context, raw, nonce string) (OAuthProfile, time.Time, error)
	// Refresh overrides the standard OAuth 2.0 refresh request.
	Refresh                func(context.Context, oauth2.Config, string) (*oauth2.Token, error)
	DisableRefresh         bool
	HTTPClient             *http.Client
	AllowVerifiedEmailLink bool
	// DisableSignUp prevents this provider from creating new accounts.
	DisableSignUp bool
	// DisableImplicitSignUp requires requestSignUp for new browser and direct ID-token accounts.
	DisableImplicitSignUp bool
	// GoogleHostedDomain restricts the verified Google Workspace hd claim. Use * for any Workspace.
	GoogleHostedDomain  string
	AuthorizationParams url.Values
	DisablePKCE         bool
	OmitNonce           bool
	FormPostName        bool
}

// OAuthFlow is the temporary state of a browser authorization. Binding ties a
// request to the initiating browser, provider and existing session.
type OAuthFlow struct {
	// ProxyOrigin is the preview that owns the browser state and final session.
	ProxyOrigin                                       string         `json:",omitempty"`
	PopupAdditionalData                               map[string]any `json:",omitempty"`
	ProviderReference                                 string         `json:",omitempty"`
	RedirectURI                                       string         `json:",omitempty"`
	RequestSignUp                                     bool           `json:",omitempty"`
	AnonymousSessionProof                             string         `json:",omitempty"`
	State, Binding, Provider, Verifier, Nonce         string
	CallbackURL, ErrorCallbackURL, NewUserCallbackURL string
	LinkUserID                                        string
	ExpiresAt                                         time.Time
}

// OAuthTokens are the provider-issued account credentials kept by the adapter.
type OAuthTokens struct {
	AccessToken, RefreshToken, IDToken, Scope string
	ExpiresAt, RefreshExpiresAt               time.Time
}

// OAuthLoginOptions binds an explicit link to a live session or a direct
// ID-token grant to the verified token's expiry.
type OAuthLoginOptions struct {
	DisableSignUp bool
	// DisableImplicitLinking also takes precedence over directory-based trust in custom stores.
	DisableImplicitLinking       bool
	OneTapNonce                  string
	OneTapExpires                time.Time
	AllowVerifiedEmailLink       bool
	LinkUserID, LinkSessionToken string
	IDTokenValidUntil            time.Time
	// IDTokenHash binds single-use grants independently of randomized storage encryption.
	IDTokenHash [32]byte
}

// OAuthStore supports shared, single-use flow state and atomic identity login.
// CompleteOAuth returns the actual account owner and whether it created a user.
type OAuthStore interface {
	SaveOAuthFlow(context.Context, OAuthFlow, time.Time) error
	ConsumeOAuthFlow(ctx context.Context, state, binding string, now time.Time) (OAuthFlow, error)
	CompleteOAuth(ctx context.Context, provider, subject string, tokens OAuthTokens, candidate User, session StoredSession, options OAuthLoginOptions) (User, bool, error)
}

// OAuthRegistrationFields resolves the configured scalar values for a new
// account. It has no side effects and can be called again when retrying a write.
type OAuthRegistrationFields func() (UserFieldValues, error)

type oauthRegistrationFieldError struct{ error }

func (e oauthRegistrationFieldError) Unwrap() error { return e.error }

// OAuthRegistrationStore resolves fields only for new users after selecting the
// exact identity. It commits them with the user, account link and initial session.
type OAuthRegistrationStore interface {
	CompleteOAuthRegistration(ctx context.Context, provider, subject string, tokens OAuthTokens, candidate User, session StoredSession, options OAuthLoginOptions, fields OAuthRegistrationFields) (User, bool, error)
}

// OAuthLinkRefreshStore updates an already-owned provider identity after verifying
// the live owner session and the provider subject in the same transaction.
// Implement it to permit redundant mobile link requests when linking is disabled.
type OAuthLinkRefreshStore interface {
	RefreshOwnedOAuthLink(context.Context, string, string, OAuthTokens, User, StoredSession, OAuthLoginOptions) (User, bool, error)
}

var ErrOAuthLinkingDisabled = errors.New("account linking is disabled")
var ErrOAuthAccountAlreadyLinked = errors.New("social identity belongs to another account")

var ErrOAuthSignupDisabled = errors.New("OAuth account creation disabled")
var ErrOAuthLinkRequired = errors.New("account must be linked by its existing owner")
var ErrIDTokenUsed = errors.New("ID token has already been used")
var providerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func prepareOAuthProviders(in map[string]OAuthProvider, store Store, userFieldsOnSignup bool) (map[string]OAuthProvider, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if _, ok := store.(OAuthStore); !ok {
		return nil, errors.New("social providers require OAuthStore")
	}
	out := make(map[string]OAuthProvider, len(in))
	for id, p := range in {
		if userFieldsOnSignup && !p.DisableSignUp {
			if _, ok := store.(OAuthRegistrationStore); !ok {
				return nil, errors.New("auth: social signup with configured user fields requires an OAuthRegistrationStore")
			}
		}
		if !providerName.MatchString(id) || id == "credential" || p.Config.ClientID == "" || p.Resolve == nil {
			return nil, fmt.Errorf("incomplete OAuth provider %q", id)
		}
		endpoints := []string{p.Config.Endpoint.AuthURL, p.Config.Endpoint.TokenURL}
		if p.EndSessionEndpoint != "" {
			endpoints = append(endpoints, p.EndSessionEndpoint)
		}
		for _, endpoint := range endpoints {
			u, err := url.Parse(endpoint)
			if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
				return nil, fmt.Errorf("invalid OAuth endpoint for %q", id)
			}
			ip := net.ParseIP(u.Hostname())
			if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || ip.IsLoopback())) {
				return nil, fmt.Errorf("OAuth endpoint for %q requires HTTPS", id)
			}
		}
		p.Config.Scopes = slices.Clone(p.Config.Scopes)
		if p.AuthorizationParams != nil {
			params := make(url.Values, len(p.AuthorizationParams))
			for k, v := range p.AuthorizationParams {
				params[k] = slices.Clone(v)
			}
			p.AuthorizationParams = params
		}
		if p.HTTPClient == nil {
			p.HTTPClient = &http.Client{Timeout: 15 * time.Second}
		}
		// Token and profile requests can carry credentials in headers, bodies or
		// query strings. Providers must answer at their configured endpoint.
		client := *p.HTTPClient
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		p.HTTPClient = &client
		out[id] = p
	}
	return out, nil
}

func (a *Auth) oauthCookie(name, value string, maxAge int) *http.Cookie {
	return a.browserCookie(name, value, maxAge)
}
