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

	"github.com/Plain-Org/plain-auth/internal/httporigin"
	"golang.org/x/oauth2"
)

// OAuthProfile identifies a person by their stable provider subject.
type OAuthProfile struct {
	// AdditionalFields is an explicit mapping from the authenticated provider
	// profile to writable user attributes at registration and optional sign-in updates.
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
	// GetAccountFields maps a verified social grant to declared writable account attributes.
	GetAccountFields func(context.Context, OAuthAccountFieldInput) (map[string]any, error)
	// Config holds the client credentials, endpoints and scopes. RedirectURL
	// defaults to the callback route, BaseURL+BasePath+"/callback/"+id. Set it
	// to an absolute URL that forwards to that route to use another address.
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
	// DisableIDTokenSignIn closes the direct token grant on social sign-in and
	// linking. Browser code exchanges and the One Tap plugin verify independently.
	DisableIDTokenSignIn bool
	// Refresh overrides the standard OAuth 2.0 refresh request.
	Refresh func(context.Context, oauth2.Config, string) (*oauth2.Token, error)
	// Name is a display label; it defaults to the SocialProviders key.
	Name string
	// AccessType is sent as access_type on the authorization URL, such as
	// "offline"; AuthorizationParams and a call's additionalParams override
	// it.
	AccessType string
	// DefaultAccessTokenLifetime is the access token lifetime assumed when a
	// token response has no expires_in; zero assumes none.
	DefaultAccessTokenLifetime time.Duration
	// TokenParams are extra form fields for the standard code exchange, such
	// as audience or resource, with one value each. New refuses the grant
	// and client authentication fields, and ExchangeCode, which replaces
	// that request.
	TokenParams url.Values
	// TokenHeaders are added to the code exchange and refresh requests sent
	// to the token endpoint, and never replace a header the request already
	// has. New refuses them together with ExchangeCode or Refresh.
	TokenHeaders http.Header
	// RefreshParams returns extra form fields for one refresh-token request;
	// nil adds none. It runs before the account is locked. Header values come
	// from the caller, so check anything derived from them against the
	// owner's entitlements. New refuses it together with Refresh.
	RefreshParams func(context.Context, OAuthRefreshRequest) (url.Values, error)
	// TokenEndpointAuth chooses how the code exchange and refresh
	// authenticate the client. It cannot be combined with ExchangeCode or
	// Refresh, which replace these requests.
	TokenEndpointAuth      TokenEndpointAuth
	DisableRefresh         bool
	HTTPClient             *http.Client
	AllowVerifiedEmailLink bool
	// DisableSignUp prevents this provider from creating new accounts.
	DisableSignUp bool
	// DisableImplicitSignUp requires requestSignUp for new browser and direct ID-token accounts.
	DisableImplicitSignUp bool
	// OverrideUserInfoOnSignIn updates the local profile from this provider on
	// successful sign-in. Explicit account linking preserves the owner's profile.
	OverrideUserInfoOnSignIn bool
	// RequireEmailVerification withholds a session until the local mailbox is verified.
	RequireEmailVerification bool
	// GoogleHostedDomain restricts the verified Google Workspace hd claim. Use * for any Workspace.
	GoogleHostedDomain  string
	AuthorizationParams url.Values
	DisablePKCE         bool
	OmitNonce           bool
	FormPostName        bool
}

// OAuthRefreshRequest describes the request that triggered a provider token
// refresh.
type OAuthRefreshRequest struct {
	// Header is a copy of the triggering request's headers, or nil for a
	// trusted server call.
	Header http.Header
	// UserID owns the account and AccountID is its local record ID.
	UserID, AccountID string
}

// tokenFields are set by the code exchange, the refresh or the client
// authentication, so TokenParams and RefreshParams cannot name them.
var tokenFields = []string{"grant_type", "code", "redirect_uri", "code_verifier", "refresh_token", "client_id", "client_secret", "client_assertion", "client_assertion_type"}

// OAuthFlow is the temporary state of a browser authorization. Binding ties a
// request to the initiating browser, provider and existing session.
type OAuthFlow struct {
	// IssuerLoginQuery is the host's verified login request, retained in the
	// flow store, or sealed in the state cookie, while the browser visits the
	// identity provider.
	IssuerLoginQuery string `json:",omitempty"`
	// ProxyOrigin is the preview that owns the browser state and final session.
	ProxyOrigin string `json:",omitempty"`
	// AdditionalData is the additionalData object the browser sent when it
	// started the flow, without the reserved names.
	AdditionalData map[string]any `json:",omitempty"`
	// ServerContext holds the values hooks added with
	// HookContext.AddOAuthServerContext when the flow started. A custom
	// OAuthFlowStore must keep it.
	ServerContext                                     map[string]any `json:",omitempty"`
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
	// AccountFields holds validated provider values keyed by logical account field name.
	AccountFields *MappedAccountFields
	DisableSignUp bool
	// RequireEmailVerification commits an unverified identity without issuing a session.
	RequireEmailVerification bool
	// DisableAccountUpdateOnSignIn skips the existing account row update during
	// login. Adapters still claim single-use grants and apply the session policy.
	DisableAccountUpdateOnSignIn bool
	// DisableImplicitLinking also takes precedence over directory-based trust in custom stores.
	DisableImplicitLinking bool
	OneTapNonce            string
	OneTapExpires          time.Time
	AllowVerifiedEmailLink bool
	// TrustedProvider accepts a provider email that is not verified for a
	// link. An implicit link still needs a verified local email.
	TrustedProvider bool
	// AllowDifferentEmails lets an explicit link attach to LinkUserID
	// whatever the provider email.
	AllowDifferentEmails bool
	// UpdateUserInfoOnLink writes the candidate's non-empty Name, non-nil
	// Image and the LinkUserFields values to the owner when this call links
	// the identity to an existing user or refreshes it through an explicit
	// link. The email and its verification never change.
	UpdateUserInfoOnLink bool
	// LinkUserFields prepares the user fields to copy. Call it only when the
	// copy applies. It reports false when the profile fails validation, and
	// then nothing is copied.
	LinkUserFields               func() (UserFieldValues, bool)
	LinkUserID, LinkSessionToken string
	IDTokenValidUntil            time.Time
	// IDTokenHash binds single-use grants independently of randomized storage encryption.
	IDTokenHash [32]byte
}

// OAuthFlowStore keeps shared, single-use browser flow state. It is needed
// unless OAuthStateStrategy is OAuthStateCookie.
type OAuthFlowStore interface {
	SaveOAuthFlow(context.Context, OAuthFlow, time.Time) error
	ConsumeOAuthFlow(ctx context.Context, state, binding string, now time.Time) (OAuthFlow, error)
}

// OAuthFlowFinder reads a browser OAuth flow without spending it, for
// verification delete hooks. A flow that is unknown, expired or bound to
// another browser is ErrNotFound.
type OAuthFlowFinder interface {
	FindOAuthFlow(ctx context.Context, state, binding string, now time.Time) (OAuthFlow, error)
}

// OAuthIdentityStore completes a provider sign-in atomically. CompleteOAuth
// returns the actual account owner and whether it created a user.
type OAuthIdentityStore interface {
	CompleteOAuth(ctx context.Context, provider, subject string, tokens OAuthTokens, candidate User, session StoredSession, options OAuthLoginOptions) (User, bool, error)
}

// OAuthStore supports shared, single-use flow state and atomic identity login.
type OAuthStore interface {
	OAuthFlowStore
	OAuthIdentityStore
}

// OAuthRegistrationFields resolves configured columns for a new account.
type OAuthRegistrationFields func() (UserFieldValues, error)

// OAuthProfileFields supplies the creation defaults or the mapped update for
// the selected owner. Call only the matching resolver inside the transaction.
type OAuthProfileFields struct {
	Create OAuthRegistrationFields
	Update func() (UserFieldValues, error)
}

type oauthProfileFieldError struct{ error }

func (e oauthProfileFieldError) Unwrap() error { return e.error }

// OAuthRegistrationStore resolves fields only for new users after selecting the
// exact identity. It commits them with the user, account link and initial session.
type OAuthRegistrationStore interface {
	CompleteOAuthRegistration(ctx context.Context, provider, subject string, tokens OAuthTokens, candidate User, session StoredSession, options OAuthLoginOptions, fields OAuthRegistrationFields) (User, bool, error)
}

// OAuthProfileSyncStore applies an authenticated provider profile to the owner
// selected by the ordinary sign-in and linking rules. Profile, credentials,
// token consumption and session creation must commit together.
type OAuthProfileSyncStore interface {
	CompleteOAuthProfile(ctx context.Context, provider, subject string, tokens OAuthTokens, candidate User, session StoredSession, options OAuthLoginOptions, fields OAuthProfileFields) (User, bool, error)
}

// OAuthVerifiedEmailStore checks the locked owner's email before inserting a
// session. For an unverified owner it commits the user, provider credential and
// single-use proof, then returns the owner, creation flag and ErrOAuthEmailUnverified.
// A nil fields.Update preserves the existing profile on returning sign-ins.
type OAuthVerifiedEmailStore interface {
	CompleteOAuthVerifiedEmail(ctx context.Context, provider, subject string, tokens OAuthTokens, candidate User, session StoredSession, options OAuthLoginOptions, fields OAuthProfileFields) (User, bool, error)
}

// OAuthLinkRefreshStore updates an already-owned provider identity after verifying
// the live owner session and the provider subject in the same transaction.
// Implement it to permit redundant mobile link requests when linking is disabled.
type OAuthLinkRefreshStore interface {
	RefreshOwnedOAuthLink(context.Context, string, string, OAuthTokens, User, StoredSession, OAuthLoginOptions) (User, bool, error)
}

var ErrOAuthLinkingDisabled = errors.New("account linking is disabled")
var ErrOAuthAccountAlreadyLinked = errors.New("social identity belongs to another account")
var ErrOAuthProfileConflict = errors.New("provider profile conflicts with an existing profile")
var ErrOAuthEmailUnverified = errors.New("OAuth account requires email verification")

var ErrOAuthSignupDisabled = errors.New("OAuth account creation disabled")
var ErrOAuthLinkRequired = errors.New("account must be linked by its existing owner")

// ErrOAuthLinkNotAllowed refuses an explicit link from a provider that is not
// trusted and did not verify the email.
var ErrOAuthLinkNotAllowed = errors.New("provider email is not verified and the provider is not trusted")

// ErrOAuthLinkEmailMismatch refuses an explicit link whose provider email
// differs from the account's email.
var ErrOAuthLinkEmailMismatch = errors.New("provider email does not match the account email")
var ErrIDTokenUsed = errors.New("ID token has already been used")
var providerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func prepareOAuthProviders(in map[string]OAuthProvider, store Store, userFieldsOnSignup bool, strategy OAuthStateStrategy) (map[string]OAuthProvider, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if _, ok := store.(OAuthIdentityStore); !ok {
		return nil, errors.New("social providers require an OAuthIdentityStore")
	}
	if _, ok := store.(OAuthFlowStore); !ok && strategy != OAuthStateCookie {
		return nil, errors.New("social providers require an OAuthFlowStore, or OAuthStateStrategy OAuthStateCookie")
	}
	out := make(map[string]OAuthProvider, len(in))
	for id, p := range in {
		if p.RequireEmailVerification {
			if _, ok := store.(OAuthVerifiedEmailStore); !ok {
				return nil, fmt.Errorf("auth: verified email for provider %q requires an OAuthVerifiedEmailStore", id)
			}
		} else if p.OverrideUserInfoOnSignIn {
			if _, ok := store.(OAuthProfileSyncStore); !ok {
				return nil, fmt.Errorf("auth: profile updates from provider %q require an OAuthProfileSyncStore", id)
			}
		} else if userFieldsOnSignup && !p.DisableSignUp {
			if _, ok := store.(OAuthRegistrationStore); !ok {
				return nil, errors.New("auth: social signup with configured user fields requires an OAuthRegistrationStore")
			}
		}
		if !providerName.MatchString(id) || id == "credential" || p.Config.ClientID == "" || p.Resolve == nil {
			return nil, fmt.Errorf("incomplete OAuth provider %q", id)
		}
		if err := prepareTokenEndpointAuth(id, &p); err != nil {
			return nil, err
		}
		if p.Name == "" {
			p.Name = id
		}
		if p.DefaultAccessTokenLifetime < 0 {
			return nil, fmt.Errorf("auth: OAuth provider %q: DefaultAccessTokenLifetime is negative", id)
		}
		if err := prepareTokenRequests(id, &p); err != nil {
			return nil, err
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
		// A custom redirect URI must reach this provider's callback route.
		if p.Config.RedirectURL != "" {
			u, err := url.Parse(p.Config.RedirectURL)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
				return nil, fmt.Errorf("invalid redirect URL for OAuth provider %q", id)
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

// prepareTokenRequests checks and copies the extra token request fields and
// headers. Each one must take effect, so a request replaced by ExchangeCode
// or Refresh refuses them, and the protocol fields stay the library's.
func prepareTokenRequests(id string, p *OAuthProvider) error {
	refuse := func(why string) error { return fmt.Errorf("auth: OAuth provider %q: %s", id, why) }
	if p.TokenParams != nil && p.ExchangeCode != nil {
		return refuse("TokenParams cannot be combined with ExchangeCode")
	}
	if p.TokenHeaders != nil && (p.ExchangeCode != nil || p.Refresh != nil) {
		return refuse("TokenHeaders cannot be combined with ExchangeCode or Refresh")
	}
	if p.RefreshParams != nil && p.Refresh != nil {
		return refuse("RefreshParams cannot be combined with Refresh")
	}
	params := make(url.Values, len(p.TokenParams))
	for k, v := range p.TokenParams {
		if slices.Contains(tokenFields, k) {
			return refuse("TokenParams cannot set " + k)
		}
		if len(v) != 1 {
			return refuse("TokenParams " + k + " needs exactly one value")
		}
		params[k] = slices.Clone(v)
	}
	if p.TokenParams != nil {
		p.TokenParams = params
	}
	headers, err := httporigin.Headers(p.TokenHeaders)
	if err != nil {
		return refuse("TokenHeaders: " + err.Error())
	}
	p.TokenHeaders = headers
	return nil
}

// accessTokenExpiry returns the token's expiry, or now plus the provider's
// default lifetime when the response gave none.
func (p OAuthProvider) accessTokenExpiry(t *oauth2.Token, now time.Time) time.Time {
	if t.Expiry.IsZero() && p.DefaultAccessTokenLifetime > 0 {
		return now.Add(p.DefaultAccessTokenLifetime)
	}
	return t.Expiry
}
