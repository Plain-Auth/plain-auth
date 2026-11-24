package plainauth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// DynamicBaseURLOptions lists the hosts one instance answers for.
type DynamicBaseURLOptions struct {
	// AllowedHosts lists hosts such as "app.example.com", "*.example.com" or
	// "localhost:3000". A request for another host uses Fallback, or fails
	// with a 500 without one.
	AllowedHosts []string
	// Protocol is "http" or "https" to fix the scheme of every link. The
	// default ("" or "auto") takes a trusted X-Forwarded-Proto, then the
	// connection's TLS, and otherwise uses http for loopback hosts and https
	// for others. Allowed hosts are trusted origins over https, and over
	// http too for loopback hosts, with "auto", or with "http" alone.
	Protocol string
	// Fallback is the public URL for requests to unlisted hosts and for
	// values without a request, such as issuers and direct Go calls.
	Fallback string
	// TrustedProxyHeaders reads X-Forwarded-Host and X-Forwarded-Proto from
	// the peers in ClientIP.TrustedProxies.
	TrustedProxyHeaders bool
}

// Options configures one isolated authentication instance.
type Options struct {
	UserAdditionalFields    map[string]UserField
	SessionAdditionalFields map[string]SessionField
	AccountAdditionalFields map[string]AccountField
	AccountFieldRules       map[string]AccountFieldRule

	// AppName names the application where users see it, such as the issuer
	// in authenticator apps. It defaults to "Auth".
	AppName string
	// Logger receives diagnostics for this instance. A nil logger uses slog.Default().
	Logger *slog.Logger
	// SkipTrailingSlashes serves a path with trailing slashes, such as
	// /sign-in/email/, as the path without them.
	SkipTrailingSlashes bool
	// DisableCSRFCheck turns off the Origin, Referer and Fetch Metadata checks
	// on requests that change state. This exposes cookie-authenticated
	// endpoints to cross-site request forgery.
	DisableCSRFCheck bool
	// DisableOriginCheck accepts any callbackURL, redirectTo and other redirect
	// target instead of only trusted origins and relative paths, which allows
	// open redirects. Request origins are still checked unless DisableCSRFCheck
	// is also set.
	DisableOriginCheck bool
	// Cookies overrides the name and attributes of individual cookies, by
	// their base name such as "session_token", "session_data" or
	// "dont_remember".
	Cookies map[string]CookieOptions
	// DefaultCookieAttributes applies to every cookie before the per-cookie
	// overrides.
	DefaultCookieAttributes CookieAttributes
	// Hooks run before and after each mounted HTTP endpoint.
	Hooks EndpointHooks
	// DatabaseHooks run before and after user and session writes, after the
	// plugins' database hooks.
	DatabaseHooks DatabaseHooks
	// OnAPIError observes an HTTP endpoint error before its response is written.
	// It runs synchronously and may use the request's context for cancellation.
	OnAPIError func(ErrorContext, error) error
	// SessionCookieCache enables authenticated snapshots for public browser session reads.
	SessionCookieCache *SessionCookieCacheOptions
	// Store persists identities and sessions. Configure one store per auth instance.
	Store Store
	// BaseURL is the public HTTP(S) address. BasePath defaults to /api/auth.
	BaseURL  string
	BasePath string
	// DynamicBaseURL serves several public hosts from one instance in place
	// of a fixed BaseURL. Each request's host chooses the origin of its links
	// and callbacks.
	DynamicBaseURL *DynamicBaseURLOptions
	// DisabledPaths hides exact HTTP paths relative to this instance’s mount.
	DisabledPaths []string
	// TrustedOrigins allows exact HTTP(S) origins, hostname or port wildcard
	// patterns, and custom-scheme URLs such as myapp:// or
	// chrome-extension://ID, for browser requests and callbacks.
	TrustedOrigins []string
	// TrustedOriginsForRequest adds origins for one HTTP request, such as
	// tenant domains loaded from a database, to TrustedOrigins,
	// AUTH_TRUSTED_ORIGINS and the BaseURL origin. It takes the same patterns
	// as TrustedOrigins and receives a copy of the request without its body,
	// once per request to the handler. A returned *APIError with a 4xx or
	// 5xx status is sent as the response; another error or an invalid
	// pattern fails the request with a 500. Calls made outside the handler, BindOneTapNonce, the public
	// CallbackURL and server-side discovery use the static origins only.
	TrustedOriginsForRequest func(*http.Request) ([]string, error)
	CookiePrefix             string
	// CrossSubDomainCookies selects the Domain attribute for shared browser cookies.
	// A nil value keeps cookies host-only. An empty Domain uses the BaseURL hostname.
	CrossSubDomainCookies *CrossSubDomainCookiesOptions
	// UseSecureCookies overrides the HTTPS-based default for session cookies.
	UseSecureCookies *bool
	ErrorRedirectURL string
	// Secret signs credentials. Secrets configures ordered keys for rotation.
	Secret  string
	Secrets []VersionedSecret

	// PasswordHash derives a stored credential from a plaintext password.
	// PasswordVerify checks a stored credential against a plaintext password.
	// A nil callback uses the built-in scrypt implementation for that operation.
	PasswordHash   func(ctx context.Context, password string) (string, error)
	PasswordVerify func(ctx context.Context, encoded, password string) (bool, error)

	// OnExistingUserSignUp receives the persisted mailbox owner on a protected duplicate
	// sign-up. An HTTP call supplies request metadata; direct calls supply nil.
	OnExistingUserSignUp func(context.Context, User, *http.Request) error
	// ValidateUserInfo decides which identities the instance admits. It runs
	// before a user is created, before a provider identity is linked to an
	// existing user, and before an existing user signs in again through a
	// provider, outside any store transaction and before the user create
	// database hooks. Return nil to admit, or an *APIError to refuse with its
	// Code and Message. Every refusal answers 403; browser flows redirect to
	// their error URL with error and error_description. Any other error, an
	// APIError without a Code, or a panic refuses with validation_failed.
	ValidateUserInfo func(context.Context, UserInfoValidation) error
	// CustomSyntheticUser shapes the user an HTTP sign-up returns for an email
	// that already exists, when RequireEmailVerification or DisableAutoSignIn
	// hides that the email is taken. The returned values replace the
	// generated ones for the fields a real sign-up returns, in that field's
	// format; other keys are dropped and a value that does not fit keeps the
	// generated one. Built-in plugin fields are already filled in.
	CustomSyntheticUser func(SyntheticUser) map[string]any

	EmailAndPassword         bool
	MinPasswordLength        int
	MaxPasswordLength        int
	DisableSignUp            bool
	DisableAutoSignIn        bool
	RequireEmailVerification bool
	// AutoSignInAfterVerification issues or reuses a browser session on first email-link verification.
	AutoSignInAfterVerification   bool
	SendVerificationOnSignUp      *bool
	SendVerificationOnSignIn      bool
	SendVerificationEmail         MailSender
	EmailVerificationTokenTTL     time.Duration
	SendResetPassword             MailSender
	PasswordResetTokenTTL         time.Duration
	RevokeSessionsOnPasswordReset bool
	// BeforeEmailVerification and AfterEmailVerification run outside store locks.
	BeforeEmailVerification, AfterEmailVerification EmailVerificationHook

	// OnPasswordReset runs after a recovery proof is consumed, the password is
	// replaced, and any requested session revocation commits. Mounted endpoints
	// pass the HTTP request. Direct Go calls pass nil.
	OnPasswordReset func(context.Context, User, *http.Request) error

	// Account lifecycle operations with destructive or identity-changing effects are opt-in.
	DeleteUserEnabled bool
	// BeforeDeleteUser runs before a user is deleted, with a body-free copy of
	// the request or nil for a Go call. An error cancels the deletion and is
	// returned to the caller.
	BeforeDeleteUser func(context.Context, User, *http.Request) error
	// AfterDeleteUser runs once a user is deleted. Its error is returned to
	// the caller; the user stays deleted.
	AfterDeleteUser                func(context.Context, User, *http.Request) error
	SendDeleteAccountVerification  MailSender
	DeleteTokenTTL                 time.Duration
	ChangeEmailEnabled             bool
	UpdateEmailWithoutVerification bool
	SendChangeEmailConfirmation    MailSender
	// DisableAccountLinking prevents attaching another provider to an existing account.
	DisableAccountLinking bool
	// DisableImplicitAccountLinking requires an authenticated owner to link an additional provider.
	DisableImplicitAccountLinking bool
	// TrustedProviders lists social provider IDs whose identities may link
	// without a verified email from the provider, such as "google", which also
	// covers One Tap. A sign-in can then attach to an existing user with the
	// same verified email, and a signed-in user can link the identity. Trust
	// never marks an email as verified, and it raises the risk of account
	// takeover: list only providers that own their users' email addresses.
	TrustedProviders []string
	// TrustedProvidersForRequest chooses the trusted providers per request,
	// for example per tenant, instead of TrustedProviders. It receives a copy
	// of the request without its body whenever a social sign-in or link
	// reaches the store and when an SSO provider is registered. An error
	// fails that request.
	TrustedProvidersForRequest func(*http.Request) ([]string, error)
	// AllowDifferentEmails lets a signed-in user link a provider identity
	// whose email differs from their own. The user's email does not change,
	// and whoever controls that provider account can then sign in as them.
	AllowDifferentEmails bool
	// UpdateUserInfoOnLink copies the provider's name, image and writable
	// UserAdditionalFields onto the user whenever an identity is linked,
	// through /link-social or by a sign-in that links by email. An empty name
	// or missing image keeps the stored value, and the email and its
	// verification never change.
	UpdateUserInfoOnLink bool
	// DisableAccountUpdateOnSignIn preserves credentials on existing provider
	// accounts during sign-in. New links and explicit reauthorization still store grants.
	DisableAccountUpdateOnSignIn bool
	AllowUnlinkingAll            bool

	SessionTTL time.Duration
	// FreshAge is how recent a session must be for sensitive account changes,
	// such as deleting the user or unlinking an account. It defaults to one
	// day; a negative value turns the check off.
	FreshAge time.Duration
	// SessionUpdateAge controls sliding expiration. A pointer to zero refreshes on every eligible read.
	SessionUpdateAge      *time.Duration
	DisableSessionRefresh bool
	DeferSessionRefresh   bool

	// RateLimit overrides the environment's enablement policy. By default
	// counters live on the auth instance. Supply RateLimitStorage to share them.
	RateLimit        *bool
	RateLimitStorage RateLimitStorage
	// RateLimitDefault applies to routes without their own rule. RateLimitRules
	// overrides built-in and plugin rules by exact route or trailing /* prefix.
	// A nil map value exempts the matching route from the limiter.
	// RateLimitRuleFuncs does the same with a function that chooses the limit
	// for each request. The closest entry in either map wins, and a route may
	// appear in only one of them.
	RateLimitDefault   *RateLimitRule
	RateLimitRules     map[string]*RateLimitRule
	RateLimitRuleFuncs map[string]RateLimitRuleFunc
	ClientIP           ClientIPOptions
	SocialProviders    map[string]OAuthProvider
	// EncryptOAuthTokens encrypts linked provider credentials at rest using the configured key ring.
	EncryptOAuthTokens bool
	Plugins            []Plugin
}

// User is the public account profile shared by all authentication methods.
type User struct {
	extraJSON string

	*PhoneNumberFields
	*UsernameFields
	LastLoginMethod *string `json:"lastLoginMethod,omitempty"`
	IsAnonymous     *bool   `json:"isAnonymous,omitempty"`
	*AdminUserFields
	TwoFactorEnabled *bool     `json:"twoFactorEnabled,omitempty"`
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Email            string    `json:"email"`
	EmailVerified    bool      `json:"emailVerified"`
	Image            *string   `json:"image"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

// Session identifies one authenticated login.
type Session struct {
	extraJSON string

	CredentialType       string `json:"credentialType,omitempty"`
	credentialAccess     *credentialSessionAccess
	ImpersonatedBy       *string   `json:"impersonatedBy,omitempty"`
	ActiveTeamID         *string   `json:"activeTeamId,omitempty"`
	ActiveOrganizationID *string   `json:"activeOrganizationId,omitempty"`
	ID                   string    `json:"id"`
	UserID               string    `json:"userId"`
	Token                string    `json:"token"`
	IPAddress            string    `json:"ipAddress"`
	UserAgent            string    `json:"userAgent"`
	CreatedAt            time.Time `json:"createdAt"`
	UpdatedAt            time.Time `json:"updatedAt"`
	ExpiresAt            time.Time `json:"expiresAt"`
}

// StoredSession is the record passed to the storage adapter.
type StoredSession struct {
	storageFields *storedSessionFields
	Session
}

// SessionResult pairs the current session with its authenticated user.
type SessionResult struct {
	// NeedsRefresh is present for eligible deferred HTTP reads.
	NeedsRefresh *bool   `json:"needsRefresh,omitempty"`
	Session      Session `json:"session"`
	User         User    `json:"user"`
}

// AuthResult contains a newly issued token or a pending second-factor challenge.
type AuthResult struct {
	// TrustedDeviceCookie contains the rotated or expired cookie after a credential login.
	TrustedDeviceCookie *http.Cookie    `json:"-"`
	Challenge           *LoginChallenge `json:"-"`
	TwoFactorRedirect   bool            `json:"twoFactorRedirect,omitempty"`
	TwoFactorMethods    []string        `json:"twoFactorMethods,omitempty"`
	Token               string          `json:"token"`
	User                User            `json:"user"`
	// syntheticUser replaces User in the HTTP response of a protected
	// duplicate sign-up.
	syntheticUser json.RawMessage
}

// SyntheticUser is the generated user for a sign-up with an existing email.
type SyntheticUser struct {
	ID, Name, Email      string
	EmailVerified        bool
	Image                *string
	CreatedAt, UpdatedAt time.Time
	// AdditionalFields holds the public UserAdditionalFields after defaults.
	AdditionalFields map[string]any
}

// SignUpInput describes a new email credential and public profile.
type SignUpInput struct {
	AdditionalFields          map[string]any
	Username, DisplayUsername *string
	Name, Email, Password     string
	Image                     *string
}

// SignInInput authenticates an existing email credential.
type SignInInput struct {
	Email, Password string
	RememberMe      *bool
}

// RequestMeta records the originating client information for a login.
type RequestMeta struct {
	// TrustedDeviceCookie is the incoming signed browser cookie value, if any.
	TrustedDeviceCookie  string
	CallbackURL          string
	IPAddress, UserAgent string
	RememberMe           *bool
}

var (
	ErrNotFound   = errors.New("authn: record not found")
	ErrEmailTaken = errors.New("authn: email already registered")
)

// Store persists users, credentials, and sessions. CreateUser commits its three
// writes atomically. Deletions are idempotent. An empty keep token revokes all
// sessions for that user. Implementations must support concurrent requests.
type Store interface {
	CreateUser(context.Context, User, string, *StoredSession) error
	Credential(context.Context, string) (User, string, error)
	CreateSession(context.Context, StoredSession) error
	Session(context.Context, string) (StoredSession, User, error)
	DeleteSession(context.Context, string) error
	ListSessions(context.Context, string) ([]StoredSession, error)
	DeleteOtherSessions(context.Context, string, string) error
	DeleteUserSession(context.Context, string, string) error
}

// APIError exposes a public status and error code shared by Go and HTTP callers.
type APIError struct {
	Status  int    `json:"-"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

func (e *APIError) Error() string { return e.Message }

// MissingPermissionsError identifies individual grants that an actor may not delegate.
type MissingPermissionsError struct {
	*APIError
	MissingPermissions []string `json:"missingPermissions"`
	OriginalMessage    string   `json:"originalMessage,omitempty"`
}

func (e *MissingPermissionsError) Unwrap() error {
	if e.OriginalMessage != "" {
		return &LocalizedError{APIError: e.APIError, OriginalMessage: e.OriginalMessage}
	}
	return e.APIError
}

// OAuthError represents the public error fields of an OAuth protocol response.
type OAuthError struct {
	Status      int    `json:"-"`
	Code        string `json:"error,omitempty"`
	Description string `json:"error_description"`
}

func (e *OAuthError) Error() string { return e.Description }

// EmptyResponse sends a successful endpoint response with its declared status and no body.
type EmptyResponse struct{}

// StatusOnlyError writes an HTTP status without a response body. Native
// callers can also retrieve its status and standard text with errors.As and *APIError.
type StatusOnlyError int

func (e StatusOnlyError) statusOnlyCode() int {
	if e < 400 || e > 599 {
		return http.StatusInternalServerError
	}
	return int(e)
}

func (e StatusOnlyError) Error() string { return http.StatusText(e.statusOnlyCode()) }
func (e StatusOnlyError) Unwrap() error {
	return &APIError{Status: e.statusOnlyCode(), Message: e.Error()}
}
