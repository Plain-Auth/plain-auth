// Package stonewrit embeds authentication in the host application's HTTP server.
package stonewrit

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// Options configures one isolated authentication instance.
type Options struct {
	// Logger receives diagnostics for this instance. A nil logger uses slog.Default().
	Logger *slog.Logger
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
	// DisabledPaths hides exact HTTP paths relative to this instance’s mount.
	DisabledPaths []string
	// TrustedOrigins allows exact HTTP(S) origins and hostname or port wildcard patterns for browser requests and callbacks.
	TrustedOrigins []string
	CookiePrefix   string
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
	// OnPasswordReset runs after a recovery proof is consumed, the password is
	// replaced, and any requested session revocation commits. Mounted endpoints
	// pass the HTTP request. Direct Go calls pass nil.
	OnPasswordReset func(context.Context, User, *http.Request) error

	// Account lifecycle operations with destructive or identity-changing effects are opt-in.
	DeleteUserEnabled              bool
	SendDeleteAccountVerification  MailSender
	DeleteTokenTTL                 time.Duration
	ChangeEmailEnabled             bool
	UpdateEmailWithoutVerification bool
	SendChangeEmailConfirmation    MailSender
	// DisableAccountLinking prevents attaching another provider to an existing account.
	DisableAccountLinking bool
	// DisableImplicitAccountLinking requires an authenticated owner to link an additional provider.
	DisableImplicitAccountLinking bool
	AllowUnlinkingAll             bool

	SessionTTL time.Duration
	FreshAge   time.Duration
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
	RateLimitDefault *RateLimitRule
	RateLimitRules   map[string]*RateLimitRule
	ClientIP         ClientIPOptions
	SocialProviders  map[string]OAuthProvider
	// EncryptOAuthTokens encrypts linked provider credentials at rest using the configured key ring.
	EncryptOAuthTokens bool
	Plugins            []Plugin
}

// User is the public account profile shared by all authentication methods.
type User struct {
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
}

// SignUpInput describes a new email credential and public profile.
type SignUpInput struct {
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
