// Package fineauth embeds authentication in the host application's HTTP server.
package fineauth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Options configures one isolated authentication instance.
type Options struct {
	// Store persists identities and sessions. Configure one store per auth instance.
	Store Store
	// BaseURL is the public HTTP(S) address. BasePath defaults to /api/auth.
	BaseURL  string
	BasePath string
	// TrustedOrigins adds exact origins allowed to make browser requests and callbacks.
	TrustedOrigins   []string
	CookiePrefix     string
	ErrorRedirectURL string
	// Secret signs credentials. Secrets configures ordered keys for rotation.
	Secret  string
	Secrets []VersionedSecret

	EmailAndPassword              bool
	MinPasswordLength             int
	MaxPasswordLength             int
	DisableSignUp                 bool
	DisableAutoSignIn             bool
	RequireEmailVerification      bool
	SendVerificationOnSignUp      *bool
	SendVerificationOnSignIn      bool
	SendVerificationEmail         MailSender
	EmailVerificationTokenTTL     time.Duration
	SendResetPassword             MailSender
	PasswordResetTokenTTL         time.Duration
	RevokeSessionsOnPasswordReset bool

	// Account lifecycle operations with destructive or identity-changing effects are opt-in.
	DeleteUserEnabled              bool
	SendDeleteAccountVerification  MailSender
	DeleteTokenTTL                 time.Duration
	ChangeEmailEnabled             bool
	UpdateEmailWithoutVerification bool
	SendChangeEmailConfirmation    MailSender
	AllowUnlinkingAll              bool

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
	IsAnonymous      *bool     `json:"isAnonymous,omitempty"`
	LastLoginMethod  *string   `json:"lastLoginMethod,omitempty"`
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
	Session Session `json:"session"`
	User    User    `json:"user"`
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
	Name, Email, Password string
	Image                 *string
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
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string { return e.Message }
