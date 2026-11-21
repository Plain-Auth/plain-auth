// Package betterauth embeds authentication in the host application's HTTP server.
package betterauth

import (
	"context"
	"errors"
	"time"
)

// Options configures one isolated authentication instance.
type Options struct {
	SendResetPassword             MailSender
	SendVerificationEmail         MailSender
	PasswordResetTokenTTL         time.Duration
	EmailVerificationTokenTTL     time.Duration
	RevokeSessionsOnPasswordReset bool
	Plugins                       []Plugin
	Store                         Store
	Secret                        string
	BaseURL                       string
	BasePath                      string
	TrustedOrigins                []string
	EmailAndPassword              bool
	SessionTTL                    time.Duration
	FreshAge                      time.Duration
	MinPasswordLength             int
	MaxPasswordLength             int
	RateLimit                     *bool
}

// User is the public account profile shared by all authentication methods.
type User struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"emailVerified"`
	Image         *string   `json:"image"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// Session identifies one authenticated login.
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	Token     string    `json:"token"`
	IPAddress string    `json:"ipAddress"`
	UserAgent string    `json:"userAgent"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// StoredSession is the record passed to the storage adapter.
type StoredSession struct {
	Session
}
type SessionResult struct {
	Session Session `json:"session"`
	User    User    `json:"user"`
}
type AuthResult struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}
type SignUpInput struct {
	Name, Email, Password string
	Image                 *string
}
type SignInInput struct {
	Email, Password string
	RememberMe      *bool
}
type RequestMeta struct {
	IPAddress, UserAgent string
	RememberMe           *bool
}

var (
	ErrNotFound   = errors.New("betterauth: record not found")
	ErrEmailTaken = errors.New("betterauth: email already registered")
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
