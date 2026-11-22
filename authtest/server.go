package authtest

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/organization"
)

// Server holds an auth handler and privileged helpers for a dedicated test database.
// Only Auth should be mounted in the application's router.
type Server struct {
	Auth                 *auth.Auth
	store                auth.Store
	origin               string
	organizations        *organization.Service
	organizationFixtures OrganizationStore
}

// New creates an auth instance from the same options used by the application.
func New(opts auth.Options) (*Server, error) {
	node, err := auth.New(opts)
	if err != nil {
		return nil, err
	}
	origin, err := node.CallbackURL("/")
	if err != nil {
		return nil, err
	}
	return &Server{Auth: node, store: opts.Store, origin: origin}, nil
}

// UserStore lets a custom adapter support setup and teardown of user fixtures.
type UserStore interface {
	SaveFixtureUser(context.Context, auth.User) error
	DeleteFixtureUser(context.Context, string) error
	FindAccountUser(context.Context, string) (auth.User, error)
}

// SaveUser inserts a profile without creating a password account or a session.
func (s *Server) SaveUser(ctx context.Context, u auth.User) (auth.User, error) {
	store, ok := s.store.(UserStore)
	if !ok {
		return auth.User{}, errors.New("authtest: adapter does not implement UserStore")
	}
	if u.ID == "" || u.Email == "" {
		return auth.User{}, errors.New("authtest: a user ID and email are required")
	}
	u.Email = strings.ToLower(u.Email)
	if err := store.SaveFixtureUser(ctx, u); err != nil {
		return auth.User{}, err
	}
	actual, err := store.FindAccountUser(ctx, u.Email)
	if err == nil && actual.ID != u.ID {
		return auth.User{}, auth.ErrNotFound
	}
	return actual, err
}

// DeleteUser removes a user and its dependent records from the configured store.
func (s *Server) DeleteUser(ctx context.Context, id string) error {
	store, ok := s.store.(UserStore)
	if !ok {
		return errors.New("authtest: adapter does not implement UserStore")
	}
	return store.DeleteFixtureUser(ctx, id)
}

// LoginResult can authenticate native, HTTP and browser tests with the same session.
type LoginResult struct {
	auth.SessionResult
	Token   string
	Headers http.Header
	Cookies []*http.Cookie
}

// LoginOptions selects an existing fixture user and values for configured session fields.
// Fields can supply required or server-only values before the row is inserted.
type LoginOptions struct {
	UserID string
	Fields map[string]any
}

// Login creates a real session for an existing user and returns its signed cookie.
// Reuse the result when several requests should belong to the same login.
func (s *Server) Login(ctx context.Context, userID string) (*LoginResult, error) {
	return s.LoginWithOptions(ctx, LoginOptions{UserID: userID})
}

// LoginWithOptions creates a real session with trusted fixture attributes.
func (s *Server) LoginWithOptions(ctx context.Context, opts LoginOptions) (*LoginResult, error) {
	if opts.UserID == "" {
		return nil, auth.ErrNotFound
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.origin, nil)
	if err != nil {
		return nil, err
	}
	call := auth.EndpointContext{Auth: s.Auth, Request: req, ResponseHeader: make(http.Header)}
	var issued string
	fields := make(map[string]any, len(opts.Fields))
	for name, value := range opts.Fields {
		switch name {
		case "id", "userId", "token", "expiresAt", "createdAt", "updatedAt", "ipAddress", "userAgent":
			// Session issuance owns these fields even when the fixture includes them.
		default:
			fields[name] = value
		}
	}
	session, err := call.IssueSession(opts.UserID, func(ctx context.Context, row auth.StoredSession) (auth.User, error) {
		row, err := s.Auth.WithTrustedSessionFields(row, fields)
		if err != nil {
			return auth.User{}, err
		}
		if err := s.store.CreateSession(ctx, row); err != nil {
			return auth.User{}, err
		}
		issued = row.Token
		_, user, err := s.store.Session(ctx, row.Token)
		return user, err
	})
	if err != nil {
		if issued != "" {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			err = errors.Join(err, s.store.DeleteSession(cleanup, issued))
		}
		return nil, err
	}
	cookie := s.Auth.SessionCookie(issued, true)
	req.AddCookie(cookie)
	if cookie.Domain == "" {
		cookie.Domain = req.URL.Hostname()
	}
	return &LoginResult{SessionResult: *session, Token: issued, Headers: req.Header, Cookies: []*http.Cookie{cookie}}, nil
}

// GetAuthHeaders creates a session and returns a request header for native or HTTP calls.
func (s *Server) GetAuthHeaders(ctx context.Context, userID string) (http.Header, error) {
	return s.GetAuthHeadersWithOptions(ctx, LoginOptions{UserID: userID})
}

// GetAuthHeadersWithOptions creates a session with fixture attributes and returns its request headers.
func (s *Server) GetAuthHeadersWithOptions(ctx context.Context, opts LoginOptions) (http.Header, error) {
	login, err := s.LoginWithOptions(ctx, opts)
	if err != nil {
		return nil, err
	}
	return login.Headers, nil
}

// GetCookies creates a session and returns its cookie for a browser fixture.
// Pass an empty domain to use the configured cookie domain or auth hostname.
func (s *Server) GetCookies(ctx context.Context, userID, domain string) ([]*http.Cookie, error) {
	return s.GetCookiesWithOptions(ctx, LoginOptions{UserID: userID}, domain)
}

// GetCookiesWithOptions creates a session with fixture attributes and returns its browser cookie.
func (s *Server) GetCookiesWithOptions(ctx context.Context, opts LoginOptions, domain string) ([]*http.Cookie, error) {
	if err := validateCookieDomain(domain); err != nil {
		return nil, err
	}
	login, err := s.LoginWithOptions(ctx, opts)
	if err != nil {
		return nil, err
	}
	if domain != "" {
		login.Cookies[0].Domain = domain
	}
	return login.Cookies, nil
}
