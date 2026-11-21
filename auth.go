package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/nabuhadba/go-better-auth/internal/configenv"
)

// Auth is safe for concurrent use by application handlers.
type Auth struct {
	deviceSessionResponse SessionResponseFunc
	deviceSessions        DeviceSessionStore
	maxDeviceSessions     int
	emailOTP              *EmailOTPOptions
	sessionResponse       SessionResponseFunc
	serviceJWT            *JWTOptions
	oneTimeToken          *OneTimeTokenOptions
	factorOptions         *TwoFactorOptions
	factorStore           TwoFactorStore
	passwordSlots         chan struct{}
	plugins               map[endpointKey]Endpoint
	opts                  Options
	now                   func() time.Time
	limiter               rateLimiter
}

// New constructs an http.Handler for mounting in an existing router.
func New(opts Options) (*Auth, error) {
	if err := resolveEnvironment(&opts); err != nil {
		return nil, err
	}
	if err := opts.ClientIP.prepare(); err != nil {
		return nil, err
	}
	if len(opts.Secrets) > 0 {
		opts.Secret = opts.Secrets[0].Value
	}
	if opts.CookiePrefix != "" && !cookiePrefixPattern.MatchString(opts.CookiePrefix) {
		return nil, errors.New("auth: CookiePrefix must contain only letters, digits, underscores, or hyphens")
	}
	if opts.Store == nil {
		return nil, errors.New("authn: Store is required")
	}
	if len(opts.Secret) < 32 {
		return nil, errors.New("authn: Secret needs at least 32 bytes")
	}
	var err error
	opts.BaseURL, opts.BasePath, err = configenv.ServerEndpoint(opts.BaseURL, opts.BasePath)
	if err != nil {
		return nil, fmt.Errorf("authn: BaseURL: %w", err)
	}
	for i, s := range opts.TrustedOrigins {
		origin, err := parseOrigin(s)
		if err != nil {
			return nil, fmt.Errorf("authn: TrustedOrigins[%d]: %w", i, err)
		}
		opts.TrustedOrigins[i] = origin
	}
	if opts.SessionTTL == 0 {
		opts.SessionTTL = 7 * 24 * time.Hour
	}
	updateAge := 24 * time.Hour
	if opts.SessionUpdateAge != nil {
		updateAge = *opts.SessionUpdateAge
		if updateAge < 0 {
			return nil, errors.New("authn: session update age must be nonnegative")
		}
	}
	opts.SessionUpdateAge = &updateAge
	if opts.FreshAge == 0 {
		opts.FreshAge = 24 * time.Hour
	}
	if opts.MinPasswordLength == 0 {
		opts.MinPasswordLength = 8
	}
	if opts.MaxPasswordLength == 0 {
		opts.MaxPasswordLength = 128
	}
	if opts.SessionTTL < time.Second || opts.FreshAge < 0 || opts.MinPasswordLength < 1 || opts.MaxPasswordLength < opts.MinPasswordLength {
		return nil, errors.New("authn: invalid session duration or password length")
	}
	if err := prepareRateLimits(&opts); err != nil {
		return nil, err
	}
	if opts.DeleteTokenTTL == 0 {
		opts.DeleteTokenTTL = 24 * time.Hour
	}
	if opts.DeleteTokenTTL < 0 {
		return nil, errors.New("authn: deletion token lifetime must be positive")
	}
	if opts.SendVerificationOnSignUp != nil {
		v := *opts.SendVerificationOnSignUp
		opts.SendVerificationOnSignUp = &v
	}
	if opts.DeleteUserEnabled || opts.ChangeEmailEnabled {
		if _, ok := opts.Store.(AccountLifecycleStore); !ok {
			return nil, errors.New("authn: account management requires an AccountLifecycleStore")
		}
	}
	if opts.PasswordResetTokenTTL == 0 {
		opts.PasswordResetTokenTTL = time.Hour
	}
	if opts.EmailVerificationTokenTTL == 0 {
		opts.EmailVerificationTokenTTL = time.Hour
	}
	if opts.PasswordResetTokenTTL < 0 || opts.EmailVerificationTokenTTL < 0 {
		return nil, errors.New("authn: token lifetimes must be positive")
	}
	if opts.SendVerificationEmail != nil || opts.SendResetPassword != nil {
		if _, ok := opts.Store.(AccountStore); !ok {
			return nil, errors.New("authn: mail link delivery requires an AccountStore")
		}
	}
	opts.Plugins = append([]Plugin(nil), opts.Plugins...)
	opts.SocialProviders, err = prepareOAuthProviders(opts.SocialProviders, opts.Store)
	if err != nil {
		return nil, err
	}
	plugins, err := registerPlugins(opts.Plugins)
	if err != nil {
		return nil, err
	}
	a := &Auth{opts: opts, now: time.Now, passwordSlots: make(chan struct{}, min(runtime.GOMAXPROCS(0), 4)), plugins: plugins}
	for _, p := range opts.Plugins {
		if p.SessionResponse != nil {
			a.sessionResponse = p.SessionResponse
			if p.ProjectDeviceSessions {
				a.deviceSessionResponse = p.SessionResponse
			}
		}
		if p.serviceJWT != nil {
			a.serviceJWT = p.serviceJWT
		}
		if p.emailOTP != nil {
			a.emailOTP = p.emailOTP
			if p.emailOTP.OverrideDefaultEmailVerification {
				original := a.opts.SendVerificationEmail
				a.opts.SendVerificationEmail = func(ctx context.Context, message MailLink) error {
					if message.NewEmail != "" {
						if original == nil {
							return errors.New("configure an email-change verification sender")
						}
						return original(ctx, message)
					}
					return a.SendEmailOTP(ctx, message.User.Email, OTPVerifyEmail)
				}
			}
		}
		if p.maxDeviceSessions != nil {
			a.deviceSessions, _ = opts.Store.(DeviceSessionStore)
			if a.deviceSessions == nil {
				return nil, errors.New("authn: multi-session requires a DeviceSessionStore")
			}
			a.maxDeviceSessions = *p.maxDeviceSessions
		}
		if p.oneTime != nil {
			a.oneTimeToken = p.oneTime
		}
		if p.ValidateStore != nil {
			if err := p.ValidateStore(opts.Store); err != nil {
				return nil, err
			}
		}
		if p.factor != nil {
			s, ok := opts.Store.(TwoFactorStore)
			if !ok {
				return nil, errors.New("auth: two-factor plugin requires a two-factor store")
			}
			if v, ok := s.(interface{ TwoFactorReady() bool }); ok && !v.TwoFactorReady() {
				return nil, errors.New("auth: install the two-factor database schema before enabling the plugin")
			}
			a.factorOptions = p.factor
			a.factorStore = s
		}
	}
	if opts.ErrorRedirectURL != "" && !a.trustedURL(opts.ErrorRedirectURL, true) {
		return nil, errors.New("auth: ErrorRedirectURL must be a trusted callback")
	}
	return a, nil
}

func parseOrigin(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || (u.EscapedPath() != "" && u.EscapedPath() != "/") || u.RawQuery != "" || u.ForceQuery || strings.Contains(s, "#") {
		return "", errors.New("expected an absolute HTTP(S) origin")
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), nil
}

var cookiePrefixPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

var emailPattern = regexp.MustCompile("(?i)^[a-z0-9_'+-](?:[a-z0-9_'+.-]*[a-z0-9_'+-])?@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}$")

func (a *Auth) validateCredential(email, password string, signup bool) error {
	if !a.opts.EmailAndPassword {
		if signup {
			return &APIError{400, "EMAIL_PASSWORD_SIGN_UP_DISABLED", "Email and password sign up is not enabled"}
		}
		return &APIError{400, "EMAIL_PASSWORD_DISABLED", "Email and password is not enabled"}
	}
	if len(email) > 254 || strings.Contains(email, "..") || !emailPattern.MatchString(email) {
		return &APIError{400, "INVALID_EMAIL", "Invalid email"}
	}
	return a.validatePasswordLength(password, signup)
}

func (a *Auth) validatePasswordLength(password string, enforceMinimum bool) error {
	// Measure the wire limit in UTF-16 code units.
	n := 0
	for _, r := range password {
		n += utf16.RuneLen(r)
	}
	if n > a.opts.MaxPasswordLength {
		return &APIError{400, "PASSWORD_TOO_LONG", "Password too long"}
	}
	if enforceMinimum && n < a.opts.MinPasswordLength {
		return &APIError{400, "PASSWORD_TOO_SHORT", "Password too short"}
	}
	return nil
}

func randomID() string {
	var b [24]byte
	rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func (a *Auth) newSession(id string, meta RequestMeta) (StoredSession, string) {
	now := a.now().UTC().Truncate(time.Millisecond)
	ttl := a.opts.SessionTTL
	if meta.RememberMe != nil && !*meta.RememberMe {
		ttl = min(ttl, 24*time.Hour)
	}
	s := Session{ID: randomID(), UserID: id, IPAddress: meta.IPAddress, UserAgent: meta.UserAgent, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(ttl)}
	s.Token = randomID()
	return StoredSession{Session: s}, s.Token
}

// SignUpEmail creates a credential account and its first session atomically.
func (a *Auth) SignUpEmail(ctx context.Context, in SignUpInput, meta RequestMeta) (AuthResult, error) {
	if a.opts.DisableSignUp {
		return AuthResult{}, &APIError{400, "EMAIL_PASSWORD_SIGN_UP_DISABLED", "Email and password sign up is not enabled"}
	}
	if meta.CallbackURL != "" && !a.trustedURL(meta.CallbackURL, true) {
		return AuthResult{}, &APIError{403, "INVALID_CALLBACK_URL", "Invalid callbackURL"}
	}
	if err := a.validateCredential(in.Email, in.Password, true); err != nil {
		return AuthResult{}, err
	}
	hash, err := a.hashCredential(ctx, "/sign-up/email", in.Password)
	if err != nil {
		return AuthResult{}, err
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	user := User{ID: randomID(), Email: strings.ToLower(in.Email), Name: in.Name, Image: in.Image, CreatedAt: now, UpdatedAt: now}
	if a.factorStore != nil {
		enabled := false
		user.TwoFactorEnabled = &enabled
	}
	var first *StoredSession
	var token string
	if !a.opts.RequireEmailVerification && !a.opts.DisableAutoSignIn {
		row, raw := a.newSession(user.ID, meta)
		first, token = &row, raw
	}
	err = a.opts.Store.CreateUser(ctx, user, hash, first)
	if errors.Is(err, ErrEmailTaken) {
		if first == nil {
			return AuthResult{User: user}, nil
		}
		return AuthResult{}, &APIError{422, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL", "User already exists. Use another email."}
	}
	if err != nil {
		return AuthResult{}, err
	}
	if a.emailOTP != nil && a.emailOTP.SendVerificationOnSignUp && !a.emailOTP.OverrideDefaultEmailVerification {
		if err := a.SendEmailOTP(ctx, user.Email, OTPVerifyEmail); err != nil {
			slog.ErrorContext(ctx, "Could not deliver sign-up verification code")
		}
	}
	send := a.opts.RequireEmailVerification
	if a.opts.SendVerificationOnSignUp != nil {
		send = *a.opts.SendVerificationOnSignUp
	}
	if send && a.opts.SendVerificationEmail != nil {
		if err := a.sendEmailProof(ctx, user, "", "", meta.CallbackURL, a.opts.SendVerificationEmail); err != nil {
			slog.ErrorContext(ctx, "Could not deliver sign-up verification email")
		}
	}
	return AuthResult{User: user, Token: token}, nil
}

// SignInEmail verifies credentials and returns a new session or a pending second-factor challenge.
func (a *Auth) SignInEmail(ctx context.Context, in SignInInput, meta RequestMeta) (AuthResult, error) {
	if err := a.validateCredential(in.Email, in.Password, false); err != nil {
		return AuthResult{}, err
	}
	user, hash, err := a.opts.Store.Credential(ctx, strings.ToLower(in.Email))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return AuthResult{}, err
	}
	if errors.Is(err, ErrNotFound) {
		hash = dummyPasswordHash
	}
	valid, err := a.checkCredential(ctx, hash, in.Password)
	if err != nil {
		return AuthResult{}, err
	}
	if !valid || user.ID == "" {
		return AuthResult{}, &APIError{401, "INVALID_EMAIL_OR_PASSWORD", "Invalid email or password"}
	}
	if a.opts.RequireEmailVerification && !user.EmailVerified {
		if a.opts.SendVerificationOnSignIn && a.opts.SendVerificationEmail != nil {
			if err := a.sendEmailProof(ctx, user, "", "", meta.CallbackURL, a.opts.SendVerificationEmail); err != nil {
				return AuthResult{}, err
			}
		}
		return AuthResult{}, &APIError{403, "EMAIL_NOT_VERIFIED", "Email not verified"}
	}
	if in.RememberMe != nil {
		meta.RememberMe = in.RememberMe
	}
	session, token := a.newSession(user.ID, meta)
	if a.factorStore != nil {
		return a.factorLogin(ctx, user, hash, session, meta.TrustedDeviceCookie)
	}
	if s, ok := a.opts.Store.(AccountStore); ok {
		err = s.CreateCredentialSession(ctx, hash, session)
		if errors.Is(err, ErrNotFound) {
			return AuthResult{}, &APIError{401, "INVALID_EMAIL_OR_PASSWORD", "Invalid email or password"}
		}
	} else {
		err = a.opts.Store.CreateSession(ctx, session)
	}
	if err != nil {
		return AuthResult{}, err
	}
	return AuthResult{User: user, Token: token}, nil
}

// GetSession returns nil for an unauthenticated request.
func (a *Auth) GetSession(ctx context.Context, headers http.Header) (*SessionResult, error) {
	token := a.cookieToken(headers)
	if token == "" {
		return nil, nil
	}
	row, user, err := a.opts.Store.Session(ctx, token)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !row.ExpiresAt.After(a.now()) {
		return nil, nil
	}
	row.Token = token
	return a.withSessionPlugins(ctx, row.Session, user)
}

func (a *Auth) SignOut(ctx context.Context, headers http.Header) error {
	token := a.cookieToken(headers)
	if a.deviceSessions != nil {
		devices := a.readDeviceCookies(headers)
		tokens := devices.tokens
		if token != "" {
			tokens = append(tokens, token)
		}
		return a.deviceSessions.DeleteDeviceSessions(ctx, tokens)
	}
	if token == "" {
		return nil
	}
	return a.opts.Store.DeleteSession(ctx, token)
}

func (a *Auth) requireSession(ctx context.Context, headers http.Header) (*SessionResult, error) {
	s, err := a.GetSession(ctx, headers)
	if err == nil && s == nil {
		return nil, &APIError{401, "UNAUTHORIZED", "Unauthorized"}
	}
	return s, err
}

func (a *Auth) ListSessions(ctx context.Context, headers http.Header) ([]Session, error) {
	current, err := a.requireSession(ctx, headers)
	if err != nil {
		return nil, err
	}
	now := a.now()
	if now.Sub(current.Session.CreatedAt) >= a.opts.FreshAge {
		return nil, &APIError{403, "SESSION_NOT_FRESH", "Session is not fresh"}
	}
	rows, err := a.opts.Store.ListSessions(ctx, current.User.ID)
	if err != nil {
		return nil, err
	}
	sessions := make([]Session, 0, len(rows))
	for _, row := range rows {
		if row.ExpiresAt.After(now) {

			sessions = append(sessions, row.Session)
		}
	}
	return sessions, nil
}

func (a *Auth) RevokeSession(ctx context.Context, h http.Header, token string) error {
	s, err := a.requireSession(ctx, h)
	if err != nil {
		return err
	}
	return a.opts.Store.DeleteUserSession(ctx, s.User.ID, token)
}

func (a *Auth) RevokeOtherSessions(ctx context.Context, h http.Header) error {
	s, err := a.requireSession(ctx, h)
	if err != nil {
		return err
	}
	return a.opts.Store.DeleteOtherSessions(ctx, s.User.ID, s.Session.Token)
}

func (a *Auth) RevokeSessions(ctx context.Context, h http.Header) error {
	s, err := a.requireSession(ctx, h)
	if err != nil {
		return err
	}
	return a.opts.Store.DeleteOtherSessions(ctx, s.User.ID, "")
}

// BasePath reports the effective mount path after configuration resolution.
func (a *Auth) BasePath() string { return a.opts.BasePath }
