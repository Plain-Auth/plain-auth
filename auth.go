package plainauth

import (
	"github.com/Plain-Auth/plain-auth/internal/sessionfields"
	"slices"

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

	"github.com/Plain-Auth/plain-auth/internal/configenv"
)

// Auth is safe for concurrent use by application handlers.
type Auth struct {
	trustedProfileFields  map[string]UserField
	oauthProxy            *OAuthProxyOptions
	sessionCacheKeys      []sessionCacheKey
	disabledPaths         map[string]struct{}
	trustedOrigins        []trustedOrigin
	phoneNumber           *PhoneNumberOptions
	translateError        func(ErrorContext, APIError) string
	username              *UsernameOptions
	anonymous             *AnonymousOptions
	admin                 *AdminOptions
	adminStore            AdminStore
	deviceSessionResponse SessionResponseFunc
	deviceSessions        DeviceSessionStore
	maxDeviceSessions     int
	emailOTP              *EmailOTPOptions
	sessionResponse       SessionResponseFunc
	prepareOAuthSelection func(EndpointContext, string) (OAuthLoginContinuation, error)
	prepareOAuthLogin     func(EndpointContext, string) (OAuthLoginContinuation, error)
	serviceJWT            *JWTOptions
	oneTimeToken          *OneTimeTokenOptions
	factorOptions         *TwoFactorOptions
	factorStore           TwoFactorStore
	passwordSlots         chan struct{}
	plugins               map[endpointKey]Endpoint
	wellKnown             map[string]WellKnownDocument
	opts                  Options
	now                   func() time.Time
	limiter               rateLimiter
}

// New constructs an http.Handler for mounting in an existing router.
func New(opts Options) (*Auth, error) {
	if err := prepareSessionCookieCache(&opts); err != nil {
		return nil, err
	}
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
	if opts.EmailAndPassword && !opts.DisableSignUp && opts.OnExistingUserSignUp != nil && (opts.RequireEmailVerification || opts.DisableAutoSignIn) {
		if _, ok := opts.Store.(signUpUserFinder); !ok {
			return nil, errors.New("auth: protected sign-up observer requires a store implementing FindAccountUser")
		}
	}
	if len(opts.Secret) < 32 {
		return nil, errors.New("authn: Secret needs at least 32 bytes")
	}
	var err error
	opts.UserAdditionalFields, err = sessionfields.NormalizeUser(opts.UserAdditionalFields)
	if err != nil {
		return nil, err
	}
	if len(opts.UserAdditionalFields) > 0 {
		store, ok := opts.Store.(UserFieldStore)
		if !ok {
			return nil, errors.New("auth: additional user fields require a UserFieldStore")
		}
		if err = store.ValidateUserFields(opts.UserAdditionalFields); err != nil {
			return nil, err
		}
	}
	opts.SessionAdditionalFields, err = sessionfields.Normalize(opts.SessionAdditionalFields)
	if err != nil {
		return nil, err
	}
	if len(opts.SessionAdditionalFields) > 0 {
		store, ok := opts.Store.(SessionFieldStore)
		if !ok {
			return nil, errors.New("auth: additional session fields require a SessionFieldStore")
		}
		if err = store.ValidateSessionFields(opts.SessionAdditionalFields); err != nil {
			return nil, err
		}
	}
	if err := configureAccountFields(&opts); err != nil {
		return nil, err
	}
	opts.BaseURL, opts.BasePath, err = configenv.ServerEndpoint(opts.BaseURL, opts.BasePath)
	if err != nil {
		return nil, fmt.Errorf("authn: BaseURL: %w", err)
	}
	if err := prepareCookieScope(&opts); err != nil {
		return nil, err
	}
	trustedOrigins, err := configuredTrustedOrigins(opts.TrustedOrigins)
	if err != nil {
		return nil, err
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
	opts.SocialProviders, err = prepareOAuthProviders(opts.SocialProviders, opts.Store, len(opts.UserAdditionalFields) > 0 && !opts.DisableSignUp)
	if err != nil {
		return nil, err
	}
	plugins, err := registerPlugins(opts.Plugins)
	if err != nil {
		return nil, err
	}
	disabledPaths, err := prepareDisabledPaths(opts.DisabledPaths)
	if err != nil {
		return nil, err
	}
	a := &Auth{opts: opts, disabledPaths: disabledPaths, trustedOrigins: trustedOrigins, now: time.Now, passwordSlots: make(chan struct{}, min(runtime.GOMAXPROCS(0), 4)), plugins: plugins}
	a.trustedProfileFields, err = trustedProfileSchema(opts.UserAdditionalFields, opts.Plugins)
	if err != nil {
		return nil, err
	}
	if err := a.prepareSessionCacheKeys(); err != nil {
		return nil, err
	}
	for _, p := range opts.Plugins {
		if p.oauthProxy != nil {
			proxy := *p.oauthProxy
			if proxy.ProductionURL == "" {
				proxy.ProductionURL = proxyOrigin(a.opts.BaseURL)
				if proxy.ProductionURL == "" {
					return nil, errors.New("oauth proxy: a secure production origin is required")
				}
			}
			if len(proxy.Secrets) == 0 {
				proxy.Secrets = a.encryptionSecrets()
			}
			a.oauthProxy = &proxy
		}
		if p.PrepareOAuthLogin != nil {
			if a.prepareOAuthLogin != nil {
				return nil, errors.New("auth: only one plugin may resume OAuth logins")
			}
			a.prepareOAuthLogin = p.PrepareOAuthLogin
		}
		if p.PrepareOAuthSelection != nil {
			if a.prepareOAuthSelection != nil {
				return nil, errors.New("auth: only one plugin may resume OAuth selections")
			}
			a.prepareOAuthSelection = p.PrepareOAuthSelection
		}
		if p.TranslateError != nil {
			if a.translateError != nil {
				return nil, errors.New("auth: only one plugin may translate errors")
			}
			a.translateError = p.TranslateError
		}
		if p.phoneNumber != nil {
			if !opts.DisableSignUp && p.phoneNumber.SignUpOnVerification != nil && len(opts.UserAdditionalFields) > 0 {
				if _, ok := opts.Store.(PhoneRegistrationStore); !ok {
					return nil, errors.New("phone signup with configured user fields requires a PhoneRegistrationStore")
				}
			}
			a.phoneNumber = p.phoneNumber
		}
		if p.admin != nil {
			store, ok := opts.Store.(AdminStore)
			if !ok {
				return nil, errors.New("authn: admin requires an AdminStore")
			}
			a.adminStore, err = store.WithAdminConfig(p.admin.DefaultRole, p.admin.BannedUserMessage)
			if err != nil {
				return nil, err
			}
			a.admin = p.admin
			a.opts.Store = a.adminStore
			opts.Store = a.adminStore
		}
	}
	for _, p := range opts.Plugins {

		if p.username != nil {
			a.username = p.username
		}
		if p.anonymous != nil {
			a.anonymous = p.anonymous
		}
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
			if len(opts.UserAdditionalFields) > 0 && !p.emailOTP.DisableSignUp {
				if _, ok := opts.Store.(EmailOTPRegistrationStore); !ok {
					return nil, errors.New("auth: email OTP signup with configured user fields requires an EmailOTPRegistrationStore")
				}
			}
			if opts.OnPasswordReset != nil {
				if _, ok := opts.Store.(EmailOTPResetHookStore); !ok {
					return nil, errors.New("auth: email OTP password reset callbacks require an EmailOTPResetHookStore")
				}
			}
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
		if p.magicLinkRegistration && len(opts.UserAdditionalFields) > 0 {
			if _, ok := opts.Store.(MagicLinkUserFieldStore); !ok {
				return nil, errors.New("magic link registration with configured user fields requires a MagicLinkUserFieldStore")
			}
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
	if opts.AutoSignInAfterVerification {
		if _, ok := a.opts.Store.(EmailVerificationSessionStore); !ok {
			return nil, errors.New("auth: automatic email verification sign-in requires an EmailVerificationSessionStore")
		}
	}
	if a.hasVerificationObservers() {
		if _, ok := a.opts.Store.(EmailVerificationObserverStore); !ok {
			return nil, errors.New("auth: email verification callbacks require an EmailVerificationObserverStore")
		}
		if _, ok := a.opts.Store.(EmailOTPVerificationObserverStore); a.emailOTP != nil && !ok {
			return nil, errors.New("auth: email OTP verification callbacks require an EmailOTPVerificationObserverStore")
		}
	}
	if err := a.prepareWellKnown(); err != nil {
		return nil, err
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
		if n > a.opts.MaxPasswordLength {
			return &APIError{400, "PASSWORD_TOO_LONG", "Password too long"}
		}
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
	row := a.sessionDraft(id, meta)
	if len(a.opts.SessionAdditionalFields) > 0 {
		prepared, err := a.WithTrustedSessionFields(row, nil)
		if err != nil {
			row.storageFields = &storedSessionFields{invalid: err.Error()}
		} else {
			row = prepared
		}
	}
	return row, row.Token
}

func (a *Auth) sessionDraft(id string, meta RequestMeta) StoredSession {
	now := a.now().UTC().Truncate(time.Millisecond)
	ttl := a.opts.SessionTTL
	if meta.RememberMe != nil && !*meta.RememberMe {
		ttl = min(ttl, 24*time.Hour)
	}
	s := Session{ID: randomID(), UserID: id, IPAddress: meta.IPAddress, UserAgent: meta.UserAgent, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(ttl)}
	s.Token = randomID()
	return StoredSession{Session: s}
}

// SignUpEmail creates a credential account and its first session atomically.
func (a *Auth) SignUpEmail(ctx context.Context, in SignUpInput, meta RequestMeta) (AuthResult, error) {
	return a.signUpEmail(ctx, in, meta, nil, nil)
}

func (a *Auth) signUpEmail(ctx context.Context, in SignUpInput, meta RequestMeta, request *http.Request, beforeCreate func(SessionResult) error) (AuthResult, error) {
	if a.opts.DisableSignUp {
		return AuthResult{}, &APIError{400, "EMAIL_PASSWORD_SIGN_UP_DISABLED", "Email and password sign up is not enabled"}
	}
	if meta.CallbackURL != "" && !a.trustedURL(meta.CallbackURL, true) {
		return AuthResult{}, &APIError{403, "INVALID_CALLBACK_URL", "Invalid callbackURL"}
	}
	if err := a.validateCredential(in.Email, in.Password, true); err != nil {
		return AuthResult{}, err
	}
	extras, err := a.prepareUserFields(in.AdditionalFields, true, false)
	if err != nil {
		return AuthResult{}, err
	}
	var fields *UsernameFields
	if a.username != nil {
		fields, err = a.username.fields(ctx, in.Username, in.DisplayUsername, true)
		if err != nil {
			return AuthResult{}, err
		}
		if fields.Username != nil {
			used, err := a.opts.Store.(UsernameStore).UsernameExists(ctx, *fields.Username)
			if err != nil {
				return AuthResult{}, err
			}
			if used {
				return AuthResult{}, usernameWriteError(ErrUsernameTaken)
			}
		}
	}
	hash, err := a.hashCredential(ctx, "/sign-up/email", in.Password)
	if err != nil {
		return AuthResult{}, err
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	user := User{UsernameFields: fields, ID: randomID(), Email: strings.ToLower(in.Email), Name: in.Name, Image: in.Image, CreatedAt: now, UpdatedAt: now}
	if a.admin != nil {
		user.AdminUserFields = &AdminUserFields{Role: a.admin.DefaultRole}
	}
	if a.factorStore != nil {
		enabled := false
		user.TwoFactorEnabled = &enabled
	}
	var first *StoredSession
	var token string
	if !a.opts.RequireEmailVerification && !a.opts.DisableAutoSignIn {
		row, raw := a.newSession(user.ID, meta)
		first, token = &row, raw
		if beforeCreate != nil {
			if err := beforeCreate(SessionResult{Session: row.Session, User: user}); err != nil {
				return AuthResult{}, err
			}
		}
	}
	if extras.Present() {
		err = a.opts.Store.(UserFieldStore).CreateUserWithFields(ctx, user, hash, first, extras)
	} else {
		err = a.opts.Store.CreateUser(ctx, user, hash, first)
	}
	err = usernameWriteError(err)
	if errors.Is(err, ErrEmailTaken) {
		if first == nil {
			// A generated profile has the same enabled public fields as a new account.
			if a.anonymous != nil {
				guest := false
				user.IsAnonymous = &guest
			}
			if a.phoneNumber != nil {
				user.PhoneNumberFields = &PhoneNumberFields{}
			}
			if err := a.projectPublicUser(&user, extras.columns); err != nil {
				return AuthResult{}, err
			}
			if a.opts.OnExistingUserSignUp != nil {
				a.notifyExistingSignUp(ctx, user.Email, request)
			}
			return AuthResult{User: user}, nil
		}
		return AuthResult{}, duplicateSignupError()
	}
	if err != nil {
		return AuthResult{}, err
	}
	if a.emailOTP != nil && a.emailOTP.SendVerificationOnSignUp && !a.emailOTP.OverrideDefaultEmailVerification {
		if err := a.SendEmailOTP(ctx, user.Email, OTPVerifyEmail); err != nil {
			a.Logger().ErrorContext(ctx, "Could not deliver sign-up verification code")
		}
	}
	if a.sendVerificationOnSignup(a.opts.RequireEmailVerification) && a.opts.SendVerificationEmail != nil {
		if err := a.sendEmailProof(ctx, user, "", "", meta.CallbackURL, a.opts.SendVerificationEmail); err != nil {
			a.Logger().ErrorContext(ctx, "Could not deliver sign-up verification email")
		}
	}
	if err := a.readPublicUserFields(ctx, &user); err != nil {
		return AuthResult{}, err
	}
	return AuthResult{User: user, Token: token}, nil
}

func duplicateSignupError() *APIError {
	return &APIError{422, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL", "User already exists. Use another email."}
}

// SignInEmail verifies credentials and returns a new session or a pending second-factor challenge.
func (a *Auth) SignInEmail(ctx context.Context, in SignInInput, meta RequestMeta) (AuthResult, error) {
	if err := a.validateCredential(in.Email, in.Password, false); err != nil {
		return AuthResult{}, err
	}
	user, hash, err := a.opts.Store.Credential(ctx, strings.ToLower(in.Email))
	if in.RememberMe != nil {
		meta.RememberMe = in.RememberMe
	}
	return a.completeCredentialSignIn(ctx, user, hash, err, in.Password, meta, &APIError{401, "INVALID_EMAIL_OR_PASSWORD", "Invalid email or password"})
}

func (a *Auth) completeCredentialSignIn(ctx context.Context, user User, hash string, err error, password string, meta RequestMeta, denied *APIError) (AuthResult, error) {
	if err != nil && !errors.Is(err, ErrNotFound) {
		return AuthResult{}, err
	}
	if errors.Is(err, ErrNotFound) || hash == "" || user.ID == "" {
		// Spend a password derivation on unsuccessful lookups with the configured
		// algorithm. This result is discarded even if the password matches.
		if _, err := a.derivePassword(ctx, password); err != nil {
			return AuthResult{}, err
		}
		return AuthResult{}, denied
	}
	valid, err := a.checkCredential(ctx, hash, password)
	if err != nil {
		return AuthResult{}, err
	}
	if !valid {
		return AuthResult{}, denied
	}
	if a.admin != nil && user.AdminUserFields != nil && user.Banned {
		if user.BanExpires == nil || user.BanExpires.After(a.now()) {
			return AuthResult{}, &APIError{403, "BANNED_USER", a.admin.BannedUserMessage}
		}
		user.Banned = false
		user.BanReason = nil
		user.BanExpires = nil
	}
	if a.opts.RequireEmailVerification && !user.EmailVerified {
		if a.opts.SendVerificationOnSignIn && a.opts.SendVerificationEmail != nil {
			if err := a.sendEmailProof(ctx, user, "", "", meta.CallbackURL, a.opts.SendVerificationEmail); err != nil {
				return AuthResult{}, err
			}
		}
		return AuthResult{}, &APIError{403, "EMAIL_NOT_VERIFIED", "Email not verified"}
	}

	session, token := a.newSession(user.ID, meta)
	if a.factorStore != nil {
		return a.factorLogin(ctx, user, hash, session, meta.TrustedDeviceCookie)
	}
	if s, ok := a.opts.Store.(AccountStore); ok {
		err = s.CreateCredentialSession(ctx, hash, session)
		if errors.Is(err, ErrNotFound) {
			return AuthResult{}, denied
		}
	} else {
		err = a.opts.Store.CreateSession(ctx, session)
	}
	if err != nil {
		return AuthResult{}, err
	}
	if err := a.readPublicUserFields(ctx, &user); err != nil {
		return AuthResult{}, err
	}
	return AuthResult{User: user, Token: token}, nil
}

// GetSession returns nil for an unauthenticated request.
func (a *Auth) GetSession(ctx context.Context, headers http.Header) (*SessionResult, error) {
	if identity, _ := ctx.Value(credentialSessionKey{a}).(*SessionResult); identity != nil {
		return identity, nil
	}
	if ctx.Value(credentialProbedKey{a}) == nil {
		if _, identity, err := a.resolveCredentialSession(ctx, headers, RequestMeta{UserAgent: headers.Get("User-Agent")}, nil); identity != nil || err != nil {
			return identity, err
		}
	}
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
	result, err := a.withSessionPlugins(ctx, row.Session, user)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err == nil && a.translateError != nil {
		a.noteErrorUser(ctx, token, result.User)
	}
	return result, err
}

func (a *Auth) SignOut(ctx context.Context, headers http.Header) error {
	if err := a.revokeGuestContinuation(ctx, headers); err != nil {
		return err
	}
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

// RequireOwner requires a direct sign-in for operations that reveal credentials
// or change an account's authentication or permissions.
func (s Session) RequireOwner() error {
	if s.IsApplicationCredential() || s.ImpersonatedBy != nil {
		return &APIError{403, "OWNER_SESSION_REQUIRED", "This operation requires the account owner's session"}
	}
	return nil
}

func (a *Auth) requireOwnerSession(ctx context.Context, headers http.Header) (*SessionResult, error) {
	s, err := a.requireSession(ctx, headers)
	if err != nil {
		return nil, err
	}
	return s, s.Session.RequireOwner()
}

func (a *Auth) ListSessions(ctx context.Context, headers http.Header) ([]Session, error) {
	current, err := a.requireOwnerSession(ctx, headers)
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
		if row.ExpiresAt.After(now) && row.ImpersonatedBy == nil {
			sessions = append(sessions, row.Session)
		}
	}
	if err := a.projectSessionFields(ctx, sessions); err != nil {
		return nil, err
	}
	if len(a.opts.SessionAdditionalFields) != 0 {
		sessions = slices.DeleteFunc(sessions, func(s Session) bool { return s.ID == "" })
	}
	return sessions, nil
}

func (a *Auth) RevokeSession(ctx context.Context, h http.Header, token string) error {
	s, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return err
	}
	return a.opts.Store.DeleteUserSession(ctx, s.User.ID, token)
}

func (a *Auth) RevokeOtherSessions(ctx context.Context, h http.Header) error {
	s, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return err
	}
	return a.opts.Store.DeleteOtherSessions(ctx, s.User.ID, s.Session.Token)
}

func (a *Auth) RevokeSessions(ctx context.Context, h http.Header) error {
	s, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return err
	}
	return a.opts.Store.DeleteOtherSessions(ctx, s.User.ID, "")
}

// BasePath reports the effective mount path after configuration resolution.
func (a *Auth) BasePath() string { return a.opts.BasePath }

// Logger returns this instance’s logger for host handlers and plugins.
func (a *Auth) Logger() *slog.Logger {
	if a.opts.Logger != nil {
		return a.opts.Logger
	}
	return slog.Default()
}

// PublicURL returns the configured public URL of the auth mount.
func (a *Auth) PublicURL() string {
	return a.opts.BaseURL + strings.TrimRight(a.opts.BasePath, "/")
}

// OAuthIssuer returns the authorization-server issuer advertised by OAuth
// discovery. An explicit JWT issuer takes precedence over the public auth URL.
func (a *Auth) OAuthIssuer() string {
	if a.serviceJWT != nil && a.serviceJWT.Issuer != "" {
		return a.serviceJWT.Issuer
	}
	return a.PublicURL()
}
