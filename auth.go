package plainauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/Plain-Org/plain-auth/internal/configenv"
	"github.com/Plain-Org/plain-auth/internal/httporigin"
	"github.com/Plain-Org/plain-auth/internal/sessionfields"
	"golang.org/x/net/idna"
)

// Auth is safe for concurrent use by application handlers.
type Auth struct {
	trustedProfileFields  map[string]UserField
	oauthProxy            *OAuthProxyOptions
	sessionCacheKeys      []sessionCacheKey
	disabledPaths         map[string]struct{}
	trustedOrigins        []httporigin.Rule
	dynamic               *dynamicBase
	phoneNumber           *PhoneNumberOptions
	translateError        func(ErrorContext, APIError) string
	username              *UsernameOptions
	anonymous             *AnonymousOptions
	admin                 *AdminOptions
	adminStore            AdminStore
	missingClientIP       sync.Once
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
	beforeHooks           []boundHook
	afterHooks            []boundHook
	onResponse            bool
	dbHooks               databaseHookChains
	wellKnown             map[string]WellKnownDocument
	opts                  Options
	identifierStorage     map[string]VerificationIdentifierStorage
	now                   func() time.Time
	limiter               rateLimiter
}

// New constructs an http.Handler for mounting in an existing router.
func New(opts Options) (*Auth, error) {
	if err := prepareSessionCookieCache(&opts); err != nil {
		return nil, err
	}
	if err := prepareErrorPage(&opts); err != nil {
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
	if err := prepareSecondaryStorage(&opts); err != nil {
		return nil, err
	}
	cleanupStore := opts.Store
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
	var dynamic *dynamicBase
	if opts.DynamicBaseURL != nil {
		if dynamic, err = prepareDynamicBaseURL(&opts); err != nil {
			return nil, err
		}
	} else if opts.BaseURL, opts.BasePath, err = configenv.ServerEndpoint(opts.BaseURL, opts.BasePath); err != nil {
		return nil, fmt.Errorf("authn: BaseURL: %w", err)
	}
	if err := prepareCookieScope(&opts, dynamic); err != nil {
		return nil, err
	}
	trustedOrigins, err := httporigin.Compile("TrustedOrigins", opts.TrustedOrigins)
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
	if opts.AppName == "" {
		opts.AppName = "Auth"
	}
	if opts.MinPasswordLength == 0 {
		opts.MinPasswordLength = 8
	}
	if opts.MaxPasswordLength == 0 {
		opts.MaxPasswordLength = 128
	}
	if opts.SessionTTL < time.Second || opts.MinPasswordLength < 1 || opts.MaxPasswordLength < opts.MinPasswordLength {
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
	for i := range opts.Plugins {
		opts.Plugins[i].OrganizationRoleFields = maps.Clone(opts.Plugins[i].OrganizationRoleFields)
	}
	switch opts.OAuthStateStrategy {
	case "":
		opts.OAuthStateStrategy = OAuthStateDatabase
	case OAuthStateDatabase, OAuthStateCookie:
	default:
		return nil, errors.New("auth: OAuthStateStrategy must be OAuthStateDatabase or OAuthStateCookie")
	}
	if opts.StoreAccountCookie {
		_, linked := opts.Store.(LinkedAccountStore)
		_, credentials := opts.Store.(ProviderCredentialStore)
		if !linked || !credentials {
			return nil, errors.New("auth: StoreAccountCookie requires a store implementing LinkedAccountStore and ProviderCredentialStore")
		}
	}
	opts.SocialProviders, err = prepareOAuthProviders(opts.SocialProviders, opts.Store, len(opts.UserAdditionalFields) > 0 && !opts.DisableSignUp, opts.OAuthStateStrategy)
	if err != nil {
		return nil, err
	}
	if len(opts.TrustedProviders) > 0 && opts.TrustedProvidersForRequest != nil {
		return nil, errors.New("auth: set TrustedProviders or TrustedProvidersForRequest, not both")
	}
	opts.TrustedProviders = slices.Clone(opts.TrustedProviders)
	plugins, err := registerPlugins(opts.Plugins)
	if err != nil {
		return nil, err
	}
	if err := validEndpointHooks(opts.Hooks, "user"); err != nil {
		return nil, err
	}
	for _, p := range opts.Plugins {
		if err := validEndpointHooks(p.Hooks, "plugin "+p.ID); err != nil {
			return nil, err
		}
		for _, m := range p.Middleware {
			if err := validMiddleware(m, p.ID); err != nil {
				return nil, err
			}
		}
	}
	disabledPaths, err := prepareDisabledPaths(opts.DisabledPaths)
	if err != nil {
		return nil, err
	}
	identifierStorage, err := prepareVerificationIdentifiers(opts)
	if err != nil {
		return nil, err
	}
	a := &Auth{opts: opts, identifierStorage: identifierStorage, dynamic: dynamic, disabledPaths: disabledPaths, trustedOrigins: trustedOrigins, now: time.Now, passwordSlots: make(chan struct{}, min(runtime.GOMAXPROCS(0), 4)), plugins: plugins}
	a.beforeHooks, a.afterHooks = endpointHooks(opts)
	if err := a.checkCookieOptions(); err != nil {
		return nil, err
	}
	a.onResponse = slices.ContainsFunc(opts.Plugins, func(p Plugin) bool { return p.OnResponse != nil })
	a.dbHooks = composeDatabaseHooks(opts)
	if err := a.checkDatabaseHooks(); err != nil {
		return nil, err
	}
	if err := a.checkUserInfoValidation(); err != nil {
		return nil, err
	}
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
			if _, ok := a.adminStore.(AdminUserReader); p.admin.BannedUserMessageFunc != nil && !ok {
				return nil, errors.New("authn: BannedUserMessageFunc requires an AdminUserReader store")
			}
			a.admin = p.admin
			a.opts.Store = a.adminStore
			opts.Store = a.adminStore
		}
		if p.ConfigureStore != nil {
			store, err := p.ConfigureStore(opts.Store)
			if err != nil {
				return nil, err
			}
			a.opts.Store, opts.Store = store, store
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
					// Preparing and sending the code are one delivery, as in the
					// reference: over HTTP either failure is logged.
					return a.deliver(ctx, "Could not deliver email OTP", func(ctx context.Context) error {
						return a.SendEmailOTP(ctx, message.User.Email, OTPVerifyEmail)
					})
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
			factor := *p.factor
			if factor.Issuer == "" {
				factor.Issuer = a.opts.AppName
			}
			a.factorOptions = &factor
			a.factorStore = s
		}
	}
	if opts.ErrorRedirectURL != "" && !a.trustedURL(context.Background(), opts.ErrorRedirectURL, true) {
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
	if err := a.checkJWTSessionCache(); err != nil {
		return nil, err
	}
	if err := a.checkDynamicWithoutFallback(); err != nil {
		return nil, err
	}
	if err := a.prepareWellKnown(); err != nil {
		return nil, err
	}
	// The store's cleanup setting is fixed last, so a New that fails leaves
	// the store free for a corrected one.
	if err := prepareVerificationCleanup(cleanupStore, opts.DisableVerificationCleanup); err != nil {
		return nil, err
	}
	return a, nil
}

var cookiePrefixPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// emailPattern is the address format the reference accepts: ASCII letters,
// digits and _'+- in dot-separated local parts that do not end in an
// apostrophe, and a domain of dot-separated labels with a final label of at
// least two letters.
var emailPattern = regexp.MustCompile(`^(?:[A-Za-z0-9_'+\-]+\.)*[A-Za-z0-9_'+\-]*[A-Za-z0-9_+-]@(?:[A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$`)

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
	// A browser-session login (rememberMe false) lasts one day. Deviation for
	// safety: it is capped at SessionTTL, so it never outlives a persistent
	// login when a shorter lifetime is configured.
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
	if meta.CallbackURL != "" && !a.trustedURL(ctx, meta.CallbackURL, true) {
		return AuthResult{}, &APIError{403, "INVALID_CALLBACK_URL", "Invalid callbackURL"}
	}
	if err := a.validateCredential(in.Email, in.Password, true); err != nil {
		return AuthResult{}, err
	}
	if in.refused != nil {
		return AuthResult{}, in.refused
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
	}
	duplicate := func() (AuthResult, error) {
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
			return AuthResult{User: user, syntheticUser: a.customSyntheticUser(ctx, user)}, nil
		}
		return AuthResult{}, duplicateSignupError()
	}
	var userFields, sessionFields map[string]any
	if a.dbHooks.user.create.set() || a.dbHooks.account.create.set() || first != nil && a.dbHooks.session.create.set() || a.opts.ValidateUserInfo != nil {
		// An existing email takes the duplicate path before any hook runs.
		if _, err := a.opts.Store.(signUpUserFinder).FindAccountUser(ctx, user.Email); err == nil {
			return duplicate()
		} else if !errors.Is(err, ErrNotFound) {
			return AuthResult{}, err
		}
		check := UserInfoValidation{Action: UserInfoCreateUser, Method: "email-password", Request: request,
			User: UserRecord{User: user, Fields: serverInput(a.opts.UserAdditionalFields, in.AdditionalFields)}}
		if err := a.ValidateUserInfo(ctx, check); err != nil {
			// A protected sign-up answers a refusal like an existing email.
			if first == nil {
				return duplicate()
			}
			return AuthResult{}, err
		}
		if user, userFields, err = a.beforeUserCreate(ctx, user, serverInput(a.opts.UserAdditionalFields, in.AdditionalFields)); err != nil {
			var problem *APIError
			switch {
			case errors.Is(err, ErrSkipWrite):
				return AuthResult{}, &APIError{400, "FAILED_TO_CREATE_USER", "Failed to create user"}
			case errors.As(err, &problem) && problem.Status == 403 && first == nil:
				// A protected sign-up answers a denial like an existing email.
				return duplicate()
			case errors.As(err, &problem):
				return AuthResult{}, err
			case !errors.Is(err, errDatabaseHookEdit):
				a.Logger().ErrorContext(ctx, "Failed to create user", "error", err)
				return AuthResult{}, &APIError{422, "FAILED_TO_CREATE_USER", "Failed to create user"}
			}
			return AuthResult{}, err
		}
		if len(a.dbHooks.user.create.before) > 0 {
			if extras, err = a.prepareUserFields(userFields, true, true); err != nil {
				return AuthResult{}, err
			}
		}
		credential := LinkedAccount{ProviderID: "credential", AccountID: user.ID, UserID: user.ID, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt}
		if err := a.beforeAccount(ctx, a.dbHooks.account.create, credential); errors.Is(err, ErrSkipWrite) {
			// The credential is stored with its user, so declining it cancels the sign-up.
			return AuthResult{}, &APIError{400, "FAILED_TO_CREATE_USER", "Failed to create user"}
		} else if err != nil {
			return AuthResult{}, err
		}
		if first != nil {
			row, fields, err := a.beforeSessionCreate(ctx, *first, nil, &APIError{400, "FAILED_TO_CREATE_SESSION", "Failed to create session"})
			if err != nil {
				return AuthResult{}, err
			}
			first, sessionFields = &row, fields
		}
	}
	if first != nil && beforeCreate != nil {
		if err := beforeCreate(SessionResult{Session: first.Session, User: user}); err != nil {
			return AuthResult{}, err
		}
	}
	if extras.Present() {
		err = a.opts.Store.(UserFieldStore).CreateUserWithFields(ctx, user, hash, first, extras)
	} else {
		err = a.opts.Store.CreateUser(ctx, user, hash, first)
	}
	err = usernameWriteError(err)
	if errors.Is(err, ErrEmailTaken) {
		return duplicate()
	}
	if err != nil {
		return AuthResult{}, err
	}
	err = a.afterUserCreate(ctx, user, userFields)
	if err == nil {
		err = a.afterCredentialAccount(ctx, a.dbHooks.account.create, user.ID)
	}
	if err != nil {
		if first != nil {
			return AuthResult{}, a.discardUnpublishedSession(ctx, first.Token, err)
		}
		return AuthResult{}, err
	}
	// The verification link goes out once the user and its account are
	// stored, before the session's after hooks, as in the reference.
	if a.sendVerificationOnSignup(a.opts.RequireEmailVerification) && a.opts.SendVerificationEmail != nil {
		if link, err := a.emailProofLink(ctx, user, "", "", meta.CallbackURL); err != nil {
			a.Logger().ErrorContext(ctx, "Could not deliver sign-up verification email")
		} else {
			a.sendMailLink(ctx, "Could not deliver sign-up verification email", link, a.opts.SendVerificationEmail)
		}
	}
	if first != nil {
		if err := a.afterSessionCreate(ctx, *first, sessionFields); err != nil {
			return AuthResult{}, err
		}
	}
	if a.emailOTP != nil && a.emailOTP.SendVerificationOnSignUp && !a.emailOTP.OverrideDefaultEmailVerification {
		if message, err := a.prepareEmailOTP(ctx, user.Email, OTPVerifyEmail); err != nil {
			a.Logger().ErrorContext(ctx, "Could not deliver sign-up verification code")
		} else if message != nil {
			a.runInBackgroundOrAwait(ctx, "Could not deliver sign-up verification code", func(ctx context.Context) error {
				return a.emailOTP.Send(ctx, *message)
			})
		}
	}
	if err := a.readPublicUserFields(ctx, &user); err != nil {
		return AuthResult{}, err
	}
	return AuthResult{User: user, Token: token}, nil
}

// customSyntheticUser applies Options.CustomSyntheticUser to the generated
// duplicate sign-up profile. The result keeps the encoded user's keys, their
// order and the value formats of a real sign-up, so the two read the same.
func (a *Auth) customSyntheticUser(ctx context.Context, user User) json.RawMessage {
	if a.opts.CustomSyntheticUser == nil {
		return nil
	}
	fields := map[string]any{}
	for name, f := range a.opts.UserAdditionalFields {
		if value, ok := user.AdditionalField(name); ok && !f.Hidden {
			fields[name] = value
		}
	}
	shaped := a.opts.CustomSyntheticUser(SyntheticUser{ID: user.ID, Name: user.Name, Email: user.Email, EmailVerified: user.EmailVerified,
		Image: user.Image, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, AdditionalFields: fields})
	raw, err := json.Marshal(user)
	if err != nil {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		return nil
	}
	var out bytes.Buffer
	out.WriteByte('{')
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil
		}
		name, _ := token.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil
		}
		if replacement, ok := shaped[name]; ok {
			if encoded, ok := a.syntheticValue(name, value, replacement); ok {
				value = encoded
			} else {
				a.Logger().WarnContext(ctx, "CustomSyntheticUser returned a value that does not fit the field; keeping the generated one", "field", name)
			}
		}
		if out.Len() > 1 {
			out.WriteByte(',')
		}
		key, _ := json.Marshal(name)
		out.Write(key)
		out.WriteByte(':')
		out.Write(value)
	}
	out.WriteByte('}')
	return out.Bytes()
}

// syntheticValue encodes a hook value the way a real sign-up encodes that
// field, or reports false when the value does not fit it.
func (a *Auth) syntheticValue(name string, generated json.RawMessage, value any) (json.RawMessage, bool) {
	if f, ok := a.opts.UserAdditionalFields[name]; ok {
		public, err := f.PublicValue(value)
		if err != nil {
			return nil, false
		}
		value = public
	} else if name == "createdAt" || name == "updatedAt" {
		instant, ok := value.(time.Time)
		if !ok {
			return nil, false
		}
		value = instant.UTC().Truncate(time.Millisecond)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, false
	}
	kind := func(v json.RawMessage) byte {
		switch c := v[0]; {
		case c == 't' || c == 'f':
			return 'b'
		case c == '-' || c >= '0' && c <= '9':
			return '0'
		default:
			return c
		}
	}
	if got, want := kind(encoded), kind(generated); got != want && got != 'n' && want != 'n' {
		return nil, false
	}
	return encoded, true
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
			return AuthResult{}, &BannedUserError{APIError: &APIError{403, "BANNED_USER", a.admin.BannedUserMessage}, UserID: user.ID}
		}
		user.Banned = false
		user.BanReason = nil
		user.BanExpires = nil
	}
	if a.opts.RequireEmailVerification && !user.EmailVerified {
		if a.opts.SendVerificationOnSignIn && a.opts.SendVerificationEmail != nil {
			if err := a.deliverEmailProof(ctx, "Could not deliver sign-in verification email", user, "", "", meta.CallbackURL, a.opts.SendVerificationEmail); err != nil {
				return AuthResult{}, err
			}
		}
		return AuthResult{}, &APIError{403, "EMAIL_NOT_VERIFIED", "Email not verified"}
	}

	session, token := a.newSession(user.ID, meta)
	if a.factorStore != nil {
		return a.factorLogin(ctx, user, hash, session, meta.TrustedDeviceCookie)
	}
	_, err = a.createSessionWithHooks(ctx, session, &APIError{401, "FAILED_TO_CREATE_SESSION", "Failed to create session"}, func(session StoredSession) error {
		if s, ok := a.opts.Store.(AccountStore); ok {
			err := s.CreateCredentialSession(ctx, hash, session)
			if errors.Is(err, ErrNotFound) {
				return denied
			}
			return err
		}
		return a.opts.Store.CreateSession(ctx, session)
	})
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
	result, err := a.sessionForToken(ctx, token)
	if result != nil && a.translateError != nil {
		a.noteErrorUser(ctx, token, result.User)
	}
	return result, err
}

// sessionForToken returns the live session for token, or nil when it is
// unknown or expired.
func (a *Auth) sessionForToken(ctx context.Context, token string) (*SessionResult, error) {
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
		_, err := a.deleteSessionsWithHooks(ctx, func() ([]Session, error) { return a.sessionRows(ctx, tokens...) }, func() error {
			return a.deviceSessions.DeleteDeviceSessions(ctx, tokens)
		})
		return err
	}
	if token == "" {
		return nil
	}
	_, err := a.deleteSessionsWithHooks(ctx, func() ([]Session, error) { return a.sessionRows(ctx, token) }, func() error {
		return a.opts.Store.DeleteSession(ctx, token)
	})
	return err
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
	if !a.freshSession(current.Session) {
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
	_, err = a.deleteSessionsWithHooks(ctx, func() ([]Session, error) {
		rows, err := a.sessionRows(ctx, token)
		if len(rows) == 1 && rows[0].UserID != s.User.ID {
			rows = nil
		}
		return rows, err
	}, func() error { return a.opts.Store.DeleteUserSession(ctx, s.User.ID, token) })
	return err
}

func (a *Auth) RevokeOtherSessions(ctx context.Context, h http.Header) error {
	s, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return err
	}
	_, err = a.deleteSessionsWithHooks(ctx, func() ([]Session, error) { return a.userSessionRows(ctx, s.User.ID, s.Session.Token) }, func() error {
		return a.opts.Store.DeleteOtherSessions(ctx, s.User.ID, s.Session.Token)
	})
	return err
}

func (a *Auth) RevokeSessions(ctx context.Context, h http.Header) error {
	s, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return err
	}
	_, err = a.deleteSessionsWithHooks(ctx, func() ([]Session, error) { return a.userSessionRows(ctx, s.User.ID, "") }, func() error {
		return a.opts.Store.DeleteOtherSessions(ctx, s.User.ID, "")
	})
	return err
}

// freshSession reports whether s was created within FreshAge. A negative
// FreshAge turns the check off.
func (a *Auth) freshSession(s Session) bool {
	return a.opts.FreshAge < 0 || a.now().Sub(s.CreatedAt) < a.opts.FreshAge
}

// AppName returns the application name shown in authenticator apps.
func (a *Auth) AppName() string { return a.opts.AppName }

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
// The issuer is published without a query, fragment or trailing slash, as
// another runtime publishes it. Tokens this server signs name it too, where
// that runtime stamps the configured spelling, because clients compare iss
// with the discovered issuer exactly.
func (a *Auth) OAuthIssuer() string {
	return normalizeIssuer(a.configuredOAuthIssuer())
}

func (a *Auth) configuredOAuthIssuer() string {
	if a.serviceJWT != nil && a.serviceJWT.Issuer != "" {
		return a.serviceJWT.Issuer
	}
	return a.PublicURL()
}

// oauthIssuerAccepted reports whether iss names this server in its
// published or its configured spelling, as another runtime accepts both.
func (a *Auth) oauthIssuerAccepted(iss string) bool {
	return iss == a.OAuthIssuer() || iss == a.configuredOAuthIssuer()
}

// whatwgHosts converts host names to ASCII with the WHATWG URL flags.
var whatwgHosts = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.CheckJoiners(true), idna.Transitional(false),
	idna.StrictDomainName(false), idna.CheckHyphens(false))

// normalizeIssuer serializes an absolute URL as a WHATWG URL is, with an
// ASCII lowercase host, a canonical IP literal, no default or empty port and
// its dot segments resolved, then drops its query, fragment and one trailing
// slash; a value that does not parse is returned unchanged. IPv4 shorthand
// such as 127.1 is kept as configured, where a WHATWG URL expands it.
func normalizeIssuer(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return raw
	}
	u = u.ResolveReference(&url.URL{})
	if u.Host != "" {
		host, port := strings.ToLower(u.Hostname()), u.Port()
		if addr, err := netip.ParseAddr(host); err == nil {
			host = addr.String()
			if addr.Is4In6() {
				// A WHATWG URL writes the mapped IPv4 part in hex.
				b := addr.As16()
				host = fmt.Sprintf("::ffff:%x:%x", uint16(b[12])<<8|uint16(b[13]), uint16(b[14])<<8|uint16(b[15]))
			}
		} else if ascii, err := whatwgHosts.ToASCII(host); err == nil {
			host = ascii
		}
		if n, err := strconv.ParseUint(port, 10, 16); err == nil {
			port = strconv.FormatUint(n, 10)
		}
		if u.Scheme == "https" && port == "443" || u.Scheme == "http" && port == "80" {
			port = ""
		}
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		u.Host = host
		if port != "" {
			u.Host += ":" + port
		}
	}
	u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = "", false, "", ""
	return strings.TrimSuffix(u.String(), "/")
}
