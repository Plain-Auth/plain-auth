// Command fixture serves a disposable instance to the differential client tests.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	authn "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/adapters/sqlstore"
	"github.com/Plain-Auth/plain-auth/plugins/apikey"
	"github.com/Plain-Auth/plain-auth/plugins/bearer"
	"github.com/Plain-Auth/plain-auth/plugins/emailotp"
	jwtplugin "github.com/Plain-Auth/plain-auth/plugins/jwt"
	"github.com/Plain-Auth/plain-auth/plugins/lastlogin"
	"github.com/Plain-Auth/plain-auth/plugins/magiclink"
	"github.com/Plain-Auth/plain-auth/plugins/multisession"
	"github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/plugins/openapi"
	"github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/plugins/passkey"
	"github.com/Plain-Auth/plain-auth/plugins/pwnedpassword"
	"github.com/Plain-Auth/plain-auth/plugins/siwe"
	"github.com/Plain-Auth/plain-auth/plugins/sso"
	"github.com/Plain-Auth/plain-auth/plugins/twofactor"
	"github.com/Plain-Auth/plain-auth/providers"
	"github.com/Plain-Auth/plain-auth/schema"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "import-totp" {
		if err := importAuthenticator(os.Args[2]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "add-organization-member" {
		if err := grantMember(os.Args[2]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "reconcile-sso-account" {
		if err := reconcileSSOAccount(os.Args[2]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) < 2 {
		log.Fatal("usage: fixture <temporary-database-path> [organization|two-factor ...]")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	if os.Getenv("CONFORMANCE_OAUTH_PROXY") == "1" {
		if err := serveProxyPair(listener, os.Args[1]); err != nil {
			log.Fatal(err)
		}
		return
	}
	baseURL := "http://" + listener.Addr().String()
	samlFixture := os.Getenv("CONFORMANCE_SAML") == "1"
	if samlFixture {
		baseURL = "https://" + listener.Addr().String()
	}
	passkeyFirst := os.Getenv("CONFORMANCE_PASSKEY_FIRST") == "1"
	if passkeyFirst {
		baseURL = strings.Replace(baseURL, "127.0.0.1", "localhost", 1)
	}
	ddl, err := schema.Generate("sqlite", os.Args[2:])
	if err != nil {
		log.Fatal(err)
	}
	var store *sqlstore.Store
	var additionalSessionFields map[string]authn.SessionField
	var additionalUserFields map[string]authn.UserField
	var accountFields map[string]authn.AccountField
	if os.Getenv("CONFORMANCE_ACCOUNT_FIELDS") == "1" {
		accountFields = fixtureAccountFields()
	}
	if os.Getenv("CONFORMANCE_SESSION_FIELDS") == "1" {
		additionalSessionFields = configuredSessionFields()
	}
	if mode := os.Getenv("CONFORMANCE_USER_FIELDS"); mode == "1" || mode == "magic-defaults" || mode == "phone" || mode == "phone-defaults" {
		additionalUserFields = configuredUserFields()
		if mode == "phone" || mode == "phone-defaults" {
			additionalUserFields["code"] = authn.UserField{Type: authn.FieldString, Column: "profile_code"}
			additionalUserFields["disableSession"] = authn.UserField{Type: authn.FieldBoolean, Column: "profile_quiet"}
			additionalUserFields["updatePhoneNumber"] = authn.UserField{Type: authn.FieldBoolean, Column: "profile_replace"}
		}
		if mode == "phone-defaults" || mode == "magic-defaults" || os.Getenv("CONFORMANCE_SOCIAL_FIELD_DEFAULT") == "1" {
			field := additionalUserFields["locale"]
			field.Default = "en"
			additionalUserFields["locale"] = field
		}
	}
	if os.Getenv("CONFORMANCE_COMPUTED_FIELDS") == "1" {
		additionalUserFields = map[string]authn.UserField{
			"approval": {Type: authn.FieldString, Required: true, ServerOnly: true, Default: func() string { return "generated" }},
			"shade":    {Type: authn.FieldString, Default: func() string { return "blue" }},
		}
		additionalSessionFields = map[string]authn.SessionField{
			"channel": {Type: authn.FieldString, Required: true, Default: func() string { return "browser" }},
		}
	}
	if os.Getenv("CONFORMANCE_DATE_FIELDS") == "1" {
		additionalUserFields = map[string]authn.UserField{"reviewedAt": {Type: authn.FieldDate, Column: "profile_reviewed_at"}}
		additionalSessionFields = map[string]authn.SessionField{"remindAt": {Type: authn.FieldDate, Column: "session_remind_at"}}
	}
	if os.Getenv("CONFORMANCE_WALLET_SCHEMA") == "1" {
		store, err = sqlstore.OpenWithOptions(context.Background(), "sqlite", os.Args[1], os.Args[2:], schema.Options{Wallet: walletFixtureOptions().Schema, AdditionalFields: schema.AdditionalFields{Session: additionalSessionFields, User: additionalUserFields, Account: accountFields}})
	} else if len(additionalSessionFields)+len(additionalUserFields)+len(accountFields) > 0 {
		store, err = sqlstore.OpenWithAdditionalFields(context.Background(), "sqlite", os.Args[1], os.Args[2:], schema.AdditionalFields{Session: additionalSessionFields, User: additionalUserFields, Account: accountFields})
	} else {
		store, err = sqlstore.OpenWithSchema(context.Background(), "sqlite", os.Args[1], ddl)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	var plugins []authn.Plugin
	var applicationKeys *apikey.Service
	var directoryEnabled bool
	for _, id := range os.Args[2:] {
		switch id {
		case "siwe":
			p, err := siwe.New(walletFixtureOptions())
			if err != nil {
				log.Fatal(err)
			}
			plugins = append(plugins, p)
		case "sso", "sso-domain-verification":
			opts := sso.Options{SharedCallback: os.Getenv("CONFORMANCE_SSO_SHARED_CALLBACK") == "1"}
			if samlFixture {
				opts.SAML = &sso.SAMLOptions{}
				if file := os.Getenv("CONFORMANCE_SAML_REVIEWED_DIRECTORY"); file != "" {
					opts.SAML.AllowIDPInitiated = fixtureSAMLPortal(file)
					opts.SAML.IDPInitiatedCallbackURL = "/global-landing"
				}
				if dir := os.Getenv("CONFORMANCE_SAML_SLO_DIR"); dir != "" {
					signer, e := fixtureSAMLEncryption(dir, "logout")
					if e != nil {
						log.Fatal(e)
					}
					opts.SAML.EnableSingleLogout = true
					opts.SAML.EnableIDPInitiatedLogout = os.Getenv("CONFORMANCE_SAML_IDP_LOGOUT") == "1"
					opts.SAML.RequestSigner = signer.PrivateKey
					opts.SAML.RequestCertificate = signer.Certificate
				}
				if dir := os.Getenv("CONFORMANCE_SAML_ENCRYPTION_DIR"); dir != "" {
					keys, e := fixtureSAMLEncryption(dir, "sp")
					if e != nil {
						log.Fatal(e)
					}
					opts.SAML.Encryption = keys
				}
			}
			if id == "sso-domain-verification" {
				address := os.Getenv("CONFORMANCE_SSO_DNS")
				host, _, err := net.SplitHostPort(address)
				if err != nil || host != "127.0.0.1" {
					log.Fatal("domain verification fixture requires a loopback DNS server")
				}
				opts.DomainVerification = &sso.DomainVerificationOptions{TokenPrefix: "tenant-proof", Resolver: &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					var dialer net.Dialer
					return dialer.DialContext(ctx, network, address)
				}}}
			}
			p, e := sso.New(opts)
			if e != nil {
				log.Fatal(e)
			}
			plugins = append(plugins, p)
		case "scim", "scim-managed":
			directoryEnabled = true
		case "api-key":
			keySessions := os.Getenv("AUTH_TEST_API_KEY_SESSIONS") == "1"
			opts := apikey.Options{Store: store, EnableMetadata: true, EnableSession: keySessions}
			if prefix := os.Getenv("CONFORMANCE_KEY_VALIDATOR_PREFIX"); prefix != "" {
				opts.EnableSession = true
				opts.ValidateKey = func(_ context.Context, key string) (bool, error) {
					return strings.HasPrefix(key, prefix), nil
				}
			}
			if os.Getenv("CONFORMANCE_KEY_HOOKS") == "1" {
				opts.EnableSession = true
				opts.DefaultPrefix, opts.KeyLength = "app_", 32
				opts.GenerateKey = func(_ context.Context, g apikey.Generation) (string, error) {
					return "host-" + g.Prefix + strings.Repeat("Q", g.Length), nil
				}
				opts.ExtractKey = func(r *http.Request) (string, bool, error) {
					values := r.Header.Values("X-Managed-Key")
					if len(values) == 0 {
						return "", false, nil
					}
					if len(values) != 1 {
						return "", true, nil
					}
					return values[0], true, nil
				}
			}
			keys, err := apikey.New(opts)
			if err != nil {
				log.Fatal(err)
			}
			applicationKeys = keys
			keyPlugin := keys.Plugin()
			if keySessions {
				teamKeys, err := apikey.New(apikey.Options{Store: store, ConfigID: "teams", Organization: &apikey.OrganizationOptions{}, EnableSession: true, Headers: []string{"X-Team-Key"}})
				if err != nil {
					log.Fatal(err)
				}
				keyPlugin, err = apikey.NewPlugin(keys, teamKeys)
				if err != nil {
					log.Fatal(err)
				}
			}
			plugins = append(plugins, keyPlugin)
		case "phone-number":
			sms := func(_ context.Context, m authn.PhoneOTPMessage) error {
				b, err := json.Marshal(m)
				if err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(filepath.Dir(os.Args[1]), "sms.json"), b, 0600)
			}
			signup := &authn.PhoneSignUpOptions{GetTempEmail: func(n string) string { return n + "@phone.test" }}
			if os.Getenv("CONFORMANCE_USER_FIELDS") == "phone" {
				signup.GetTempName = func(n string) string { return "Phone " + n }
			}
			p, err := authn.NewPhoneNumber(authn.PhoneNumberOptions{SendOTP: sms, SendPasswordResetOTP: sms, RequireVerification: true, SignUpOnVerification: signup})
			if err != nil {
				log.Fatal(err)
			}
			plugins = append(plugins, p)
		case "username", "username-only":
			p, err := authn.NewUsername(authn.UsernameOptions{DisableDisplay: id == "username-only"})
			if err != nil {
				log.Fatal(err)
			}
			plugins = append(plugins, p)
		case "last-login-method":
			plugins = append(plugins, lastlogin.New(lastlogin.Options{Database: store}))
		case "stripe-subscriptions", "stripe-organization":
			workerCtx, stopWorker := context.WithCancel(context.Background())
			defer stopWorker()
			p, err := fixtureStripe(workerCtx, store, os.Getenv("CONFORMANCE_STRIPE_URL"), id == "stripe-organization", os.Getenv("CONFORMANCE_STRIPE_AUTO_SEATS") == "1")
			if err != nil {
				log.Fatal(err)
			}
			plugins = append(plugins, p)
		case "anonymous":
			p, err := authn.NewAnonymous(authn.AnonymousOptions{})
			if err != nil {
				log.Fatal(err)
			}
			plugins = append(plugins, p)
		case "device-authorization":
			p, err := authn.NewDeviceAuthorization(authn.DeviceAuthorizationOptions{})
			if err != nil {
				log.Fatal(err)
			}
			plugins = append(plugins, p)
		case "passkey":
			options := passkey.Options{RPID: "example.test", RPName: "Local Test", Origins: []string{"https://accounts.example.test"}, RequireUserVerification: true}
			if passkeyFirst {
				options = fixturePasskeyFirst(baseURL)
			}
			p, err := passkey.New(options)
			if err != nil {
				log.Fatal(err)
			}
			plugins = append(plugins, p)
		case "organization", "organization-teams":
			options := organization.Options{Store: store, MembershipLimit: fixtureMembershipLimit(), RequireVerifiedEmail: os.Getenv("CONFORMANCE_VERIFY_INVITATION_EMAIL") == "1"}
			if os.Getenv("CONFORMANCE_INVITATION_HOOKS") == "1" {
				configureDecisionHooks(&options, os.Args[1]+".invitation-events")
			}
			if os.Getenv("CONFORMANCE_ORG_PROFILE_HOOKS") == "1" {
				configureOrganizationProfileHooks(&options, os.Args[1]+".org-profile-events")
			}
			if id == "organization-teams" {
				options.Teams = &organization.TeamOptions{}
			}
			p, err := organization.New(options)
			if err != nil {
				log.Fatal(err)
			}
			plugins = append(plugins, p)
		case "admin":
			p, err := authn.NewAdmin(fixtureAdminOptions())
			if err != nil {
				log.Fatal(err)
			}
			plugins = append(plugins, p)
		case "oauth-provider":
			options := registrationFixtureOptions()
			if os.Getenv("CONFORMANCE_CLIENT_REGISTRATION") == "post-login" {
				configurePostLoginFixture(&options, store)
			}
			p, err := oauthprovider.New(options)
			if err != nil {
				log.Fatal(err)
			}
			plugins = append(plugins, p)
		case "jwt":
			p, err := jwtplugin.New(jwtplugin.Options{Algorithm: os.Getenv("CONFORMANCE_JWT_ALGORITHM"), DisableHeader: os.Getenv("CONFORMANCE_MUTE_JWT_HEADER") == "1", Issuer: os.Getenv("CONFORMANCE_DISCOVERY_ISSUER"), JWKSPath: os.Getenv("CONFORMANCE_JWKS_PATH")})
			if err != nil {
				log.Fatal(err)
			}
			plugins = append(plugins, p)
		case "two-factor":
			opts := twofactor.Options{}
			if os.Getenv("AUTH_TEST_FACTOR_MAILBOX") == "1" {
				path := filepath.Join(filepath.Dir(os.Args[1]), "factor-otp.json")
				opts.OTP = twofactor.OTPOptions{Store: "hashed", Send: func(_ context.Context, m twofactor.OTPMessage) error {
					b, err := json.Marshal(m)
					if err != nil {
						return err
					}
					return os.WriteFile(path, b, 0600)
				}}
			}
			plugins = append(plugins, twofactor.New(opts))
		default:
			log.Fatal("unknown runtime plugin")
		}
	}
	if mode := os.Getenv("CONFORMANCE_BEARER"); mode != "" {
		plugins = append(plugins, bearer.New(bearer.Options{RequireSignature: mode == "signed"}))
	}
	if os.Getenv("CONFORMANCE_I18N") == "1" {
		p, err := fixtureI18n()
		if err != nil {
			log.Fatal(err)
		}
		plugins = append(plugins, p)
	}
	if os.Getenv("CONFORMANCE_SESSION_VIEW") != "" {
		p, err := fixtureSessionProjection()
		if err != nil {
			log.Fatal(err)
		}
		plugins = append(plugins, p)
	}
	if os.Getenv("AUTH_TEST_EMAIL_OTP_MAILBOX") == "1" {
		mailbox := filepath.Join(filepath.Dir(os.Args[1]), "email-otp.json")
		p, err := emailotp.New(emailotp.Options{StoreOTP: "hashed", AutoSignInAfterVerification: os.Getenv("CONFORMANCE_VERIFY_HOOKS") == "1", ChangeEmail: emailotp.ChangeOptions{Enabled: true, VerifyCurrentEmail: true}, Send: func(_ context.Context, message emailotp.Message) error {
			data, err := json.Marshal(message)
			if err != nil {
				return err
			}
			return os.WriteFile(mailbox, data, 0600)
		}})
		if err != nil {
			log.Fatal(err)
		}
		plugins = append(plugins, p)
	}
	if os.Getenv("CONFORMANCE_MAILBOX") == "1" {
		mailbox := filepath.Join(filepath.Dir(os.Args[1]), "mailbox.json")
		p, err := magiclink.New(fixtureMagicLink(mailbox))
		if err != nil {
			log.Fatal(err)
		}
		plugins = append(plugins, p)
	}
	if os.Getenv("CONFORMANCE_MULTI_SESSION") == "1" {
		limit := 2
		p, err := multisession.New(multisession.Options{MaximumSessions: &limit})
		if err != nil {
			log.Fatal(err)
		}
		plugins = append(plugins, p)
	}
	if mode := os.Getenv("CONFORMANCE_TRANSFER"); mode != "" {
		p, err := transferPlugin(mode)
		if err != nil {
			log.Fatal(err)
		}
		plugins = append(plugins, p)
	}
	if digest := os.Getenv("CONFORMANCE_SYNTHETIC_BREACH"); digest != "" {
		if len(digest) != 40 {
			log.Fatal("invalid synthetic breach fixture")
		}
		plugins = append(plugins, pwnedpassword.New(pwnedpassword.Options{Transport: passwordRangeFixture{digest}}))
	}
	var social map[string]authn.OAuthProvider
	if os.Getenv("CONFORMANCE_PROVIDER") == "1" {
		social = fixtureSocialProvider()
	}
	if keys := os.Getenv("CONFORMANCE_APPLE_JWKS"); keys != "" {
		opts := providers.AppleOptions{ClientID: "org.example.web", ClientSecret: "local-client-assertion", AppBundleIdentifier: "org.example.mobile",
			HTTPClient: &http.Client{Transport: fixtureProviderKeys{"https://appleid.apple.com/auth/keys", keys}}}
		if audiences := os.Getenv("CONFORMANCE_APPLE_AUDIENCES"); audiences != "" {
			opts.NativeAudiences = strings.Split(audiences, ",")
		}
		apple, err := providers.AppleWithOptions(opts)
		if err != nil {
			log.Fatal(err)
		}
		social = map[string]authn.OAuthProvider{"apple": apple}
	}
	oneTapKeys := os.Getenv("CONFORMANCE_ONE_TAP_JWKS")
	if oneTapKeys != "" {
		social = oneTapFixtureProvider(oneTapKeys)
		plugins = append(plugins, authn.NewOneTap(authn.OneTapOptions{}, authn.OAuthProvider{}))
	}
	if len(accountFields) > 0 {
		for id, provider := range social {
			provider.GetAccountFields = fixtureAccountMapping
			social[id] = provider
		}
	}
	if id := os.Getenv("CONFORMANCE_DISABLE_DIRECT_ID_TOKEN"); id != "" {
		p, ok := social[id]
		if !ok {
			log.Fatal("direct ID-token fixture requires a configured provider")
		}
		p.DisableIDTokenSignIn = true
		social[id] = p
	}
	var mount string
	if os.Getenv("CONFORMANCE_OPENAPI") == "1" {
		mount = "/identity"
		p, err := openapi.New(openapi.Options{Path: "/manual", Theme: "moon", Nonce: "openAPI123"})
		if err != nil {
			log.Fatal(err)
		}
		plugins = append(plugins, p)
	}
	var discoveryOrigins []string
	if origin := os.Getenv("CONFORMANCE_SSO_DISCOVERY_ORIGIN"); origin != "" {
		discoveryOrigins = []string{origin}
	}
	popupOrigin := os.Getenv("CONFORMANCE_POPUP_ORIGIN")
	if popupOrigin != "" {
		p, err := popupProvider(popupOrigin)
		if err != nil {
			log.Fatal(err)
		}
		social = map[string]authn.OAuthProvider{"work": p}
		discoveryOrigins = append(discoveryOrigins, popupOrigin)
		popup, err := authn.NewOAuthPopupWithOptions(authn.OAuthPopupOptions{MessageType: os.Getenv("CONFORMANCE_POPUP_MESSAGE_TYPE")})
		if err != nil {
			log.Fatal(err)
		}
		plugins = append(plugins, popup, bearer.New(bearer.Options{RequireSignature: true}))
	}
	var sessionCache *authn.SessionCookieCacheOptions
	if strategy := os.Getenv("CONFORMANCE_CACHE_STRATEGY"); strategy != "" || os.Getenv("CONFORMANCE_COMPACT_CACHE") == "1" {
		sessionCache = &authn.SessionCookieCacheOptions{Version: "release-test", Strategy: authn.SessionCookieCacheStrategy(strategy)}
		if file := os.Getenv("CONFORMANCE_SESSION_VERSION_FILE"); file != "" {
			sessionCache.Version = ""
			sessionCache.VersionFor = func(ctx context.Context, session authn.Session, user authn.User) (string, error) {
				if err := ctx.Err(); err != nil {
					return "", err
				}
				mode, err := os.ReadFile(file)
				if err != nil {
					return "", err
				}
				switch string(mode) {
				case "error":
					return "", fmt.Errorf("fixture version lookup failed")
				case "reject-replacement":
					if user.Name == "Live" {
						return "", fmt.Errorf("fixture replacement failed")
					}
				case "empty":
					return "", nil
				}
				return string(mode) + "|" + session.ID + "|" + user.ID + "|" + user.Name, nil
			}
		}
		if strategy == "jwt" || strategy == "jwe" {
			sessionCache.MaxAge = 90 * time.Second
		}
	}
	opts := authn.Options{
		SessionAdditionalFields: additionalSessionFields,
		UserAdditionalFields:    additionalUserFields,
		AccountAdditionalFields: accountFields,
		SessionCookieCache:      sessionCache,
		SessionUpdateAge:        fixtureSessionUpdateAge(),
		DeferSessionRefresh:     os.Getenv("CONFORMANCE_DEFER_SESSION_REFRESH") == "1",
		TrustedOrigins:          discoveryOrigins,
		BasePath:                mount,
		SocialProviders:         social,
		DisabledPaths:           strings.Fields(os.Getenv("CONFORMANCE_DISABLED_PATHS")),
		Plugins:                 plugins,
		BaseURL:                 baseURL,
		EmailAndPassword:        true,
		Secret:                  "local-conformance-0123456789-abcdefghijk",
		Store:                   store,
	}
	if len(accountFields) > 0 {
		opts.AccountFieldRules = map[string]authn.AccountFieldRule{"grantKind": {
			TransformInput: func(v any) (any, error) { return v.(string) + "-saved", nil },
		}}
	}
	if os.Getenv("CONFORMANCE_MAGIC_MEMORY") == "1" {
		opts.Store = memory.New()
	}
	if mode := os.Getenv("CONFORMANCE_SOCIAL_VERIFY"); mode != "" {
		configureSocialVerification(&opts, mode, os.Args[1]+".social-mail")
	}
	opts.DisableAccountLinking = os.Getenv("CONFORMANCE_LINK_POLICY") == "disabled"
	opts.DisableImplicitAccountLinking = os.Getenv("CONFORMANCE_LINK_POLICY") == "explicit"
	opts.DisableAccountUpdateOnSignIn = os.Getenv("CONFORMANCE_PRESERVE_PROVIDER_CREDENTIALS") == "1"
	switch os.Getenv("CONFORMANCE_EMAIL_POLICY") {
	case "disabled":
		opts.EmailAndPassword = false
	case "invitation":
		opts.DisableSignUp = true
	case "bounded":
		opts.MinPasswordLength, opts.MaxPasswordLength = 10, 14
	}
	if mode := os.Getenv("CONFORMANCE_SIGNUP_OBSERVER"); mode != "" {
		configureSignUpObserver(&opts, mode, os.Args[1]+".signup-events")
	}
	if os.Getenv("CONFORMANCE_VERIFY_HOOKS") == "1" {
		verificationHookFixture(&opts, os.Args[1])
	}
	if os.Getenv("CONFORMANCE_RESET_HOOK") == "1" {
		resetHookFixture(&opts, os.Args[1])
	}
	if os.Getenv("CONFORMANCE_PASSWORD_CODEC") == "1" {
		opts.PasswordHash = fixturePasswordHash
		opts.PasswordVerify = fixturePasswordVerify
	}
	if mode := os.Getenv("CONFORMANCE_LOG_LEVEL"); mode != "" {
		logFile, err := os.OpenFile(os.Args[1]+".log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
		defer logFile.Close()
		opts.Logger = slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{Level: slog.LevelError}))
		if mode == "silent" {
			opts.Logger = slog.New(slog.DiscardHandler)
		}
		enabled := true
		opts.SendVerificationOnSignUp = &enabled
		opts.SendVerificationEmail = func(context.Context, authn.MailLink) error { return fmt.Errorf("private fixture sender error") }
	}
	if path := os.Getenv("CONFORMANCE_EMAIL_VERIFY_LINK"); path != "" {
		enabled := true
		opts.AutoSignInAfterVerification = true
		opts.SendVerificationOnSignUp = &enabled
		opts.SendVerificationEmail = func(_ context.Context, message authn.MailLink) error {
			return os.WriteFile(path, []byte(message.Token), 0600)
		}
	}
	if mode := os.Getenv("CONFORMANCE_ERROR_REPORTER"); mode != "" {
		opts.Plugins = append(opts.Plugins, authn.Plugin{ID: "report-errors", Endpoints: []authn.Endpoint{{
			Method: http.MethodGet, Path: "/report-failure", Handler: func(authn.EndpointContext) (any, error) { return nil, fmt.Errorf("private endpoint failure") },
		}}})
		opts.OnAPIError = func(c authn.ErrorContext, cause error) error {
			if err := os.WriteFile(os.Args[1]+".report", []byte(c.Request.Method), 0600); err != nil {
				return err
			}
			if mode == "fail" {
				return fmt.Errorf("private reporting failure")
			}
			return nil
		}
	}
	discoveryConfig := os.Getenv("CONFORMANCE_RESOURCE_DISCOVERY")
	if discoveryConfig != "" {
		opts.BaseURL = "https://accounts.example.test/gateway/auth"
	}
	auth, err := authWithBrowserFixture(opts, os.Getenv("CONFORMANCE_BROWSER_COOKIE_FILE"))
	if err != nil {
		log.Fatal(err)
	}
	var handler http.Handler = auth
	if key := os.Getenv("CONFORMANCE_DPOP_JKT"); key != "" {
		handler = dpopFixture(baseURL, key, store, handler)
	}
	if os.Getenv("CONFORMANCE_CLIENT_REGISTRATION") == "protected" {
		handler = clientScopeFixture(auth, store, handler)
	}
	if os.Getenv("CONFORMANCE_RESOURCE_REGISTRY") == "1" {
		handler = resourceRegistryFixture(auth, store, handler)
	}
	if config := os.Getenv("CONFORMANCE_RESOURCE_CHALLENGES"); config != "" {
		handler = resourceChallengeFixture(config, handler)
	}
	if discoveryConfig != "" {
		var config struct {
			Metadata oauthprovider.ResourceMetadata
			Options  oauthprovider.DiscoveryOptions
			UseAuth  bool
		}
		if err := json.Unmarshal([]byte(discoveryConfig), &config); err != nil {
			log.Fatal(err)
		}
		if config.UseAuth {
			config.Options.Auth = auth
		}
		discovery, err := oauthprovider.NewResourceDiscovery(config.Metadata, config.Options)
		if err != nil {
			log.Fatal(err)
		}
		mux := http.NewServeMux()
		mux.Handle(discovery.Path(), discovery)
		mux.Handle("/", handler)
		handler = mux
	}
	if popupOrigin != "" {
		handler = popupCORS(auth, popupOrigin)
	}
	if directoryEnabled {
		handler, err = scimFixture(auth, store)
		if err != nil {
			log.Fatal(err)
		}
	}
	if oneTapKeys != "" {
		handler = oneTapFixtureHandler(baseURL, auth)
	}
	if applicationKeys != nil {
		mux := http.NewServeMux()
		mux.Handle("/", handler)
		mux.Handle("GET /reports", applicationKeys.Middleware(apikey.Permissions{"reports": {"read"}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key, _ := apikey.FromContext(r.Context())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"owner": key.ReferenceID, "id": key.ID})
		})))
		handler = mux
	}
	if samlFixture {
		log.Fatal(serveSAMLFixture(listener, handler, baseURL, os.Args[1]))
	}
	fmt.Println(baseURL)
	log.Fatal(http.Serve(listener, handler))
}
