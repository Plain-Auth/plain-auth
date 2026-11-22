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

	authn "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlstore"
	"github.com/Stonewrit/stonewrit-auth/plugins/apikey"
	"github.com/Stonewrit/stonewrit-auth/plugins/bearer"
	"github.com/Stonewrit/stonewrit-auth/plugins/emailotp"
	jwtplugin "github.com/Stonewrit/stonewrit-auth/plugins/jwt"
	"github.com/Stonewrit/stonewrit-auth/plugins/lastlogin"
	"github.com/Stonewrit/stonewrit-auth/plugins/magiclink"
	"github.com/Stonewrit/stonewrit-auth/plugins/multisession"
	"github.com/Stonewrit/stonewrit-auth/plugins/onetimetoken"
	"github.com/Stonewrit/stonewrit-auth/plugins/openapi"
	"github.com/Stonewrit/stonewrit-auth/plugins/organization"
	"github.com/Stonewrit/stonewrit-auth/plugins/passkey"
	"github.com/Stonewrit/stonewrit-auth/plugins/pwnedpassword"
	"github.com/Stonewrit/stonewrit-auth/plugins/sso"
	"github.com/Stonewrit/stonewrit-auth/plugins/twofactor"
	"github.com/Stonewrit/stonewrit-auth/providers"
	"github.com/Stonewrit/stonewrit-auth/schema"
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
	store, err := sqlstore.OpenWithSchema(context.Background(), "sqlite", os.Args[1], ddl)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	var plugins []authn.Plugin
	var applicationKeys *apikey.Service
	var directoryEnabled bool
	for _, id := range os.Args[2:] {
		switch id {
		case "sso", "sso-domain-verification":
			opts := sso.Options{SharedCallback: os.Getenv("CONFORMANCE_SSO_SHARED_CALLBACK") == "1"}
			if samlFixture {
				opts.SAML = &sso.SAMLOptions{}
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
			p, err := authn.NewPhoneNumber(authn.PhoneNumberOptions{SendOTP: sms, SendPasswordResetOTP: sms, RequireVerification: true, SignUpOnVerification: &authn.PhoneSignUpOptions{GetTempEmail: func(n string) string { return n + "@phone.test" }}})
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
			options := organization.Options{Store: store}
			if id == "organization-teams" {
				options.Teams = &organization.TeamOptions{}
			}
			p, err := organization.New(options)
			if err != nil {
				log.Fatal(err)
			}
			plugins = append(plugins, p)
		case "admin":
			p, err := authn.NewAdmin(authn.AdminOptions{})
			if err != nil {
				log.Fatal(err)
			}
			plugins = append(plugins, p)
		case "jwt":
			p, err := jwtplugin.New(jwtplugin.Options{DisableHeader: os.Getenv("CONFORMANCE_MUTE_JWT_HEADER") == "1"})
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
		p, err := emailotp.New(emailotp.Options{StoreOTP: "hashed", ChangeEmail: emailotp.ChangeOptions{Enabled: true, VerifyCurrentEmail: true}, Send: func(_ context.Context, message emailotp.Message) error {
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
		p, err := magiclink.New(magiclink.Options{HashTokens: true, Send: func(_ context.Context, m magiclink.Message) error {
			payload, err := json.Marshal(m)
			if err != nil {
				return err
			}
			return os.WriteFile(mailbox, payload, 0600)
		}})
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
	if os.Getenv("CONFORMANCE_TRANSFER") == "1" {
		p, err := onetimetoken.New(onetimetoken.Options{HashTokens: true})
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
		if strategy == "jwt" || strategy == "jwe" {
			sessionCache.MaxAge = 90 * time.Second
		}
	}
	opts := authn.Options{
		SessionCookieCache:  sessionCache,
		SessionUpdateAge:    fixtureSessionUpdateAge(),
		DeferSessionRefresh: os.Getenv("CONFORMANCE_DEFER_SESSION_REFRESH") == "1",
		TrustedOrigins:      discoveryOrigins,
		BasePath:            mount,
		SocialProviders:     social,
		DisabledPaths:       strings.Fields(os.Getenv("CONFORMANCE_DISABLED_PATHS")),
		Plugins:             plugins,
		BaseURL:             baseURL,
		EmailAndPassword:    true,
		Secret:              "local-conformance-0123456789-abcdefghijk",
		Store:               store,
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
	auth, err := authn.New(opts)
	if err != nil {
		log.Fatal(err)
	}
	var handler http.Handler = auth
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
