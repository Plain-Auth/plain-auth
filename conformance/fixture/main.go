// Command fixture serves a disposable instance to the differential client tests.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	authn "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlstore"
	"github.com/Stonewrit/stonewrit-auth/plugins/apikey"
	"github.com/Stonewrit/stonewrit-auth/plugins/customsession"
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
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "add-organization-member" {
		if err := grantMember(os.Args[2]); err != nil {
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
		case "sso":
			p, e := sso.New(sso.Options{SharedCallback: os.Getenv("CONFORMANCE_SSO_SHARED_CALLBACK") == "1"})
			if e != nil {
				log.Fatal(e)
			}
			plugins = append(plugins, p)
		case "scim", "scim-managed":
			directoryEnabled = true
		case "api-key":
			keySessions := os.Getenv("AUTH_TEST_API_KEY_SESSIONS") == "1"
			keys, err := apikey.New(apikey.Options{Store: store, EnableMetadata: true, EnableSession: keySessions})
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
			p, err := fixtureStripe(store, os.Getenv("CONFORMANCE_STRIPE_URL"), id == "stripe-organization")
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
			p, err := jwtplugin.New(jwtplugin.Options{})
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
	if os.Getenv("CONFORMANCE_I18N") == "1" {
		p, err := fixtureI18n()
		if err != nil {
			log.Fatal(err)
		}
		plugins = append(plugins, p)
	}
	if os.Getenv("CONFORMANCE_SESSION_VIEW") == "1" {
		p, err := customsession.NewWithOptions(func(_ authn.EndpointContext, data authn.SessionResult) (any, error) {
			return map[string]string{"viewer": data.User.Email}, nil
		}, customsession.Options{ProjectDeviceSessions: os.Getenv("CONFORMANCE_DEVICE_VIEW") == "1"})
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
	auth, err := authn.New(authn.Options{
		TrustedOrigins:   discoveryOrigins,
		BasePath:         mount,
		SocialProviders:  social,
		Plugins:          plugins,
		BaseURL:          baseURL,
		EmailAndPassword: true,
		Secret:           "local-conformance-0123456789-abcdefghijk",
		Store:            store,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(baseURL)
	var handler http.Handler = auth
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
	log.Fatal(http.Serve(listener, handler))
}
