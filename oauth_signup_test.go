package plainauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/sqlite"
	"github.com/Plain-Auth/plain-auth/client"
	"golang.org/x/oauth2"
)

func TestOAuthExplicitRegistration(t *testing.T) {
	for _, direct := range []bool{false, true} {
		mode := "browser"
		if direct {
			mode = "ID token"
		}
		t.Run(mode, func(t *testing.T) {
			store, err := sqlite.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			app := httptest.NewUnstartedServer(nil)
			base := "http://" + app.Listener.Addr().String()
			profile := auth.OAuthProfile{Subject: "person", Email: "person@example.org", Name: "Person"}
			p := auth.OAuthProvider{
				Config:                oauth2.Config{ClientID: "test", Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token"}},
				DisableImplicitSignUp: true,
				ExchangeCode: func(context.Context, oauth2.Config, string, string, url.Values) (*oauth2.Token, error) {
					return &oauth2.Token{AccessToken: "fixture"}, nil
				},
				Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) { return profile, nil },
				VerifyIDToken: func(context.Context, string, string) (auth.OAuthProfile, time.Time, error) {
					return profile, time.Now().Add(time.Hour), nil
				},
			}
			closed := p
			closed.DisableSignUp = true
			browserOnly := p
			browserOnly.DisableIDTokenSignIn = true
			browserOnly.VerifyIDToken = func(context.Context, string, string) (auth.OAuthProfile, time.Time, error) {
				t.Error("disabled provider invoked its direct token verifier")
				return auth.OAuthProfile{}, time.Time{}, errors.New("unexpected direct grant")
			}
			api, err := auth.New(auth.Options{Store: store, BaseURL: base, BasePath: "/identity", Secret: strings.Repeat("s", 32), SocialProviders: map[string]auth.OAuthProvider{"invite": p, "closed": closed, "browser": browserOnly}})
			if err != nil {
				t.Fatal(err)
			}
			app.Config.Handler = api
			app.Start()
			defer app.Close()
			signin := func(provider, token string, optIn bool) string {
				t.Helper()
				jar, err := cookiejar.New(nil)
				if err != nil {
					t.Fatal(err)
				}
				browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
				c, err := client.New(base+"/identity", browser)
				if err != nil {
					t.Fatal(err)
				}
				in := client.SocialSignInRequest{Provider: provider, RequestSignUp: optIn, DisableRedirect: true, CallbackURL: "/signed-in", NewUserCallbackURL: "/welcome", ErrorCallbackURL: "/declined?source=choice"}
				if direct {
					in.IDToken = &client.SocialIDToken{Token: token, Nonce: "nonce"}
				}
				out, err := c.SignInSocial(t.Context(), in)
				if direct {
					var ae *auth.APIError
					if errors.As(err, &ae) && ae.Status == 404 && ae.Code == "ID_TOKEN_NOT_SUPPORTED" {
						return "unsupported"
					}
					if errors.As(err, &ae) && ae.Status == 401 && ae.Code == "OAUTH_LINK_ERROR" {
						return "declined"
					}
					if err != nil || out.User == nil || out.Token == "" || out.User.Email != profile.Email {
						t.Fatal(out, err)
					}
					return "signed-in"
				}
				if err != nil || out.Redirect || out.URL == "" {
					t.Fatal(out, err)
				}
				idp, err := url.Parse(out.URL)
				if err != nil {
					t.Fatal(err)
				}
				cb, err := url.Parse(idp.Query().Get("redirect_uri"))
				if err != nil {
					t.Fatal(err)
				}
				// Consent belongs to the saved authorization request. Callback parameters cannot change it.
				cb.RawQuery = url.Values{"code": {"grant"}, "state": {idp.Query().Get("state")}, "requestSignUp": {"true"}}.Encode()
				response, err := browser.Get(cb.String())
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				next, err := response.Location()
				if err != nil || response.StatusCode != 302 {
					t.Fatal(response.StatusCode, err)
				}
				if next.Path == "/declined" && (next.Query().Get("error") != "signup_disabled" || next.Query().Get("source") != "choice") {
					t.Fatal("unexpected rejection redirect", next)
				}
				return strings.TrimPrefix(next.Path, "/")
			}
			if got := signin("invite", "first", false); got != "declined" {
				t.Fatal("implicit registration", got)
			}
			want := "welcome"
			if direct {
				want = "signed-in"
			}
			if got := signin("invite", "second", true); got != want {
				t.Fatal("explicit registration", got)
			}
			if got := signin("invite", "third", false); got != "signed-in" {
				t.Fatal("existing identity", got)
			}
			profile.Subject, profile.Email = "other", "other@example.org"
			if got := signin("closed", "fourth", true); got != "declined" {
				t.Fatal("disabled registration", got)
			}
			if direct {
				if got := signin("browser", "fifth", true); got != "unsupported" {
					t.Fatal("provider opted out of direct ID tokens", got)
				}
			} else if got := signin("browser", "fifth", true); got != "welcome" {
				t.Fatal("browser-only provider failed to complete code exchange", got)
			}
		})
	}
}

func TestIDTokenExplicitAccountLinking(t *testing.T) {
	for _, tc := range []struct {
		name   string
		closed bool
	}{{"owner can add identities", false}, {"all new links disabled", true}} {
		t.Run(tc.name, func(t *testing.T) {
			testMobileLinkPolicy(t, tc.closed)
		})
	}
}

func testMobileLinkPolicy(t *testing.T, closed bool) {
	ctx := t.Context()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const email = "owner@example.test"
	profile := auth.OAuthProfile{Subject: "identity", Email: email, EmailVerified: true, Name: "Owner"}
	p := auth.OAuthProvider{
		Config:                 oauth2.Config{ClientID: "mobile-test", Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/authorize", TokenURL: "https://issuer.example/token"}},
		AllowVerifiedEmailLink: true,
		Resolve:                func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) { return profile, nil },
		VerifyIDToken: func(_ context.Context, raw, nonce string) (auth.OAuthProfile, time.Time, error) {
			if nonce != "device-nonce" {
				return auth.OAuthProfile{}, time.Time{}, errors.New("unexpected nonce")
			}
			claims := profile
			if strings.HasPrefix(raw, "separate-") {
				claims.Subject, claims.Email = "separate", "separate@example.test"
			}
			return claims, time.Now().Add(time.Hour), nil
		},
	}
	host := httptest.NewUnstartedServer(nil)
	base := "http://" + host.Listener.Addr().String()
	node, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 40), BaseURL: base, EmailAndPassword: true, DisableImplicitAccountLinking: !closed, DisableAccountLinking: closed, SocialProviders: map[string]auth.OAuthProvider{"mobile": p}, RateLimit: new(bool)})
	if err != nil {
		t.Fatal(err)
	}
	host.Config.Handler = node
	host.Start()
	defer host.Close()
	newClient := func() *client.Client {
		t.Helper()
		c, e := client.New(base, &http.Client{})
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	owner, visitor := newClient(), newClient()
	created, err := owner.SignUpEmail(ctx, client.SignUpRequest{Email: email, Name: "Owner", Password: "credential fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyAccountEmail(ctx, created.User.ID, email, time.Now()); err != nil {
		t.Fatal(err)
	}
	input := func(token string) client.SocialSignInRequest {
		return client.SocialSignInRequest{Provider: "mobile", IDToken: &client.SocialIDToken{Token: token, Nonce: "device-nonce"}}
	}
	_, err = visitor.SignInSocial(ctx, input("unlinked"))
	var api *auth.APIError
	if !errors.As(err, &api) || api.Status != 401 || api.Code != "ACCOUNT_NOT_LINKED" {
		t.Fatal("direct sign-in linked an unapproved account", err)
	}
	if got, err := visitor.GetSession(ctx); err != nil || got != nil {
		t.Fatal("denied visitor retained a session", got, err)
	}
	if closed {
		_, err := owner.LinkSocial(ctx, input("explicit"))
		if !errors.As(err, &api) || api.Status != 401 || api.Code != "LINKING_NOT_ALLOWED" {
			t.Fatal("new mobile link under closed policy", err)
		}
		fresh := newClient()
		registered, err := fresh.SignInSocial(ctx, input("separate-signup"))
		if err != nil || registered.User == nil || registered.User.Email != "separate@example.test" {
			t.Fatal("closed linking affected new registration", registered, err)
		}
		refreshed, err := fresh.LinkSocial(ctx, input("separate-refresh"))
		if err != nil || !refreshed.Status || refreshed.Redirect || refreshed.Token != "" || refreshed.URL != "" {
			t.Fatal("could not refresh an already-owned identity", refreshed, err)
		}
		if sessions, err := fresh.ListSessions(ctx); err != nil || len(sessions) != 1 {
			t.Fatal("refresh changed the owner's sessions", sessions, err)
		}
		_, err = owner.LinkSocial(ctx, input("separate-foreign"))
		if !errors.As(err, &api) || api.Status != 409 || api.Code != "SOCIAL_ACCOUNT_ALREADY_LINKED" {
			t.Fatal("foreign identity error", err)
		}
		login, err := visitor.SignInSocial(ctx, input("separate-signin"))
		if err != nil || login.User == nil || login.User.ID != registered.User.ID {
			t.Fatal("existing mobile sign-in failed", login, err)
		}
		return
	}
	if _, err := owner.LinkSocial(ctx, input("explicit")); err != nil {
		t.Fatal("authenticated explicit link failed", err)
	}
	login, err := visitor.SignInSocial(ctx, input("returning"))
	if err != nil || login.User == nil || login.User.ID != created.User.ID {
		t.Fatal("existing mobile identity failed to sign in", err)
	}
}
